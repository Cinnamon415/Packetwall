package io.github.cinnamon415.packetwall.fw

import android.util.Log
import io.github.cinnamon415.packetwall.Problem
import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

/**
 * Owns the firewall configuration: persistence, mutations, blocklist downloads and pushing the
 * compiled rules to the native engine.
 *
 * Profiles follow the live configuration: switching sets on/off or reordering them edits the
 * active profile. Other profiles get new sets appended (disabled) and deleted sets removed.
 */
class FirewallStore(
    private val dir: File,
    /** Package (or pseudo-package) to uid; null when not installed. */
    private val uidOf: (String) -> Int?,
    /** Loads a compiled rules file into the engine (the native engine in the app). */
    private val loader: RulesLoader,
    defaultSetName: String,
    defaultProfileName: String,
    /** Expands AS numbers into their prefixes (GeoIp); empty map without the ASN database. */
    private val asnPrefixes: (Set<Long>) -> Map<Long, List<String>> = { emptyMap() },
    /** Where subscription lists come from (HTTP in the app, fakes in tests). */
    private val lists: ListSource = HttpListSource(),
    /** Blocking I/O (downloads); injected so tests run it on their scheduler. */
    private val io: CoroutineDispatcher = Dispatchers.IO,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + io)
) {
    fun interface RulesLoader {
        /** Returns the number of loaded rules, < 0 on error. */
        fun load(path: String): Int
    }
    private val file = File(dir, "firewall.json")
    private val listsDir = File(dir, "lists").apply { mkdirs() }
    private val compiled = File(dir, "rules.compiled")
    private val lock = Any()
    private val downloadMutex = Mutex()
    private var compileJob: Job? = null

    private val _state = MutableStateFlow(load() ?: FwState.initial(defaultSetName, defaultProfileName))
    val state: StateFlow<FwState> = _state

    /** Set ids currently being downloaded. */
    private val _updating = MutableStateFlow<Set<Int>>(emptySet())
    val updating: StateFlow<Set<Int>> = _updating

    /** Number of rules in the native engine after the last compile (-1 = error). */
    private val _loaded = MutableStateFlow(0)
    val loaded: StateFlow<Int> = _loaded

    private fun load(): FwState? = try {
        if (file.exists()) json.decodeFromString<FwState>(file.readText()) else null
    } catch (e: Exception) {
        Log.e(TAG, "Cannot read ${file.name}, keeping a copy", e)
        file.copyTo(File(dir, "firewall.broken.json"), overwrite = true)
        null
    }

    private fun save(st: FwState) {
        val tmp = File(dir, "firewall.json.tmp")
        tmp.writeText(json.encodeToString(FwState.serializer(), st))
        tmp.renameTo(file)
    }

    init {
        // One writer, always the latest state: saves can never land out of order.
        scope.launch { _state.drop(1).conflate().collect { save(it) } }
    }

    /** Applies a change, persists it and schedules a recompile. */
    fun update(fn: (FwState) -> FwState) {
        synchronized(lock) {
            val old = _state.value
            val n = fn(old)
            if (n === old) return
            _state.value = syncProfiles(old, n)
        }
        scheduleCompile()
    }

    private fun syncProfiles(old: FwState, n: FwState): FwState {
        if (old.order == n.order && old.sets == n.sets) return n
        val ids = n.sets.map { it.id }.toSet()
        val profiles = n.profiles.map { p ->
            if (p.id == n.activeProfile && old.activeProfile == n.activeProfile) {
                p.copy(sets = n.order)
            } else {
                val kept = p.sets.filter { it.id in ids }
                val missing = n.order.filter { s -> kept.none { it.id == s.id } }.map { it.copy(enabled = false) }
                p.copy(sets = kept + missing)
            }
        }
        return n.copy(profiles = profiles)
    }

    private fun FwState.allocId(): Pair<Int, FwState> = nextId to copy(nextId = nextId + 1)

    // ---------------------------------------------------------------- rules

    fun addRule(r: Rule): Int {
        var id = 0
        update { st ->
            val (nid, s2) = st.allocId()
            id = nid
            s2.copy(rules = s2.rules + r.copy(id = nid, created = System.currentTimeMillis()))
        }
        return id
    }

    fun saveRule(r: Rule) = if (r.id == 0) {
        addRule(r)
    } else {
        update { st -> st.copy(rules = st.rules.map { if (it.id == r.id) r else it }) }
        r.id
    }

    fun deleteRule(id: Int) = update { st -> st.copy(rules = st.rules.filterNot { it.id == id }) }

    // ---------------------------------------------------------------- sets

    fun addSet(name: String): Int {
        var id = 0
        update { st ->
            val (nid, s2) = st.allocId()
            id = nid
            // new user sets go after the last user set, above the blocklists
            val lastUser = s2.order.indexOfLast { s -> s2.set(s.id)?.kind == SetKind.USER }
            val order = s2.order.toMutableList().apply { add(lastUser + 1, SetState(nid, true)) }
            s2.copy(sets = s2.sets + RuleSet(nid, name.trim()), order = order)
        }
        return id
    }

    fun renameSet(id: Int, name: String) = update { st ->
        st.copy(sets = st.sets.map { if (it.id == id) it.copy(name = name.trim()) else it })
    }

    fun updateSet(s: RuleSet) = update { st -> st.copy(sets = st.sets.map { if (it.id == s.id) s else it }) }

    fun deleteSet(id: Int) {
        if (id == FwState.DEFAULT_SET) return
        update { st ->
            st.copy(
                sets = st.sets.filterNot { it.id == id },
                order = st.order.filterNot { it.id == id },
                rules = st.rules.filterNot { it.setId == id }
            )
        }
        File(listsDir, "$id.txt").delete()
    }

    fun setEnabled(id: Int, enabled: Boolean) = update { st ->
        st.copy(order = st.order.map { if (it.id == id) it.copy(enabled = enabled) else it })
    }

    fun moveSet(from: Int, to: Int) = update { st ->
        if (from !in st.order.indices || to !in st.order.indices || from == to) {
            st
        } else {
            st.copy(order = st.order.toMutableList().apply { add(to, removeAt(from)) })
        }
    }

    // ---------------------------------------------------------------- profiles

    fun addProfile(name: String) = update { st ->
        val (nid, s2) = st.allocId()
        s2.copy(profiles = s2.profiles + Profile(nid, name.trim(), s2.order), activeProfile = nid)
    }

    fun activateProfile(id: Int) = update { st ->
        val p = st.profiles.firstOrNull { it.id == id } ?: return@update st
        val ids = st.sets.map { it.id }.toSet()
        val order = p.sets.filter { it.id in ids } +
            st.order.filter { s -> p.sets.none { it.id == s.id } }.map { it.copy(enabled = false) }
        st.copy(order = order, activeProfile = id)
    }

    fun renameProfile(id: Int, name: String) = update { st ->
        st.copy(profiles = st.profiles.map { if (it.id == id) it.copy(name = name.trim()) else it })
    }

    fun deleteProfile(id: Int) = update { st ->
        if (st.profiles.size <= 1) {
            st
        } else {
            val left = st.profiles.filterNot { it.id == id }
            st.copy(profiles = left, activeProfile = if (st.activeProfile == id) left.first().id else st.activeProfile)
        }
    }

    // ---------------------------------------------------------------- groups

    fun saveGroup(g: AppGroup): Int {
        var id = g.id
        update { st ->
            if (g.id == 0) {
                val (nid, s2) = st.allocId()
                id = nid
                s2.copy(groups = s2.groups + g.copy(id = nid))
            } else {
                st.copy(groups = st.groups.map { if (it.id == g.id) g else it })
            }
        }
        return id
    }

    fun deleteGroup(id: Int) = update { st ->
        st.copy(
            groups = st.groups.filterNot { it.id == id },
            rules = st.rules.filterNot { (it.who as? Who.Group)?.id == id }
        )
    }

    // ---------------------------------------------------------------- blocklists

    fun listFile(setId: Int) = File(listsDir, "$setId.txt")

    fun readList(setId: Int): List<String> = listFile(setId).takeIf { it.exists() }?.readLines() ?: emptyList()

    /** Adds a subscription at the lowest priority and downloads it. */
    fun addBlocklist(name: String, url: String?, action: Action = Action.BLOCK): Int {
        var id = 0
        update { st ->
            val (nid, s2) = st.allocId()
            id = nid
            s2.copy(
                sets = s2.sets + RuleSet(nid, name.trim(), SetKind.BLOCKLIST, url = url?.trim(), action = action),
                order = s2.order + SetState(nid, true)
            )
        }
        if (url != null) scope.launch { download(id) }
        return id
    }

    /** Creates a blocklist set from already parsed entries (file import). */
    fun importList(name: String, res: ListParser.Result, action: Action): Int {
        val id = addBlocklist(name, null, action)
        writeList(id, res.entries)
        update { st ->
            st.copy(
                sets = st.sets.map {
                    if (it.id == id) {
                        it.copy(entries = res.entries.size, skipped = res.skipped, updated = System.currentTimeMillis())
                    } else {
                        it
                    }
                }
            )
        }
        return id
    }

    /**
     * Applies a converted foreign import: app/global rules go to a new user set, list entries to a new
     * blocklist set, $important entries to a blocklist set right above it. All at the lowest priority
     * (spec 3); ids are assigned here. Returns the ids of the created sets.
     */
    fun applyImport(name: String, plan: ForeignImport.Plan, listAction: Action): List<Int> {
        val created = ArrayList<Int>()
        if (plan.important.isNotEmpty()) {
            val id = importList("$name · important", ListParser.Result(plan.important, 0, emptyList(), 0), listAction)
            created.add(id)
        }
        if (plan.entries.isNotEmpty()) {
            val id = importList(name, ListParser.Result(plan.entries, plan.skipped, emptyList(), 0), listAction)
            created.add(id)
        }
        if (plan.rules.isNotEmpty()) {
            update { st ->
                var next = st.nextId
                val setId = next++
                val rules = plan.rules.map { it.copy(id = next++, setId = setId, created = System.currentTimeMillis()) }
                created.add(setId)
                val setName = if (plan.entries.isNotEmpty()) "$name · apps" else name
                st.copy(
                    sets = st.sets + RuleSet(setId, setName),
                    order = st.order + SetState(setId, true),
                    rules = st.rules + rules,
                    nextId = next
                )
            }
        }
        return created
    }

    private fun writeList(id: Int, entries: List<String>) {
        val tmp = File(listsDir, "$id.txt.tmp")
        tmp.bufferedWriter().use { w ->
            entries.forEach {
                w.write(it)
                w.write("\n")
            }
        }
        tmp.renameTo(listFile(id))
    }

    fun updateAll() = scope.launch {
        _state.value.blocklists.filter { it.url != null }.forEach { download(it.id) }
    }

    fun updateList(id: Int) = scope.launch { download(id) }

    /** For the scheduled worker: updates every subscription and waits. Returns the number of failures. */
    suspend fun updateAllNow(): Int {
        var failed = 0
        _state.value.blocklists.filter { it.url != null }.forEach { s ->
            download(s.id)
            if (_state.value.set(s.id)?.error != null) failed++
        }
        return failed
    }

    private suspend fun download(id: Int) {
        val set = _state.value.set(id) ?: return
        val url = set.url ?: return
        _updating.value = _updating.value + id
        try {
            val res = downloadMutex.withLock { withContext(io) { fetchAndParse(url) } }
            writeList(id, res.entries)
            update { st ->
                st.copy(
                    sets = st.sets.map {
                        if (it.id == id) {
                            it.copy(
                                entries = res.entries.size,
                                skipped = res.skipped,
                                updated = System.currentTimeMillis(),
                                error = null
                            )
                        } else {
                            it
                        }
                    }
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "Download failed: $url", e)
            update { st ->
                st.copy(sets = st.sets.map { if (it.id == id) it.copy(error = Problem.of(e).encode()) else it })
            }
        } finally {
            _updating.value = _updating.value - id
        }
    }

    private fun fetchAndParse(url: String): ListParser.Result = lists.open(url).use { r ->
        ListParser.parse(r.lineSequence().take(MAX_LIST_LINES))
    }

    // ---------------------------------------------------------------- import / export

    fun exportJson(onlySet: Int? = null): String {
        val st = _state.value
        val part = if (onlySet == null) {
            st
        } else {
            val s = st.set(onlySet)!!
            st.copy(
                sets = listOf(s),
                order = st.order.filter { it.id == onlySet },
                rules = st.rules.filter { it.setId == onlySet },
                profiles = emptyList(),
                activeProfile = null
            )
        }
        val lists = part.sets.filter { it.kind == SetKind.BLOCKLIST && it.url == null }.associate { it.id to readList(it.id) }
        return encodeExport(part, lists)
    }

    /** Only the given rules (with their sets, no profiles). */
    fun exportRules(ids: Set<Int>): String {
        val st = _state.value
        val rules = st.rules.filter { it.id in ids }
        val setIds = rules.map { it.setId }.toSet()
        val groupIds = rules.mapNotNull { (it.who as? Who.Group)?.id }.toSet()
        val part = st.copy(
            // a blocklist's file entries are not part of a rule export: the set becomes a plain user set
            sets = st.sets.filter { it.id in setIds }.map {
                if (it.kind == SetKind.BLOCKLIST) it.copy(kind = SetKind.USER, url = null) else it
            },
            order = st.order.filter { it.id in setIds },
            rules = rules,
            groups = st.groups.filter { it.id in groupIds },
            profiles = emptyList(),
            activeProfile = null
        )
        return encodeExport(part)
    }

    private fun encodeExport(part: FwState, lists: Map<Int, List<String>> = emptyMap()): String =
        jsonPretty.encodeToString(ExportFile.serializer(), ExportFile(exported = System.currentTimeMillis(), state = part, lists = lists))

    /** A profile with its sets (in its order), their rules and inlined file lists. */
    fun exportProfile(profileId: Int): String {
        val st = _state.value
        val p = st.profiles.first { it.id == profileId }
        val ids = p.sets.map { it.id }.toSet()
        val rules = st.rules.filter { it.setId in ids }
        val groupIds = rules.mapNotNull { (it.who as? Who.Group)?.id }.toSet()
        val part = st.copy(
            sets = st.sets.filter { it.id in ids },
            order = p.sets,
            rules = rules,
            groups = st.groups.filter { it.id in groupIds },
            profiles = listOf(p),
            activeProfile = p.id
        )
        val lists = part.sets.filter { it.kind == SetKind.BLOCKLIST && it.url == null }.associate { it.id to readList(it.id) }
        return encodeExport(part, lists)
    }

    fun deleteRules(ids: Set<Int>) = update { st -> st.copy(rules = st.rules.filterNot { it.id in ids }) }

    fun moveRules(ids: Set<Int>, setId: Int) = update { st ->
        st.copy(rules = st.rules.map { if (it.id in ids) it.copy(setId = setId) else it })
    }

    /** Domains/IPs of a set, one per line (hosts-style lists cannot hold app rules or allows). */
    fun exportPlain(setId: Int, hosts: Boolean): String {
        val st = _state.value
        val set = st.set(setId) ?: return ""
        val items = if (set.kind == SetKind.BLOCKLIST) {
            readList(setId).filterNot { it.startsWith("!") }.map { ListParser.displayOf(it) }
        } else {
            st.rules.filter {
                it.setId == setId &&
                    it.who == Who.Global &&
                    it.action == Action.BLOCK &&
                    it.target.kind in setOf(TargetKind.DOMAIN, TargetKind.IP)
            }.map { it.target.value }
        }
        return items.filterNot { hosts && (it.contains('*') || it.contains('/')) }
            .joinToString("\n", postfix = "\n") { if (hosts) "0.0.0.0 $it" else it }
    }

    data class ImportSummary(val sets: Int, val rules: Int, val groups: Int, val profiles: Int)

    /**
     * Imports an export file. [replace] = replace the whole configuration; otherwise the sets are
     * added as new sets (ids remapped) at the lowest priority, disabled profiles and groups appended.
     */
    fun importJson(text: String, replace: Boolean): ImportSummary {
        val f = json.decodeFromString(ExportFile.serializer(), text)
        require(f.format == ExportFile.FORMAT) { "not a Packetwall rules file" }
        val src = f.state
        var summary = ImportSummary(0, 0, 0, 0)

        if (replace) {
            val st = src.copy(
                nextId = maxOf(
                    src.nextId,
                    (
                        src.sets.map { it.id } + src.rules.map { it.id } +
                            src.groups.map { it.id } + src.profiles.map { it.id }
                        ).maxOrNull()?.plus(1) ?: 100
                )
            )
                .let {
                    if (it.set(FwState.DEFAULT_SET) == null) {
                        it.copy(
                            sets = listOf(RuleSet(FwState.DEFAULT_SET, "Default")) + it.sets,
                            order = listOf(SetState(FwState.DEFAULT_SET, true)) + it.order
                        )
                    } else {
                        it
                    }
                }
            f.lists.forEach { (id, lines) -> writeList(id, lines) }
            synchronized(lock) { _state.value = st }
            scheduleCompile()
            st.blocklists.filter { it.url != null }.forEach { s -> scope.launch { download(s.id) } }
            return ImportSummary(st.sets.size, st.rules.size, st.groups.size, st.profiles.size)
        }

        val pendingLists = HashMap<Int, List<String>>()
        update { cur ->
            var next = cur.nextId
            val setMap = HashMap<Int, Int>()
            val groupMap = HashMap<Int, Int>()
            src.sets.forEach { setMap[it.id] = next++ }
            src.groups.forEach { groupMap[it.id] = next++ }
            val sets = src.sets.map { it.copy(id = setMap.getValue(it.id)) }
            val groups = src.groups.map { it.copy(id = groupMap.getValue(it.id)) }
            val rules = src.rules.filter { it.setId in setMap }.map { r ->
                val who = (r.who as? Who.Group)?.let { g -> groupMap[g.id]?.let { Who.Group(it) } } ?: r.who
                r.copy(id = next++, setId = setMap.getValue(r.setId), who = who)
            }
            val order = src.order.filter { it.id in setMap }.map { SetState(setMap.getValue(it.id), it.enabled) } +
                sets.filter { s -> src.order.none { setMap[it.id] == s.id } }.map { SetState(it.id, true) }
            val profiles = src.profiles.map { p ->
                Profile(next++, p.name, p.sets.filter { it.id in setMap }.map { SetState(setMap.getValue(it.id), it.enabled) })
            }
            f.lists.forEach { (id, lines) -> setMap[id]?.let { pendingLists[it] = lines } }
            summary = ImportSummary(sets.size, rules.size, groups.size, profiles.size)
            cur.copy(
                sets = cur.sets + sets,
                order = cur.order + order,
                rules = cur.rules + rules,
                groups = cur.groups + groups,
                profiles = cur.profiles + profiles,
                nextId = next
            )
        }
        pendingLists.forEach { (id, lines) -> writeList(id, lines) }
        // subscriptions are imported without their entries: fetch them now
        _state.value.blocklists.filter { it.url != null && !listFile(it.id).exists() }.forEach { s -> scope.launch { download(s.id) } }
        scheduleCompile()
        return summary
    }

    // ---------------------------------------------------------------- compile

    fun scheduleCompile(delayMs: Long = 250) {
        synchronized(lock) {
            compileJob?.cancel()
            compileJob = scope.launch {
                delay(delayMs)
                compileNow()
            }
        }
    }

    fun compileNow() {
        try {
            val st = _state.value
            RulesCompiler.compile(st, uidOf, ::listFile, compiled, asnPrefixes)
            _loaded.value = loader.load(compiled.absolutePath)
        } catch (e: Throwable) {
            Log.e(TAG, "compile failed", e)
            _loaded.value = -1
        }
    }

    companion object {
        private const val TAG = "FirewallStore"
        private const val MAX_LIST_LINES = 3_000_000
        val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = false
            classDiscriminator = "type"
        }
        val jsonPretty = Json(json) {
            prettyPrint = true
            encodeDefaults = true
        }
    }
}
