package io.github.cinnamon415.packetwall.fw

import android.util.Log
import io.github.cinnamon415.packetwall.BadDataException
import io.github.cinnamon415.packetwall.Limits
import io.github.cinnamon415.packetwall.Problem
import io.github.cinnamon415.packetwall.cappedLines
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
        scope.launch { removeOrphanLists() }
    }

    /**
     * Deletes list files of sets that no longer exist (left by older versions, crashes or
     * removed sets). Temporary files of a download in progress are kept for a minute.
     */
    fun removeOrphanLists(): Int {
        val ids = _state.value.sets.map { it.id }.toHashSet()
        val recent = System.currentTimeMillis() - 60_000
        var n = 0
        listsDir.listFiles()?.forEach { f ->
            if (!f.isFile) return@forEach
            val id = f.name.substringBefore('.').toIntOrNull() ?: return@forEach
            if (id in ids || (f.name.endsWith(".tmp") && f.lastModified() > recent)) return@forEach
            if (f.delete()) n++
        }
        return n
    }

    /** Applies a change, persists it and schedules a recompile. */
    /**
     * [compileDelayMs]: edits wait a moment so a burst of them compiles once; switching a set or a
     * profile compiles at once, the user expects the next connection to follow it.
     */
    fun update(compileDelayMs: Long = 250, fn: (FwState) -> FwState) {
        synchronized(lock) {
            val old = _state.value
            val n = fn(old)
            if (n === old) return
            _state.value = syncProfiles(old, n)
        }
        scheduleCompile(compileDelayMs)
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
        File(listsDir, "$id.edited.txt").delete()
    }

    fun setEnabled(id: Int, enabled: Boolean) = update(0) { st ->
        st.copy(order = st.order.map { if (it.id == id) it.copy(enabled = enabled) else it })
    }

    fun moveSet(from: Int, to: Int) = update(0) { st ->
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

    fun activateProfile(id: Int) = update(0) { st -> withProfile(st, id) }

    /** Undo of a deletion: back to [prev] (ids keep growing, so nothing new is reused). */
    fun restore(prev: FwState) = update { st -> prev.copy(nextId = maxOf(prev.nextId, st.nextId)) }

    /** [st] with profile [id] active: its set order and switches, sets it does not know appended disabled. */
    private fun withProfile(st: FwState, id: Int): FwState {
        val p = st.profiles.firstOrNull { it.id == id } ?: return st
        val ids = st.sets.map { it.id }.toSet()
        val order = p.sets.filter { it.id in ids } +
            st.order.filter { s -> p.sets.none { it.id == s.id } }.map { it.copy(enabled = false) }
        return st.copy(order = order, activeProfile = id)
    }

    fun renameProfile(id: Int, name: String) = update { st ->
        st.copy(profiles = st.profiles.map { if (it.id == id) it.copy(name = name.trim()) else it })
    }

    fun deleteProfile(id: Int) = update { st ->
        if (st.profiles.size <= 1) {
            st
        } else {
            val left = st.copy(profiles = st.profiles.filterNot { it.id == id })
            // the live order belongs to the deleted profile: switch to the next one's own order,
            // or the next edit would overwrite that profile with the deleted one's switches
            if (st.activeProfile == id) withProfile(left, left.profiles.first().id) else left
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

    // ---------------------------------------------------------------- list edits

    private fun editList(id: Int, change: (RuleSet) -> RuleSet) = update { st ->
        st.copy(sets = st.sets.map { if (it.id == id) change(it) else it })
    }

    /** Switches one entry of a list off (or back on); kept when the list is updated. */
    fun setEntryDisabled(id: Int, entry: String, disabled: Boolean) = editList(id) {
        it.copy(disabled = if (disabled) (it.disabled + entry).distinct() else it.disabled - entry)
    }

    /** Adds entries (already normalized, see [ListParser]) to a list. */
    fun addEntries(id: Int, entries: List<String>) = editList(id) { it.copy(added = (it.added + entries).distinct()) }

    fun removeAdded(id: Int, entry: String) = editList(id) { it.copy(added = it.added - entry) }

    fun resetEdits(id: Int) = editList(id) { it.copy(disabled = emptyList(), added = emptyList()) }

    private val effectiveKeys = java.util.concurrent.ConcurrentHashMap<Int, String>()

    /**
     * The file the engine loads for a list: the downloaded one, or with edits a copy without the
     * switched-off entries plus the added ones. The copy is rebuilt only when the list or the edits change.
     */
    private fun effectiveList(st: FwState, id: Int): File {
        val set = st.set(id)
        val src = listFile(id)
        if (set == null || !set.edited) return src
        val out = File(listsDir, "$id.edited.txt")
        val key = "${src.length()}:${src.lastModified()}:${set.disabled.hashCode()}:${set.added.hashCode()}"
        if (out.exists() && effectiveKeys[id] == key) return out
        val off = set.disabled.toHashSet()
        val tmp = File(listsDir, "$id.edited.tmp")
        tmp.bufferedWriter().use { w ->
            if (src.exists()) {
                src.bufferedReader().useLines { lines ->
                    lines.filter { it !in off }.forEach {
                        w.write(it)
                        w.write("\n")
                    }
                }
            }
            set.added.forEach {
                w.write(it)
                w.write("\n")
            }
        }
        tmp.renameTo(out)
        effectiveKeys[id] = key
        return out
    }

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
        listFile(id).delete() // never pick up a file left behind by an earlier set with this id
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
    /** Downloads every subscription, then compiles once (not once per list). */
    suspend fun updateAllNow(): Int {
        var failed = 0
        holdCompile.incrementAndGet()
        try {
            _state.value.blocklists.filter { it.url != null }.forEach { s ->
                download(s.id)
                if (_state.value.set(s.id)?.error != null) failed++
            }
        } finally {
            if (holdCompile.decrementAndGet() == 0 && compileWanted.getAndSet(false)) scheduleCompile(0)
        }
        return failed
    }

    private val holdCompile = java.util.concurrent.atomic.AtomicInteger()
    private val compileWanted = java.util.concurrent.atomic.AtomicBoolean()

    private suspend fun download(id: Int) {
        val set = _state.value.set(id) ?: return
        val url = set.url ?: return
        _updating.value = _updating.value + id
        try {
            val known = Validators(set.etag, set.lastModified).takeIf {
                listFile(id).exists() &&
                    (it.etag != null || it.lastModified != null)
            }
            val fetched = downloadMutex.withLock { withContext(io) { fetchAndParse(url, known) } }
            if (fetched == null) {
                // 304: the list did not change, nothing to rewrite or recompile
                update { st ->
                    st.copy(
                        sets = st.sets.map {
                            if (it.id ==
                                id
                            ) {
                                it.copy(updated = System.currentTimeMillis(), error = null)
                            } else {
                                it
                            }
                        }
                    )
                }
                return
            }
            val (res, validators) = fetched
            // a page or file without a single usable line (an HTML error page, a binary) is not a list:
            // keep the previous copy and say so instead of silently blocking nothing
            if (res.entries.isEmpty()) throw BadDataException("no list entries (${res.skipped} lines skipped)")
            val hash = res.entries.hashCode()
            if (hash != set.contentHash || !listFile(id).exists()) withContext(io) { writeList(id, res.entries) }
            update { st ->
                st.copy(
                    sets = st.sets.map {
                        if (it.id == id) {
                            it.copy(
                                entries = res.entries.size,
                                skipped = res.skipped,
                                updated = System.currentTimeMillis(),
                                error = null,
                                etag = validators?.etag,
                                lastModified = validators?.lastModified,
                                contentHash = hash
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

    /** null when the server answered 304 Not Modified. */
    private fun fetchAndParse(url: String, known: Validators?): Pair<ListParser.Result, Validators?>? {
        val f = lists.openIfChanged(url, known) ?: return null
        return f.reader.use { r ->
            ListParser.parse(r.cappedLines(Limits.LIST_CHARS, Limits.LINE_CHARS, "list").take(MAX_LIST_LINES))
        } to f.validators
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
                // only the groups its rules use
                groups = st.groups.filter { g -> st.rules.any { it.setId == onlySet && (it.who as? Who.Group)?.id == g.id } },
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
            require(src.profiles.isNotEmpty()) { "only a full export can replace the configuration" }
            backupForReplace()
            val st = src.copy(
                // never lower: ids of the replaced configuration must not come back
                nextId = maxOf(
                    src.nextId,
                    _state.value.nextId,
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
            // a group rule whose group is not in the file is dropped: its id could name another local group
            val rules = src.rules.filter {
                it.setId in setMap && ((it.who as? Who.Group)?.id?.let { g -> g in groupMap } ?: true)
            }.map { r ->
                val who = (r.who as? Who.Group)?.let { g -> Who.Group(groupMap.getValue(g.id)) } ?: r.who
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

    // ---------------------------------------------------------------- replace backup

    private val backupDir = File(dir, "before-replace")

    /** The configuration before the last "replace" import, kept until the next one. */
    val hasReplaceBackup: Boolean get() = File(backupDir, "firewall.json").exists()

    /** Keeps the current state and list files (moved, not copied: lists can be large). */
    private fun backupForReplace() {
        backupDir.deleteRecursively()
        backupDir.mkdirs()
        File(backupDir, "firewall.json").writeText(json.encodeToString(FwState.serializer(), _state.value))
        if (listsDir.exists() && !listsDir.renameTo(File(backupDir, "lists"))) {
            listsDir.copyRecursively(File(backupDir, "lists"), overwrite = true)
            listsDir.deleteRecursively()
        }
        listsDir.mkdirs()
    }

    /** Undoes the last "replace" import. Returns false when there is nothing to restore. */
    fun restoreReplaceBackup(): Boolean {
        val f = File(backupDir, "firewall.json")
        if (!f.exists()) return false
        val st = json.decodeFromString(FwState.serializer(), f.readText())
        listsDir.deleteRecursively()
        val saved = File(backupDir, "lists")
        if (!saved.renameTo(listsDir)) {
            saved.copyRecursively(listsDir, overwrite = true)
        }
        listsDir.mkdirs()
        synchronized(lock) { _state.value = st }
        backupDir.deleteRecursively()
        scheduleCompile()
        return true
    }

    // ---------------------------------------------------------------- compile

    fun scheduleCompile(delayMs: Long = 250) {
        if (holdCompile.get() > 0) {
            compileWanted.set(true) // a batch update compiles once at its end
            return
        }
        synchronized(lock) {
            compileJob?.cancel()
            compileJob = scope.launch {
                delay(delayMs)
                compileNow()
            }
        }
    }

    /**
     * Compiles the rules and loads them into the engine. Compiles run one at a time (they share the
     * output file); when neither the compiled rules nor the list files changed, the engine keeps
     * what it has instead of reloading every list. Call off the main thread.
     */
    fun compileNow(force: Boolean = false) = synchronized(compileLock) {
        try {
            val st = _state.value
            RulesCompiler.compile(st, uidOf, { id -> effectiveList(st, id) }, compiled, asnPrefixes)
            val fp = fingerprint()
            if (!force && fp == lastFingerprint && _loaded.value >= 0) return@synchronized
            _loaded.value = loader.load(compiled.absolutePath)
            lastFingerprint = fp
        } catch (e: Throwable) {
            Log.e(TAG, "compile failed", e)
            _loaded.value = -1
            lastFingerprint = null
        }
    }

    private val compileLock = Any()
    private var lastFingerprint: String? = null

    /** The compiled file's content plus size and time of every list it names. */
    private fun fingerprint(): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val text = compiled.readBytes()
        md.update(text)
        text.toString(Charsets.UTF_8).lineSequence().filter { it.startsWith("L\t") }.forEach { line ->
            val f = File(line.substringAfterLast('\t'))
            md.update("${f.length()}:${f.lastModified()}".toByteArray())
        }
        return md.digest().joinToString("") { "%02x".format(it) }
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
