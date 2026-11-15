package io.github.cinnamon415.packetwall.fw

import android.util.Log
import io.github.cinnamon415.packetwall.engine.AppsResolver
import io.github.cinnamon415.packetwall.engine.CaptureService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Owns the firewall configuration: persistence, mutations, blocklist downloads and pushing the
 * compiled rules to the native engine.
 *
 * Profiles follow the live configuration: switching sets on/off or reordering them edits the
 * active profile. Other profiles get new sets appended (disabled) and deleted sets removed.
 */
class FirewallStore(
    private val dir: File,
    private val apps: AppsResolver,
    defaultSetName: String,
    defaultProfileName: String,
) {
    private val file = File(dir, "firewall.json")
    private val listsDir = File(dir, "lists").apply { mkdirs() }
    private val compiled = File(dir, "rules.compiled")
    private val lock = Any()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
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

    /** Applies a change, persists it and schedules a recompile. */
    fun update(fn: (FwState) -> FwState) {
        val st = synchronized(lock) {
            val old = _state.value
            var n = fn(old)
            if (n === old) return
            n = syncProfiles(old, n)
            _state.value = n
            n
        }
        scope.launch { synchronized(lock) { save(st) } }
        scheduleCompile()
    }

    private fun syncProfiles(old: FwState, n: FwState): FwState {
        if (old.order == n.order && old.sets == n.sets) return n
        val ids = n.sets.map { it.id }.toSet()
        val profiles = n.profiles.map { p ->
            if (p.id == n.activeProfile && old.activeProfile == n.activeProfile) p.copy(sets = n.order)
            else {
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

    fun saveRule(r: Rule) = if (r.id == 0) addRule(r) else {
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
                rules = st.rules.filterNot { it.setId == id },
            )
        }
        File(listsDir, "$id.txt").delete()
    }

    fun setEnabled(id: Int, enabled: Boolean) = update { st ->
        st.copy(order = st.order.map { if (it.id == id) it.copy(enabled = enabled) else it })
    }

    fun moveSet(from: Int, to: Int) = update { st ->
        if (from !in st.order.indices || to !in st.order.indices || from == to) st
        else st.copy(order = st.order.toMutableList().apply { add(to, removeAt(from)) })
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
        if (st.profiles.size <= 1) st
        else {
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
            } else st.copy(groups = st.groups.map { if (it.id == g.id) g else it })
        }
        return id
    }

    fun deleteGroup(id: Int) = update { st ->
        st.copy(groups = st.groups.filterNot { it.id == id },
            rules = st.rules.filterNot { (it.who as? Who.Group)?.id == id })
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
            s2.copy(sets = s2.sets + RuleSet(nid, name.trim(), SetKind.BLOCKLIST, url = url?.trim(), action = action),
                order = s2.order + SetState(nid, true))
        }
        if (url != null) scope.launch { download(id) }
        return id
    }

    /** Creates a blocklist set from already parsed entries (file import). */
    fun importList(name: String, res: ListParser.Result, action: Action): Int {
        val id = addBlocklist(name, null, action)
        writeList(id, res.entries)
        update { st ->
            st.copy(sets = st.sets.map {
                if (it.id == id) it.copy(entries = res.entries.size, skipped = res.skipped, updated = System.currentTimeMillis()) else it
            })
        }
        return id
    }

    private fun writeList(id: Int, entries: List<String>) {
        val tmp = File(listsDir, "$id.txt.tmp")
        tmp.bufferedWriter().use { w -> entries.forEach { w.write(it); w.write("\n") } }
        tmp.renameTo(listFile(id))
    }

    fun updateAll() = scope.launch {
        _state.value.blocklists.filter { it.url != null }.forEach { download(it.id) }
    }

    fun updateList(id: Int) = scope.launch { download(id) }

    private suspend fun download(id: Int) {
        val set = _state.value.set(id) ?: return
        val url = set.url ?: return
        _updating.value = _updating.value + id
        try {
            val res = downloadMutex.withLock { withContext(Dispatchers.IO) { fetchAndParse(url) } }
            writeList(id, res.entries)
            update { st ->
                st.copy(sets = st.sets.map {
                    if (it.id == id) it.copy(entries = res.entries.size, skipped = res.skipped,
                        updated = System.currentTimeMillis(), error = null) else it
                })
            }
        } catch (e: Exception) {
            Log.w(TAG, "Download failed: $url", e)
            update { st ->
                st.copy(sets = st.sets.map { if (it.id == id) it.copy(error = e.message ?: e.javaClass.simpleName) else it })
            }
        } finally {
            _updating.value = _updating.value - id
        }
    }

    private fun fetchAndParse(url: String): ListParser.Result {
        var u = URL(url)
        repeat(5) {
            val c = u.openConnection() as HttpURLConnection
            c.connectTimeout = 15_000
            c.readTimeout = 30_000
            c.instanceFollowRedirects = false
            c.setRequestProperty("User-Agent", "Packetwall")
            val code = c.responseCode
            if (code in 300..399) {
                u = URL(u, c.getHeaderField("Location") ?: throw IllegalStateException("HTTP $code"))
                c.disconnect()
                return@repeat
            }
            if (code != 200) throw IllegalStateException("HTTP $code")
            return c.inputStream.bufferedReader().useLines { ListParser.parse(it.take(MAX_LIST_LINES)) }
        }
        throw IllegalStateException("too many redirects")
    }

    // ---------------------------------------------------------------- import / export

    fun exportJson(onlySet: Int? = null): String {
        val st = _state.value
        val part = if (onlySet == null) st else {
            val s = st.set(onlySet)!!
            st.copy(sets = listOf(s), order = st.order.filter { it.id == onlySet },
                rules = st.rules.filter { it.setId == onlySet }, profiles = emptyList(), activeProfile = null)
        }
        val lists = part.sets.filter { it.kind == SetKind.BLOCKLIST && it.url == null }.associate { it.id to readList(it.id) }
        return jsonPretty.encodeToString(ExportFile.serializer(), ExportFile(exported = System.currentTimeMillis(), state = part, lists = lists))
    }

    /** Domains/IPs of a set, one per line (hosts-style lists cannot hold app rules or allows). */
    fun exportPlain(setId: Int, hosts: Boolean): String {
        val st = _state.value
        val set = st.set(setId) ?: return ""
        val items = if (set.kind == SetKind.BLOCKLIST) readList(setId).filterNot { it.startsWith("!") }.map { ListParser.displayOf(it) }
        else st.rules.filter { it.setId == setId && it.who == Who.Global && it.action == Action.BLOCK &&
                it.target.kind in setOf(TargetKind.DOMAIN, TargetKind.IP) }.map { it.target.value }
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
            val st = src.copy(nextId = maxOf(src.nextId, (src.sets.map { it.id } + src.rules.map { it.id } +
                    src.groups.map { it.id } + src.profiles.map { it.id }).maxOrNull()?.plus(1) ?: 100))
                .let { if (it.set(FwState.DEFAULT_SET) == null) it.copy(sets = listOf(RuleSet(FwState.DEFAULT_SET, "Default")) + it.sets,
                    order = listOf(SetState(FwState.DEFAULT_SET, true)) + it.order) else it }
            f.lists.forEach { (id, lines) -> writeList(id, lines) }
            synchronized(lock) { _state.value = st }
            scope.launch { synchronized(lock) { save(st) } }
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
            cur.copy(sets = cur.sets + sets, order = cur.order + order, rules = cur.rules + rules,
                groups = cur.groups + groups, profiles = cur.profiles + profiles, nextId = next)
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
            RulesCompiler.compile(st, apps::uidOf, ::listFile, compiled)
            _loaded.value = CaptureService.loadRules(compiled.absolutePath)
        } catch (e: Throwable) {
            Log.e(TAG, "compile failed", e)
            _loaded.value = -1
        }
    }

    companion object {
        private const val TAG = "FirewallStore"
        private const val MAX_LIST_LINES = 3_000_000
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = false; classDiscriminator = "type" }
        val jsonPretty = Json(json) { prettyPrint = true; encodeDefaults = true }
    }
}
