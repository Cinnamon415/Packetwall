package io.github.cinnamon415.packetwall.ui

import android.content.SharedPreferences
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.github.cinnamon415.packetwall.analysis.ConnFilter
import io.github.cinnamon415.packetwall.engine.Conn
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map

enum class StatusFilter { ALL, BLOCKED, ALLOWED }

/**
 * Opening the log already filtered (from Home tiles, Statistics) and stepping through the list that
 * was on screen (the arrows on a connection).
 */
object LogsLink {
    data class Request(val status: StatusFilter, val filter: String)

    val request = MutableStateFlow<Request?>(null)

    /** Ids of the list a connection was opened from, in its order; null = the whole log. */
    @Volatile var ids: List<Int>? = null

    /**
     * The log's filter text and status chip. They live as long as the app, not the screen: leaving
     * the log and coming back finds them as they were. Only an explicit [request] replaces them.
     */
    val filter = MutableStateFlow("")
    val status = MutableStateFlow(StatusFilter.ALL)

    /** [filter] and [status] were read from the saved preferences (once per process). */
    @Volatile var loaded = false
}

enum class LogTab { CONNECTIONS, DNS, HTTP, CAPTURES }

/** Connections passing the status chip, the filter expression and the tab. Pure. */
fun selectConns(conns: List<Conn>, filter: ((Conn) -> Boolean)?, status: StatusFilter, tab: LogTab): List<Conn> = conns.filter { c ->
    when (status) {
        StatusFilter.ALL -> true
        StatusFilter.BLOCKED -> c.blocked
        StatusFilter.ALLOWED -> !c.blocked
    } &&
        when (tab) {
            LogTab.DNS -> c.l7proto == "DNS"
            LogTab.HTTP -> !c.url.isNullOrEmpty()
            else -> true
        } &&
        (filter == null || filter(c))
}

/**
 * The connection log: what is shown (filter, status chip, tab, compact view) and the filtered list,
 * computed off the main thread. The choices are kept in [prefs]: leaving the log, closing the app or
 * a restart of the process finds them as they were.
 */
class LogsViewModel(conns: StateFlow<List<Conn>>, private val prefs: SharedPreferences) : ScreenViewModel() {
    init {
        if (!LogsLink.loaded) {
            LogsLink.loaded = true
            LogsLink.filter.value = prefs.getString(K_FILTER, null) ?: ""
            LogsLink.status.value = prefs.getString(K_STATUS, null).enumOr(StatusFilter.ALL)
        }
    }

    /** The filter expression. Compose state, so the text field updates synchronously while typing. */
    var filter by mutableStateOf(LogsLink.filter.value)
        private set
    val status: StateFlow<StatusFilter> = LogsLink.status
    private val _tab = MutableStateFlow(prefs.getString(K_TAB, null).enumOr(LogTab.CONNECTIONS))
    val tab: StateFlow<LogTab> = _tab
    private val _compact = MutableStateFlow(prefs.getBoolean(K_COMPACT, false))
    val compact: StateFlow<Boolean> = _compact

    fun updateFilter(v: String) {
        filter = v
        LogsLink.filter.value = v
        prefs.edit().putString(K_FILTER, v).apply()
    }

    fun setStatus(v: StatusFilter) {
        LogsLink.status.value = v
        prefs.edit().putString(K_STATUS, v.name).apply()
    }

    fun setTab(v: LogTab) {
        _tab.value = v
        prefs.edit().putString(K_TAB, v.name).apply()
    }

    fun toggleCompact() {
        _compact.value = !_compact.value
        prefs.edit().putBoolean(K_COMPACT, _compact.value).apply()
    }

    /** Filter expression state: [valid] false shows the field as an error, [error] explains a parse error. */
    data class FilterCheck(val valid: Boolean = true, val error: ConnFilter.ParseError? = null)

    data class Shown(val list: List<Conn> = emptyList(), val total: Int = 0)

    // from the shared StateFlow, not snapshotFlow: every change arrives, also without a frame in between
    private val compiled = LogsLink.filter.map { runCatching { ConnFilter.compile(it) } }

    val filterCheck: StateFlow<FilterCheck> = compiled.map { r ->
        FilterCheck(r.isSuccess, r.exceptionOrNull() as? ConnFilter.ParseError)
    }.whileShown(FilterCheck())

    val shown: StateFlow<Shown> = combine(conns, compiled, status, tab) { list, pred, st, t ->
        Shown(selectConns(list, pred.getOrNull(), st, t), list.size)
    }.flowOn(Dispatchers.Default).whileShown(Shown(total = conns.value.size))

    companion object {
        /** The SharedPreferences file of the log's choices. */
        const val PREFS = "logs"
        private const val K_FILTER = "logs.filter"
        private const val K_STATUS = "logs.status"
        private const val K_TAB = "logs.tab"
        private const val K_COMPACT = "logs.compact"

        private inline fun <reified E : Enum<E>> String?.enumOr(default: E): E =
            this?.let { n -> enumValues<E>().firstOrNull { it.name == n } } ?: default
    }
}
