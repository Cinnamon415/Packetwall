package io.github.cinnamon415.packetwall.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.lifecycle.SavedStateHandle
import io.github.cinnamon415.packetwall.analysis.ConnFilter
import io.github.cinnamon415.packetwall.engine.Conn
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map

enum class StatusFilter { ALL, BLOCKED, ALLOWED }

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

/** The connection log: filter state (kept across process death) and the filtered list, computed off the main thread. */
class LogsViewModel(conns: StateFlow<List<Conn>>, private val saved: SavedStateHandle) : ScreenViewModel() {
    /** The filter expression. Compose state, so the text field updates synchronously while typing. */
    var filter by mutableStateOf(saved[K_FILTER] ?: "")
        private set
    val status = saved.getStateFlow(K_STATUS, StatusFilter.ALL)
    val tab = saved.getStateFlow(K_TAB, LogTab.CONNECTIONS)
    val compact = saved.getStateFlow(K_COMPACT, false)

    fun updateFilter(v: String) {
        filter = v
        saved[K_FILTER] = v
    }

    fun setStatus(v: StatusFilter) = saved.set(K_STATUS, v)

    fun setTab(v: LogTab) = saved.set(K_TAB, v)

    fun toggleCompact() = saved.set(K_COMPACT, !compact.value)

    /** Filter expression state: [valid] false shows the field as an error, [message] explains a parse error. */
    data class FilterCheck(val valid: Boolean = true, val message: String? = null)

    data class Shown(val list: List<Conn> = emptyList(), val total: Int = 0)

    private val compiled = snapshotFlow { filter }.map { runCatching { ConnFilter.compile(it) } }

    val filterCheck: StateFlow<FilterCheck> = compiled.map { r ->
        FilterCheck(r.isSuccess, (r.exceptionOrNull() as? ConnFilter.ParseError)?.message)
    }.whileShown(FilterCheck())

    val shown: StateFlow<Shown> = combine(conns, compiled, status, tab) { list, pred, st, t ->
        Shown(selectConns(list, pred.getOrNull(), st, t), list.size)
    }.flowOn(Dispatchers.Default).whileShown(Shown(total = conns.value.size))

    private companion object {
        const val K_FILTER = "logs.filter"
        const val K_STATUS = "logs.status"
        const val K_TAB = "logs.tab"
        const val K_COMPACT = "logs.compact"
    }
}
