package io.github.cinnamon415.packetwall.ui

import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.analysis.ConnStats
import io.github.cinnamon415.packetwall.engine.CaptureStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn

/** Aggregates for the home and statistics screens, recomputed off the main thread on every connections update. */
class DashboardViewModel(app: PacketwallApp) : ScreenViewModel() {
    // the tiles' native counters are per session; the log may also hold earlier days: count the session only
    // the log keeps the newest 20 000 connections: the counts come from the session totals, which never stop
    val summary: StateFlow<ConnStats.Summary> =
        combine(app.connections.conns, CaptureStatus.sessionStart, app.connections.totals) { list, start, totals ->
            val s = ConnStats.summarize(if (start > 0) list.filter { it.firstSeen >= start } else list)
            s.copy(total = maxOf(s.total, totals.total), blockedCount = maxOf(s.blockedCount, totals.blocked))
        }
            .flowOn(Dispatchers.Default)
            .whileShown(ConnStats.Summary())
}
