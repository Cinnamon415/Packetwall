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
    val summary: StateFlow<ConnStats.Summary> = combine(app.connections.conns, CaptureStatus.sessionStart) { list, start ->
        ConnStats.summarize(if (start > 0) list.filter { it.firstSeen >= start } else list)
    }
        .flowOn(Dispatchers.Default)
        .whileShown(ConnStats.Summary())
}
