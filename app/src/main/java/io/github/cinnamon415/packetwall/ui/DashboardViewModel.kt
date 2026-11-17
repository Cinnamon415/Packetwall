package io.github.cinnamon415.packetwall.ui

import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.analysis.ConnStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map

/** Aggregates for the home and statistics screens, recomputed off the main thread on every connections update. */
class DashboardViewModel(app: PacketwallApp) : ScreenViewModel() {
    val summary: StateFlow<ConnStats.Summary> = app.connections.conns
        .map { list -> ConnStats.summarize(list, { host -> app.trackers.trackingOf(host)?.name }) }
        .flowOn(Dispatchers.Default)
        .whileShown(ConnStats.Summary())
}
