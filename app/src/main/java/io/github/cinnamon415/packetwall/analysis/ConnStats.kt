package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.engine.Conn

/** Aggregates over the connection list for the home and statistics screens. Pure, runs off the main thread. */
object ConnStats {
    data class AppTraffic(val app: AppInfo, val sent: Long, val rcvd: Long) {
        val total get() = sent + rcvd
    }

    data class HostTraffic(val host: String, val conns: Int, val bytes: Long)

    data class AppCount(val app: AppInfo, val count: Int, val names: List<String> = emptyList())

    data class Summary(
        val byApp: List<AppTraffic> = emptyList(),
        val byHost: List<HostTraffic> = emptyList(),
        val byProto: List<Pair<String, Int>> = emptyList(),
        val trackersByApp: List<AppCount> = emptyList(),
        val blockedByApp: List<AppCount> = emptyList(),
        /** Connections blocked by a firewall rule, newest first (the list order). */
        val recentBlocked: List<Conn> = emptyList(),
        /** All connections blocked by a rule (not the internal Private DNS drops). */
        val blockedCount: Int = 0
    )

    /** [conns] is newest first; [tracker] names the tracking company of a host, if any. */
    fun summarize(conns: List<Conn>, tracker: (String?) -> String?, top: Int = 8): Summary {
        val ruleBlocked = conns.filter { it.blocked && it.fwRule != 0 }
        val tracked = conns.mapNotNull { c -> tracker(c.host)?.let { c to it } }
        return Summary(
            byApp = conns.groupBy { it.uid }
                .map { (_, l) -> AppTraffic(l.first().app, l.sumOf { it.sentBytes }, l.sumOf { it.rcvdBytes }) }
                .sortedByDescending { it.total }.take(top),
            byHost = conns.filter { !it.host.isNullOrEmpty() && it.l7proto != "DNS" }.groupBy { it.host!! }
                .map { (h, l) -> HostTraffic(h, l.size, l.sumOf { it.bytes }) }
                .sortedByDescending { it.bytes }.take(top),
            byProto = conns.groupingBy { it.protoLabel }.eachCount().toList().sortedByDescending { it.second }.take(top),
            trackersByApp = tracked.groupBy { it.first.uid }
                .map { (_, l) -> AppCount(l.first().first.app, l.size, l.map { it.second }.distinct()) }
                .sortedByDescending { it.count }.take(top),
            blockedByApp = ruleBlocked.groupBy { it.uid }
                .map { (_, l) -> AppCount(l.first().app, l.size) }
                .sortedByDescending { it.count }.take(top),
            recentBlocked = ruleBlocked.take(top),
            blockedCount = ruleBlocked.size
        )
    }
}
