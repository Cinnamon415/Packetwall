package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.engine.Conn
import org.junit.Assert.assertEquals
import org.junit.Test

class ConnStatsTest {
    private val a = AppInfo(10100, "com.a", "A", false)
    private val b = AppInfo(10101, "com.b", "B", false)

    private fun conn(
        id: Int,
        app: AppInfo,
        host: String?,
        sent: Long,
        rcvd: Long,
        l7: String = "TLS",
        blocked: Boolean = false,
        rule: Int = 0
    ) = Conn(id, app.uid, app, 4, 6, "10.215.173.1", 40000, "1.2.3.4", 443, l7, host, null, sent, rcvd, 1, 1, 0, 0, 0, 3, blocked, rule)

    // newest first, like the live list
    private val conns = listOf(
        conn(5, b, "ads.example", 10, 0, blocked = true, rule = 7),
        conn(4, a, "dns.example", 5, 5, l7 = "DNS"),
        conn(3, a, "cdn.example", 1000, 9000),
        conn(2, b, "cdn.example", 100, 100),
        conn(1, b, "track.example", 50, 50, blocked = true, rule = 0) // private DNS drop: no rule
    )

    private val trackers = mapOf("track.example" to "Tracker Inc", "ads.example" to "Ads Co")

    @Test fun aggregatesByAppHostProtocolAndBlocks() {
        val s = ConnStats.summarize(conns, { trackers[it.host] })
        assertEquals(listOf("com.a" to 10010L, "com.b" to 310L), s.byApp.map { it.app.packageName to it.total })
        assertEquals(1005L, s.byApp.first().sent)
        // DNS connections are not hosts with traffic of their own
        assertEquals(listOf("cdn.example", "track.example", "ads.example"), s.byHost.map { it.host })
        assertEquals(2, s.byHost.first().conns)
        assertEquals(listOf("TLS" to 4, "DNS" to 1), s.byProto)
        assertEquals(listOf("com.b"), s.trackersByApp.map { it.app.packageName })
        assertEquals(listOf("Ads Co", "Tracker Inc"), s.trackersByApp.single().names)
        // only rule decisions count as blocks
        assertEquals(1, s.blockedCount)
        assertEquals(listOf(5), s.recentBlocked.map { it.id })
        assertEquals(listOf("com.b" to 1), s.blockedByApp.map { it.app.packageName to it.count })
    }

    @Test fun topLimitsEveryList() {
        val many = (1..20).map {
            conn(it, AppInfo(10000 + it, "p$it", "P$it", false), "h$it.example", it.toLong(), 0, blocked = true, rule = 1)
        }
        val s = ConnStats.summarize(many, { null }, top = 3)
        assertEquals(listOf("p20", "p19", "p18"), s.byApp.map { it.app.packageName })
        assertEquals(3, s.byHost.size)
        assertEquals(3, s.recentBlocked.size)
        assertEquals(20, s.blockedCount)
    }

    @Test fun emptyInput() {
        assertEquals(ConnStats.Summary(), ConnStats.summarize(emptyList(), { "x" }))
    }
}
