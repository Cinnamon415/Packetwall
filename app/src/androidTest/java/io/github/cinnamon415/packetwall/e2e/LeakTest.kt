package io.github.cinnamon415.packetwall.e2e

import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.engine.VpnSetup
import io.github.cinnamon415.packetwall.fw.HttpListSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * LEAK: with all traffic through the upstream proxy nothing reaches the internet from the real
 * address — app connections, DNS, UDP, ping, Packetwall's own downloads. The proof is twofold: every
 * row of the log went through the proxy, was blocked, or is a DNS query answered by the DoH proxy;
 * and the test proxies on the host log what they carried ("SOCKS CONNECT host port").
 */
class LeakTest : E2eTest() {

    private val s get() = app.settings.current

    private enum class Kind(val port: Int, val tag: String, val type: Int, val login: Boolean) {
        SOCKS(1081, "SOCKS CONNECT", 0, false),
        SOCKS_LOGIN(1082, "SOCKS AUTH CONNECT", 0, true),
        HTTP(3128, "HTTP CONNECT", 1, true)
    }

    /** All traffic through the host's test proxy of [kind]; the rest as given. */
    private fun upstream(kind: Kind, port: Int = kind.port, onDown: Int = 0, lanBypass: Boolean = false) {
        app.settings.update {
            it.copy(
                upstream = true, upAll = true, upHost = Hosts.HOST, upPort = port, upType = kind.type,
                upUser = if (kind.login) "user" else "", upPass = if (kind.login) "secret" else "",
                upOnDown = onDown, upUdp = 1, lanBypass = lanBypass
            )
        }
        waitFor("settings saved") { s.upstream && s.upPort == port && s.upType == kind.type }
    }

    /** What a row did with its traffic; null = it went out directly. */
    private fun how(c: Conn): String? = when {
        c.proxied -> "proxied"
        c.blocked -> "blocked"
        c.dstIp == VpnSetup.DNS4 && c.dstPort == 53 -> "DNS via the DoH proxy"
        else -> null
    }

    private fun assertNothingDirect(since: Long) {
        Thread.sleep(1500)
        val direct = Rows.all().filter { it.firstSeen >= since && how(it) == null }
        assertTrue(
            "rows that went out directly:\n" +
                direct.joinToString("\n") { "#${it.id} ${it.app.packageName} ${it.protoLabel} ${it.host} ${it.dstIp}:${it.dstPort}" },
            direct.isEmpty()
        )
    }

    private fun proxied(mark: Int, kind: Kind, what: String, pred: (String) -> Boolean) =
        waitFor("${kind.tag}: $what (log: ${ProxyLog.since(mark).takeLast(8)})", 20_000) {
            ProxyLog.since(mark).any { it.startsWith(kind.tag) && pred(it) }
        }

    /** App traffic of every kind, through [kind]: nothing direct, and the proxy carried it. */
    private fun appTraffic(kind: Kind) {
        upstream(kind)
        val mark = ProxyLog.mark()
        turnOn()
        val t = System.currentTimeMillis()
        waitFor("upstream up") { io.github.cinnamon415.packetwall.engine.CaptureStatus.upstreamUp.value == true }
        // TCP by name: the name is looked up through DoH over the proxy, the connection goes through it too
        assertAllowed(Hosts.A)
        proxied(mark, kind, "DoH to 1.1.1.1:443") { it.contains("1.1.1.1") && it.contains("443") }
        proxied(mark, kind, "${Hosts.A}:80") { it.contains(" 80") || it.endsWith(":80") }
        // TCP to an address
        assertTrue(Net.http("cf", ip = Hosts.CF_IP).ok)
        // UDP: blocked (the default), apps fall back to TCP
        Net.dnsUdp("8.8.8.8", Hosts.C)
        Rows.await("UDP blocked") { it.dstIp == "8.8.8.8" && it.blocked }
        // ping: answered after a check through the proxy, no ICMP goes out
        assertEquals("ping answered", 1, Net.ping(Hosts.CF_IP, 1))
        Rows.await("ICMP") { it.ipproto == 1 && it.dstIp == Hosts.CF_IP }
        assertNothingDirect(t)
    }

    @Test
    @Covers("LEAK-01", "LEAK-02", "LEAK-03", "LEAK-04")
    fun socksCarriesEverything() {
        launch()
        appTraffic(Kind.SOCKS)
    }

    @Test
    @Covers("LEAK-01", "LEAK-02")
    fun socksWithLoginCarriesEverything() {
        launch()
        appTraffic(Kind.SOCKS_LOGIN)
    }

    @Test
    @Covers("LEAK-01", "LEAK-02")
    fun httpConnectCarriesEverything() {
        launch()
        appTraffic(Kind.HTTP)
    }

    /** Packetwall's own downloads follow the upstream, and the proxy gets the name (no DNS query of ours). */
    private fun ownDownload(kind: Kind) {
        upstream(kind, lanBypass = true)
        turnOn()
        waitFor("upstream up") { io.github.cinnamon415.packetwall.engine.CaptureStatus.upstreamUp.value == true }
        val mark = ProxyLog.mark()
        app.trackers.download()
        assertTrue("trackers downloaded: ${app.trackers.info.value.error}", app.trackers.info.value.loaded)
        proxied(mark, kind, "the trackers database by name") { it.contains("raw.githubusercontent.com") }
        // a list on the local network goes straight there with the LAN bypass (the proxy could not reach it)
        val m2 = ProxyLog.mark()
        val text = HttpListSource().open(Fixtures.list("block.txt")).use { it.readText() }
        assertTrue(text.isNotBlank())
        assertTrue(
            "LAN list past the proxy: ${ProxyLog.since(m2)}",
            ProxyLog.since(m2).none {
                it.contains(Hosts.HOST) &&
                    it.contains("CONNECT")
            }
        )
    }

    @Test
    @Covers("LEAK-05")
    fun ownDownloadsThroughSocks() {
        launch()
        ownDownload(Kind.SOCKS)
    }

    @Test
    @Covers("LEAK-05")
    fun ownDownloadsThroughSocksWithLogin() {
        launch()
        ownDownload(Kind.SOCKS_LOGIN)
    }

    @Test
    @Covers("LEAK-05")
    fun ownDownloadsThroughHttpConnect() {
        launch()
        ownDownload(Kind.HTTP)
    }

    @Test
    @Covers("LEAK-06")
    fun proxyDownWithTheKillSwitchNothingLeaves() {
        launch()
        // a port nobody listens on, kill switch (the default)
        upstream(Kind.SOCKS, port = 9)
        turnOn()
        val t = System.currentTimeMillis()
        waitFor("upstream down") { io.github.cinnamon415.packetwall.engine.CaptureStatus.upstreamUp.value == false }
        assertFalse(Net.http(Hosts.A).ok)
        assertFalse(Net.http("cf", ip = Hosts.CF_IP).ok)
        Net.dnsUdp("8.8.8.8", Hosts.C)
        assertEquals("no ping answer", 0, Net.ping(Hosts.CF_IP, 1))
        assertNothingDirect(t)
        // Packetwall's own downloads fail instead of going direct
        app.trackers.download()
        val err = app.trackers.info.value.error
        assertFalse(app.trackers.info.value.loaded)
        assertNotNull("download refused", err)
        // after protection stops, they go direct again (as all other traffic does)
        drawer(io.github.cinnamon415.packetwall.R.string.nav_home)
        turnOff()
        val mark = ProxyLog.mark()
        app.trackers.download()
        assertTrue("direct when off: ${app.trackers.info.value.error}", app.trackers.info.value.loaded)
        assertTrue(ProxyLog.since(mark).none { it.contains("raw.githubusercontent.com") })
    }

    @Test
    @Covers("LEAK-07")
    fun pausedStillThroughTheProxy() {
        launch()
        upstream(Kind.SOCKS)
        turnOn()
        waitFor("upstream up") { io.github.cinnamon415.packetwall.engine.CaptureStatus.upstreamUp.value == true }
        tap(str(io.github.cinnamon415.packetwall.R.string.action_pause))
        waitFor("paused") { io.github.cinnamon415.packetwall.engine.CaptureStatus.pausedSince.value != null }
        val mark = ProxyLog.mark()
        // nothing is logged while paused, but the traffic still goes the same way
        assertTrue(Net.http(Hosts.C).ok)
        proxied(mark, Kind.SOCKS, "${Hosts.C} while paused") { it.contains(" 80") }
        assertEquals("ping answered through the probe", 1, Net.ping(Hosts.CF_IP, 1))
        Net.dnsUdp("8.8.8.8", Hosts.A, timeoutS = 2)
        Thread.sleep(1000)
        assertTrue("UDP still not relayed or sent: ${ProxyLog.since(mark)}", ProxyLog.since(mark).none { it.startsWith("UDP ->") })
    }
}
