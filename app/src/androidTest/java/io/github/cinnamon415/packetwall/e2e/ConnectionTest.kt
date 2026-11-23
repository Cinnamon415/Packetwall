package io.github.cinnamon415.packetwall.e2e

import android.content.ComponentName
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.performClick
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.system.ProtectionTile
import io.github.cinnamon415.packetwall.ui.formatBytes
import io.github.cinnamon415.packetwall.ui.formatWhen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Opens the log, narrows it with [filter] and opens the first row; returns the connection the screen shows. */
fun E2eTest.openConn(filter: String): Conn {
    openLogs()
    type(filter)
    ui.waitUntil("a row for $filter", 8000) { textsOf(" / ").any { Regex("^[1-9]\\d* / \\d+$").matches(it) } }
    val rows = Rows.all()
    val first = ui.onAllNodes(hasClickAction() and hasText(shellName))
    first[visible(hasClickAction() and hasText(shellName)).first()].performClick()
    waitText(str(R.string.conn_overview))
    val id = waitForValue("connection subtitle") {
        textsOf("#").firstNotNullOfOrNull { Regex("^#(\\d+) · ").find(it)?.groupValues?.get(1)?.toInt() }
    }
    return rows.firstOrNull { it.id == id } ?: Rows.all().first { it.id == id }
}

/** The tab with the label [res] (tabs are selectable, unlike the same words elsewhere). */
fun E2eTest.tab(res: Int) {
    val m = hasText(str(res)) and isSelectable()
    ui.onAllNodes(m)[visible(m).first()].performClick()
    ui.waitForIdle()
}

/** A value on a scrolling screen: brought into view, then checked. */
fun E2eTest.seeValue(v: String, substring: Boolean = false) {
    val m = has(v, substring)
    runCatching { ui.waitUntil("\"$v\" exists", 8000) { ui.onAllNodes(m).fetchSemanticsNodes().isNotEmpty() } }.onFailure {
        dumpTree("no value $v")
        throw it
    }
    scrollIntoView(m)
    if (!exists(v, substring)) dumpTree("no value $v")
    assertText(v, substring)
}

/** CONN: the connection screen. */
class ConnectionTest : E2eTest() {

    private fun fresh(c: Conn) = Rows.all().first { it.id == c.id }

    @Test
    @Covers("CONN-01", "CONN-02")
    fun overviewOfAnAllowedHttpConnection() {
        launch()
        turnOn()
        assertAllowed(Hosts.A)
        waitFor("the HTTP connection is closed") { Rows.of(host = Hosts.A, port = 80).any { !it.active } }
        drawer(R.string.nav_home)
        turnOff()
        val c = fresh(openConn("host == ${Hosts.A} && port == 80"))
        // title and subtitle
        assertText(c.title)
        assertText("#${c.id} · $shellName · HTTP")
        // every field matches the connection
        seeValue("HTTP · TCP · IPv4")
        seeValue(str(R.string.st_closed))
        seeValue("$shellName (uid $SHELL_UID)")
        seeValue(SHELL_PKG)
        seeValue("${c.srcIp}:${c.srcPort}")
        seeValue("${c.dstIp}:80", substring = true)
        seeValue(Hosts.A)
        seeValue("↑ ${formatBytes(c.sentBytes)} · ↓ ${formatBytes(c.rcvdBytes)}")
        seeValue("${c.sentPkts} ↑ · ${c.rcvdPkts} ↓")
        seeValue(formatWhen(c.firstSeen))
        seeValue(formatWhen(c.lastSeen))
        seeValue(str(R.string.kv_asn))
        // allowed by the default policy: no rule line; no route without an upstream proxy
        assertNoText(str(R.string.kv_rule))
        assertNoText(str(R.string.kv_route))
        assertNoText(str(R.string.kv_tracker))
        assertTrue("received a reply", c.rcvdBytes > 0 && c.sentPkts > 0)
    }

    @Test
    @Covers("CONN-02")
    fun ruleLineTellsWhy() {
        launch()
        val block = addGlobalRule(RuleSpec(Hosts.CF_IP, kind = TargetKind.IP))
        val allow = addAppRule(shellName, RuleSpec(Hosts.A, action = io.github.cinnamon415.packetwall.fw.Action.ALLOW))
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked("one.one.one.one", ip = Hosts.CF_IP, rule = block.id)
        assertAllowed(Hosts.A, rule = allow.id)
        // DNS over TLS (what Android's Private DNS uses) is dropped by the engine itself
        Net.http("dot", ip = "8.8.8.8", port = 853, timeoutS = 3)
        val dot = Rows.await("DoT blocked") { it.app.packageName == SHELL_PKG && it.dstPort == 853 }
        drawer(R.string.nav_home)
        turnOff()
        val main = str(R.string.set_default)
        val blocked = openConn("ip == ${Hosts.CF_IP} && port == 80")
        seeValue("${str(R.string.decision_blocked)} · ${Hosts.CF_IP} · ${str(R.string.who_global)} · $main")
        seeValue(str(R.string.st_blocked))
        assertTrue(blocked.blocked)
        back()
        openConn("host == ${Hosts.A} && port == 80")
        seeValue("${str(R.string.decision_allowed)} · ${Hosts.A} · $shellName · $main")
        back()
        if (dot.blocked) {
            openConn("port == 853")
            seeValue("${str(R.string.decision_blocked)} · ${str(R.string.reason_private_dns)}")
        } else {
            org.junit.Assert.fail("DNS over TLS to ${Hosts.CF_IP}:853 was not blocked: ${Rows.dump()}")
        }
    }

    @Test
    @Covers("CONN-03")
    fun addRuleAndAppRulesButtons() {
        launch()
        turnOn()
        assertAllowed(Hosts.A)
        drawer(R.string.nav_home)
        turnOff()
        val c = openConn("host == ${Hosts.A} && port == 80")
        tap(str(R.string.rule_add))
        // the quick rule sheet for this connection
        waitText(str(R.string.for_app))
        assertText("HTTP · ${c.title}")
        back()
        waitNoText(str(R.string.for_app))
        tap(str(R.string.app_rules))
        // the app's rules screen
        waitText(str(R.string.rule_add))
        assertText(shellName)
        assertNoText(str(R.string.conn_overview))
    }

    @Test
    @Covers("CONN-04")
    fun exportsOnlyThisConnection() {
        launch()
        turnOn()
        assertAllowed(Hosts.A)
        assertAllowed(Hosts.C)
        drawer(R.string.nav_home)
        turnOff()
        val c = openConn("host == ${Hosts.A} && port == 80")
        val name = "e2e-conn-${System.currentTimeMillis()}.pcapng"
        expectToast(str(R.string.exported)) {
            tapDesc(str(R.string.export_pcapng))
            Docs.save(name)
        }
        val pkts = Pcapng.packets(Docs.read("${Docs.DIR}/$name"))
        assertEquals("all packets of the connection", fresh(c).sentPkts + fresh(c).rcvdPkts, pkts.size)
        for (p in pkts) {
            val t = Pcapng.tuple(p)!!
            assertTrue(
                "only ${c.dstIp}:${c.dstPort} ↔ :${c.srcPort}: $t",
                (t.first == c.dstIp && t.second == c.srcPort && t.third == 80) || (t.second == 80 && t.third == c.srcPort)
            )
        }
        Docs.remove("${Docs.DIR}/$name")
    }

    @Test
    @Covers("CONN-05", "PKT-01")
    fun packetsTabAndPacketScreen() {
        launch()
        turnOn()
        assertAllowed(Hosts.A)
        drawer(R.string.nav_home)
        turnOff()
        val c = fresh(openConn("host == ${Hosts.A} && port == 80"))
        tab(R.string.conn_packets)
        val n = c.sentPkts + c.rcvdPkts
        waitText(str(R.string.packets_shown, n, n), substring = true)
        // the conversation as it happened: handshake, request, response
        for (t in listOf("TCP  SYN", "TCP  SYN,ACK", "HTTP  GET /", "HTTP  HTTP/1.1 200 OK")) seeValue(t)
        // the request packet: outgoing, its layers; the last layer is open, the others open on tap
        tap("HTTP  GET /")
        waitText(str(R.string.dir_out), substring = true)
        assertText("IPv4: ${c.srcIp} → ${c.dstIp}", substring = true)
        assertText("TCP: ${c.srcPort} → 80", substring = true)
        assertText("Host", substring = true)
        assertNoText("TTL", substring = true)
        tap("IPv4", substring = true)
        waitText("TTL", substring = true)
        assertText("Destination: ${c.dstIp}", substring = true)
        // the hex dump from the IP header (0x45) on, with "GET " of the payload
        assertText("0000  45 ", substring = true)
        assertText("47 45 54 20", substring = true)
        back()
        waitText(str(R.string.packets_shown, n, n), substring = true)
    }

    @Test
    @Covers("PKT-02")
    fun packetPushedOutOfTheBuffer() {
        launch()
        // the smallest buffer, 4 MB
        app.settings.update { it.copy(bufferMb = 4) }
        turnOn()
        assertAllowed(Hosts.A)
        drawer(R.string.nav_home)
        val c = openConn("host == ${Hosts.A} && port == 80")
        tab(R.string.conn_packets)
        seeValue("HTTP  GET /")
        // 8 MB from the host while the list is on screen: the oldest packets leave the buffer
        Shell.run("printf 'GET /zeros?mb=8 HTTP/1.0\\r\\n\\r\\n' | timeout 30 toybox nc ${Hosts.HOST} ${Hosts.CONTROL_PORT} > /dev/null")
        waitFor("its packets evicted") { app.packets.packetsOf(c, Int.MAX_VALUE).isEmpty() }
        tap("HTTP  GET /")
        waitText(str(R.string.packet_gone))
        back()
        // the list now says there is nothing left of this connection
        waitNoText("HTTP  GET /")
    }

    @Test
    @Covers("CONN-05")
    fun packetsTabWithCaptureOff() {
        launch()
        drawer(R.string.nav_settings)
        tap(str(R.string.capture_packets))
        waitFor("packets off") { !app.settings.current.capturePackets }
        drawer(R.string.nav_home)
        turnOn()
        assertAllowed(Hosts.A)
        val c = openConn("host == ${Hosts.A} && port == 80")
        tab(R.string.conn_packets)
        waitText(str(R.string.capture_off))
        tab(R.string.conn_data)
        waitText(str(R.string.no_payload))
        assertTrue(c.sentPkts > 0)
    }

    @Test
    @Covers("CONN-06", "CONN-07")
    fun dataAndHttpTabs() {
        launch()
        val block = addGlobalRule(RuleSpec(Hosts.CF_IP, kind = TargetKind.IP))
        drawer(R.string.nav_home)
        turnOn()
        assertAllowed(Hosts.A)
        assertBlocked("one.one.one.one", ip = Hosts.CF_IP, rule = block.id)
        drawer(R.string.nav_home)
        turnOff()
        openConn("host == ${Hosts.A} && port == 80")
        tab(R.string.conn_data)
        // Auto: the request as text
        waitText("GET / HTTP/1.0", substring = true)
        tap(str(R.string.mode_hex))
        // "GET " in hex
        waitText("47 45 54 20", substring = true)
        assertNoText("GET / HTTP/1.0", substring = true)
        tap(str(R.string.mode_text))
        waitText("GET / HTTP/1.0", substring = true)
        tab(R.string.tab_http)
        waitText(str(R.string.http_request))
        assertText(str(R.string.http_response))
        assertText(Hosts.A, substring = true)
        assertText("HTTP/1.", substring = true)
        back()
        // a blocked TCP connection carries no payload and no HTTP
        openConn("ip == ${Hosts.CF_IP} && port == 80")
        tab(R.string.conn_data)
        waitText(str(R.string.no_payload))
        tab(R.string.tab_http)
        waitText(str(R.string.no_http))
    }

    @Test
    @Covers("CONN-07")
    fun httpTabOfTls() {
        // not a DNS host name: TLS to those is dropped as private DNS
        val sni = "www.cloudflare.com"
        launch()
        turnOn()
        val got = Tls.hello(Hosts.CF_IP, sni)
        assertTrue("the server answered the Client Hello ($got bytes)", got > 500)
        Rows.await("TLS connection") { it.app.packageName == SHELL_PKG && it.dstPort == 443 && it.dstIp == Hosts.CF_IP }
        drawer(R.string.nav_home)
        turnOff()
        val c = openConn("ip == ${Hosts.CF_IP} && port == 443")
        assertEquals(sni, c.host)
        tab(R.string.tab_http)
        waitText(str(R.string.http_encrypted))
        assertText(str(R.string.tls_client))
        assertText(sni, substring = true)
        seeValue(str(R.string.tls_server))
        seeValue(str(R.string.tls_subject))
    }

    @Test
    @Covers("CONN-08")
    fun connectionGoneAfterANewSession() {
        launch()
        turnOn()
        assertAllowed(Hosts.A)
        drawer(R.string.nav_home)
        turnOff()
        openConn("host == ${Hosts.A} && port == 80")
        // a new session from the quick settings tile while the screen stays open
        val tile = ComponentName(ctx, ProtectionTile::class.java).flattenToString()
        Shell.run("cmd statusbar add-tile $tile")
        try {
            Shell.run("cmd statusbar click-tile $tile; sleep 0.5; cmd statusbar collapse")
            Vpn.awaitUp()
            backToApp()
            waitText(str(R.string.conn_gone))
            // the arrows have nothing to walk to
            assertTrue(!descEnabled(str(R.string.conn_older)) && !descEnabled(str(R.string.conn_newer)))
        } finally {
            Shell.run("cmd statusbar remove-tile $tile")
        }
    }
}
