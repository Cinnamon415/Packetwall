package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.ui.Help
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The proxy log of tools/e2e/host.py, read from the test process (outside the VPN, like the app itself). */
object ProxyLog {
    private fun fetch(since: Int): Pair<Int, List<String>> {
        val c = java.net.URL("${Fixtures.BASE}/log?since=$since").openConnection() as java.net.HttpURLConnection
        c.connectTimeout = 3000
        c.readTimeout = 3000
        return try {
            val total = c.getHeaderField("X-Total")?.toIntOrNull() ?: 0
            total to c.inputStream.bufferedReader().readText().lines().filter { it.isNotBlank() }
        } finally {
            c.disconnect()
        }
    }

    fun mark(): Int = fetch(0).first

    fun since(mark: Int): List<String> = fetch(mark).second
}

/** SET: settings that change what the engine does, proven on traffic. */
class SettingsTest : E2eTest() {

    private val s get() = app.settings.current

    private fun settings() {
        drawer(R.string.nav_settings)
        // the screen keeps its scroll position: the hint may be further up
        ui.waitUntil("settings", 8000) { ui.onAllNodes(has(str(R.string.settings_apply_hint))).fetchSemanticsNodes().isNotEmpty() }
    }

    /** The Recording tab of the log (the log screen keeps the tab it was left on). */
    private fun captures() {
        drawer(R.string.nav_logs)
        tab(R.string.tab_captures)
        waitText(str(R.string.export))
    }

    /** A chip of a settings row (rows scroll sideways and the screen scrolls down). */
    private fun chip(label: String) {
        val m = hasText(label) and isSelectable()
        ui.waitUntil("chip $label", 5000) { ui.onAllNodes(m).fetchSemanticsNodes().isNotEmpty() }
        scrollIntoView(m)
        val on = visible(m)
        if (on.isEmpty()) dumpTree("chip $label off screen")
        ui.onAllNodes(m)[on.first()].performClick()
        ui.waitForIdle()
    }

    /** A button or row further down the screen: scrolled into view first. */
    private fun press(text: String) {
        seeValue(text)
        tap(text)
    }

    private fun field(label: String, value: String) {
        val m = hasSetTextAction() and hasText(label, substring = true)
        ui.waitUntil("field $label", 5000) { ui.onAllNodes(m).fetchSemanticsNodes().isNotEmpty() }
        scrollIntoView(m)
        val n = ui.onAllNodes(m)[0]
        n.performTextClearanceCompat()
        if (value.isNotEmpty()) n.performTextInputCompat(value)
        ui.waitForIdle()
    }

    private fun restart() {
        drawer(R.string.nav_home)
        if (Vpn.running()) turnOff()
        turnOn()
    }

    /** Upstream on, at the host's test proxy. */
    private fun upstream(http: Boolean = false, port: Int = if (http) 3128 else 1081) {
        settings()
        seeValue(str(R.string.upstream_socks))
        if (!s.upstream) press(str(R.string.upstream_socks))
        waitFor("upstream on") { s.upstream }
        chip(if (http) "HTTP CONNECT" else "SOCKS5")
        field(str(R.string.host), Hosts.HOST)
        field(str(R.string.port), "$port")
        waitFor("proxy saved") { s.upHost == Hosts.HOST && s.upPort == port }
        if (http) {
            field(str(R.string.username), "user")
            field(str(R.string.password), "secret")
        }
    }

    @Test
    @Covers("SET-07")
    fun lanBypass() {
        launch()
        assertFalse(s.lanBypass)
        restart()
        // through the VPN: in the log
        assertTrue(Net.http("lan", ip = Hosts.HOST, port = Hosts.CONTROL_PORT, path = "/hello").ok)
        Rows.await("LAN through the VPN") { it.dstIp == Hosts.HOST && it.dstPort == Hosts.CONTROL_PORT }
        // bypass: past the VPN, not in the log
        settings()
        seeValue(str(R.string.lan_bypass))
        press(str(R.string.lan_bypass))
        waitFor("on") { s.lanBypass }
        restart()
        val t = System.currentTimeMillis()
        assertTrue(Net.http("lan", ip = Hosts.HOST, port = Hosts.CONTROL_PORT, path = "/hello").ok)
        Rows.assertNone("LAN past the VPN", 2000) { it.dstIp == Hosts.HOST && it.firstSeen >= t }
        // the internet still goes through
        assertAllowed(Hosts.A)
    }

    @Test
    @Covers("SET-08")
    fun socksProxyCarriesTheTraffic() {
        launch()
        upstream()
        // an invalid port is shown and not saved
        field(str(R.string.port), "0")
        val pf = ui.onAllNodes(hasSetTextAction() and hasText(str(R.string.port), substring = true))[0]
        assertTrue(pf.fetchSemanticsNode().config.getOrNull(SemanticsProperties.Error) != null)
        assertEquals(1081, s.upPort)
        field(str(R.string.port), "1081")
        // Check: TCP time, the address seen outside, UDP over the relay
        press(str(R.string.check))
        ui.waitUntil("check result", 20_000) { textsOf("TCP ").any { it.startsWith("TCP ") && it.contains("UDP") } }
        val res = textsOf("TCP ").first { it.startsWith("TCP ") }
        assertFalse("check failed: $res", res.contains("✕"))
        val mark = ProxyLog.mark()
        restart()
        settings()
        seeValue(str(R.string.upstream_up), substring = true)
        val c = assertAllowed(Hosts.A)
        // the proxy saw it; the log says so
        waitFor("proxy saw ${Hosts.A}") {
            ProxyLog.since(mark).any {
                it.startsWith("SOCKS CONNECT") &&
                    it.contains(":80") ||
                    it.endsWith(" 80")
            }
        }
        waitFor("row is proxied") { Rows.all().first { it.id == c.id }.proxied }
        drawer(R.string.nav_home)
        openConn("host == ${Hosts.A} && port == 80")
        seeValue(str(R.string.route_upstream))
    }

    @Test
    @Covers("SET-08")
    fun httpConnectWithLogin() {
        launch()
        upstream(http = true)
        val mark = ProxyLog.mark()
        restart()
        assertAllowed(Hosts.A)
        waitFor("CONNECT through the HTTP proxy") { ProxyLog.since(mark).any { it.startsWith("HTTP CONNECT") } }
        // a wrong password: the proxy refuses, nothing gets through it
        drawer(R.string.nav_home)
        turnOff()
        settings()
        field(str(R.string.password), "wrong")
        waitFor("saved") { s.upPass == "wrong" }
        val m2 = ProxyLog.mark()
        restart()
        assertFalse(Net.http(Hosts.A_WWW).ok)
        waitFor("407 from the proxy") { ProxyLog.since(m2).any { it.startsWith("HTTP 407") } }
    }

    @Test
    @Covers("SET-09")
    fun udpThroughTheProxy() {
        launch()
        upstream()
        // Block (the default)
        assertEquals(1, s.upUdp)
        restart()
        // the query gets the engine's spoofed reply; the row is blocked by no rule
        Net.dnsUdp("8.8.8.8", Hosts.A)
        val row = Rows.await("UDP blocked") { it.dstIp == "8.8.8.8" && it.blocked }
        assertEquals(0, row.fwRule)
        assertEquals(R.string.reason_upstream_udp, io.github.cinnamon415.packetwall.ui.internalBlockReason(row, app))
        // through the proxy: UDP ASSOCIATE
        drawer(R.string.nav_home)
        turnOff()
        settings()
        chip(str(R.string.upstream_udp_proxy))
        waitFor("proxy udp") { s.upUdp == 2 }
        val mark = ProxyLog.mark()
        restart()
        assertTrue("UDP through the relay", Net.dnsUdp("8.8.8.8", Hosts.A).isNotEmpty())
        waitFor("relay used") { ProxyLog.since(mark).any { it.startsWith("UDP -> 8.8.8.8 53") } }
        // directly: answered, not through the relay
        drawer(R.string.nav_home)
        turnOff()
        settings()
        chip(str(R.string.upstream_udp_direct))
        waitFor("direct udp") { s.upUdp == 0 }
        val m2 = ProxyLog.mark()
        restart()
        assertTrue(Net.dnsUdp("8.8.8.8", Hosts.C).isNotEmpty())
        Thread.sleep(1000)
        assertTrue(ProxyLog.since(m2).none { it.startsWith("UDP -> 8.8.8.8") })
        // HTTP CONNECT carries no UDP: "through the proxy" turns into Block
        drawer(R.string.nav_home)
        turnOff()
        settings()
        chip(str(R.string.upstream_udp_proxy))
        waitFor("proxy udp") { s.upUdp == 2 }
        chip("HTTP CONNECT")
        waitFor("block now") { s.upType == 1 && s.upUdp == 1 }
        assertNoText(str(R.string.upstream_udp_proxy))
    }

    @Test
    @Covers("SET-10")
    fun proxyDownKillSwitchOrDirect() {
        launch()
        // a port nobody listens on
        upstream(port = 9)
        assertEquals(0, s.upOnDown)
        restart()
        settings()
        seeValue(str(R.string.upstream_down), substring = true)
        val r = Net.http(Hosts.A)
        assertFalse("kill switch: nothing passes (${r.line})", r.ok)
        val row = Rows.await("blocked by the kill switch") { it.host == Hosts.A && it.blocked }
        assertEquals(0, row.fwRule)
        assertEquals(R.string.reason_kill_switch, io.github.cinnamon415.packetwall.ui.internalBlockReason(row, app))
        // straight to an address too
        Net.http("kill", ip = Hosts.CF_IP)
        Rows.await("TCP blocked by the kill switch") { it.dstIp == Hosts.CF_IP && it.blocked }
        drawer(R.string.nav_home)
        openConn("host == ${Hosts.A}")
        seeValue(str(R.string.reason_kill_switch), substring = true)
        // go directly instead
        drawer(R.string.nav_home)
        turnOff()
        settings()
        chip(str(R.string.go_direct))
        waitFor("direct") { s.upOnDown == 1 }
        restart()
        assertAllowed(Hosts.C)
        assertFalse(Rows.of(host = Hosts.C, port = 80).last().proxied)
    }

    @Test
    @Covers("SET-12")
    fun dnsOverHttps() {
        launch()
        settings()
        seeValue(str(R.string.dns_doh))
        press(str(R.string.dns_doh))
        waitFor("doh") { s.dnsMode == 1 }
        val preset = s.dohUrl
        // only https:// is taken
        field(str(R.string.doh_custom), "http://dns.example/dns-query")
        val f = ui.onAllNodes(hasSetTextAction() and hasText(str(R.string.doh_custom), substring = true))[0]
        assertTrue(f.fetchSemanticsNode().config.getOrNull(SemanticsProperties.Error) != null)
        assertEquals(preset, s.dohUrl)
        field(str(R.string.doh_custom), "")
        restart()
        // the shell's names are resolved through DoH
        val host = java.net.URI(s.dohUrl).host
        waitText("DoH $host", substring = true)
        assertAllowed(Hosts.A)
        assertAllowed(Hosts.C)
        settings()
        val prefix = str(R.string.doh_stats, 0, 0, 0).substringBefore("0")
        seeValue(prefix, substring = true)
        val re = Regex("^" + Regex.escape(prefix) + "(\\d+)")
        fun queries() = textsOf(prefix).firstNotNullOfOrNull { re.find(it)?.groupValues?.get(1)?.toInt() } ?: -1
        waitFor("DoH answered queries: ${textsOf(prefix)}") { queries() >= 2 }
    }

    @Test
    @Covers("SET-02", "SET-03", "SET-04", "SET-05", "CAP-01", "CAP-03")
    fun bufferSnaplenAndApplyOnRestart() {
        launch()
        settings()
        chip("8 MB")
        chip("128 B")
        waitFor("saved") { s.bufferMb == 8 && s.snaplen == 128 }
        restart()
        repeat(3) { assertAllowed(Hosts.A) }
        // the buffer line
        captures()
        val info = app.packets.info.value
        assertTrue(info.packets > 0)
        waitText("of 8 MB", substring = true)
        // export: every packet cut at 128 bytes
        fun export(): List<ByteArray> {
            val name = "e2e-buf-${System.nanoTime()}.pcapng"
            expectToast(str(R.string.exported)) {
                tap(str(R.string.export))
                Docs.save(name)
            }
            // the provider may show the new file empty for a moment
            val bytes = waitForValue("exported $name") { Docs.read("${Docs.DIR}/$name").takeIf { it.isNotEmpty() } }
            return Pcapng.packets(bytes).also { Docs.remove("${Docs.DIR}/$name") }
        }
        val cut = export()
        assertTrue(cut.isNotEmpty())
        assertTrue("caplen ≤ 128: ${cut.maxOf { it.size }}", cut.all { it.size <= 128 })
        // a change applies on the next start only
        settings()
        chip(str(R.string.snaplen_full))
        waitFor("full") { s.snaplen == 0 }
        assertAllowed(Hosts.C)
        captures()
        assertTrue("still cut before a restart", export().all { it.size <= 128 })
        restart()
        assertAllowed(Hosts.A_WWW)
        captures()
        assertTrue("whole packets after the restart", export().any { it.size > 128 })
        // packets off: the buffer says so and its buttons are off
        settings()
        press(str(R.string.capture_packets))
        waitFor("off") { !s.capturePackets }
        assertText(str(R.string.record_needs_packets))
        captures()
        waitText(str(R.string.capture_off))
    }

    @Test
    @Covers("SET-16")
    fun backupToAFolder() {
        launch()
        addGlobalRule(RuleSpec(Hosts.B))
        Shell.run("rm -rf ${Docs.DIR}/e2e-backup; mkdir -p ${Docs.DIR}/e2e-backup")
        settings()
        seeValue(str(R.string.backup_off))
        press(str(R.string.backup_choose))
        Docs.useFolder("e2e-backup")
        val folder = str(R.string.backup_folder, "Download/e2e-backup", "—").substringBefore(" · ")
        waitFor("folder chosen: ${s.backupUri}") { s.backupUri.isNotEmpty() }
        seeValue(folder, substring = true)
        // the daily job makes its first copy right away
        val dir = "${Docs.DIR}/e2e-backup"
        fun backups() = Docs.list(dir).filter { it.startsWith("packetwall-backup-") }.sorted()
        waitFor("first automatic backup: ${backups()}") { backups().size == 1 && s.lastBackup > 0 }
        // older copies beyond the last 7 are removed
        (1..8).forEach { Shell.run("echo '{}' > $dir/packetwall-backup-20200101-00000$it.json") }
        Thread.sleep(1100)
        expectToast(str(R.string.backup_done)) { press(str(R.string.backup_now)) }
        val kept = backups()
        assertEquals("the last 7 kept: $kept", 7, kept.size)
        assertTrue(kept.none { it.endsWith("000001.json") || it.endsWith("000002.json") })
        val json = JSONObject(Docs.readText("$dir/${kept.last()}"))
        assertEquals("packetwall-rules", json.getString("format"))
        assertEquals(1, json.getJSONObject("state").getJSONArray("rules").length())
        assertNoText(str(R.string.backup_folder, "Download/e2e-backup", "—"), substring = true)
        // off
        press(str(R.string.turn_off))
        seeValue(str(R.string.backup_off))
        assertEquals("", s.backupUri)
    }

    @Test
    @Covers("SET-17")
    fun shorterLogAsksFirst() {
        launch()
        settings()
        val week = plural(R.plurals.days, 7, 7)
        val day = plural(R.plurals.days, 1, 1)
        chip(week)
        waitFor("7 days") { s.logDays == 7 }
        chip(day)
        waitText(str(R.string.confirm_log_shorter, day))
        tap(str(R.string.cancel))
        assertEquals(7, s.logDays)
        chip(day)
        waitText(str(R.string.confirm_log_shorter, day))
        tap(str(R.string.delete))
        waitFor("1 day") { s.logDays == 1 }
        // longer needs no question
        chip(week)
        waitFor("7 days again") { s.logDays == 7 }
        assertNoText(str(R.string.confirm_log_shorter, week))
    }

    @Test
    @Covers("SET-18")
    fun infoButtonsExplain() {
        launch()
        settings()
        val seen = ArrayList<Help>()
        for (h in Help.entries) {
            val desc = str(R.string.help_about, str(h.title))
            val m = hasContentDescription(desc)
            if (ui.onAllNodes(m).fetchSemanticsNodes().isEmpty()) continue
            scrollIntoView(m)
            ui.onAllNodes(m)[visible(m).first()].performClick()
            waitText(str(h.title))
            assertText(str(h.body).take(40), substring = true)
            back()
            waitNoText(str(h.body).take(40), substring = true)
            seen += h
        }
        assertTrue("help topics on Settings: $seen", seen.size >= 8)
    }

    /** Mean brightness (0..1) of a strip at the left edge of the screen: the window background. */
    private fun backgroundBrightness(): Double {
        val shot = instr.uiAutomation.takeScreenshot()
        val x = 4
        val ys = (device.displayHeight / 3 until device.displayHeight * 2 / 3 step 40)
        val v = ys.map { y ->
            val c = shot.getPixel(x, y)
            (android.graphics.Color.red(c) + android.graphics.Color.green(c) + android.graphics.Color.blue(c)) / (3 * 255.0)
        }.average()
        shot.recycle()
        return v
    }

    @Test
    @Covers("APP-06", "SET-01")
    fun themeAppliesAtOnceAndStays() {
        launch()
        settings()
        assertEquals(0, s.theme)
        tap(str(R.string.theme_dark))
        waitFor("dark saved") { s.theme == 2 }
        waitFor("dark on screen (${backgroundBrightness()})") { backgroundBrightness() < 0.3 }
        // after a restart of the screen
        scenario!!.close()
        launch()
        waitFor("still dark (${backgroundBrightness()})") { backgroundBrightness() < 0.3 }
        settings()
        tap(str(R.string.theme_light))
        waitFor("light saved") { s.theme == 1 }
        waitFor("light on screen (${backgroundBrightness()})") { backgroundBrightness() > 0.7 }
    }

    @Test
    @Covers("SET-15")
    fun listUpdatesAreScheduled() {
        launch()
        val wm = androidx.work.WorkManager.getInstance(ctx)
        fun state() = wm.getWorkInfosForUniqueWork("update-lists").get().lastOrNull()
        waitFor("scheduled: ${state()}") { state()?.state == androidx.work.WorkInfo.State.ENQUEUED }
        // only on unmetered networks while "Wi-Fi only" is on
        assertEquals(androidx.work.NetworkType.UNMETERED, state()!!.constraints.requiredNetworkType)
        settings()
        press(str(R.string.lists_wifi))
        waitFor("any network") { !s.listsWifiOnly && state()?.constraints?.requiredNetworkType == androidx.work.NetworkType.CONNECTED }
        press(str(R.string.lists_auto))
        waitFor("cancelled: ${state()}") { !s.listsAutoUpdate && state()?.state == androidx.work.WorkInfo.State.CANCELLED }
        press(str(R.string.lists_auto))
        waitFor("again: ${state()}") { state()?.state == androidx.work.WorkInfo.State.ENQUEUED }
    }

    @Test
    @Covers("RULE-06")
    fun routeOfAnAllowRule() {
        launch()
        upstream()
        chip(str(R.string.upstream_rules_only))
        waitFor("rules only") { !s.upAll }
        addGlobalRule(RuleSpec(Hosts.A, action = io.github.cinnamon415.packetwall.fw.Action.ALLOW, route = R.string.route_upstream))
        val mark = ProxyLog.mark()
        restart()
        // the rule's route: through the proxy; everything else directly
        val a = assertAllowed(Hosts.A)
        waitFor("${Hosts.A} proxied") { Rows.all().first { it.id == a.id }.proxied }
        val c = assertAllowed(Hosts.C)
        assertFalse(Rows.all().first { it.id == c.id }.proxied)
        Thread.sleep(500)
        val log = ProxyLog.since(mark).filter { it.startsWith("SOCKS CONNECT") }
        assertTrue("one CONNECT, for ${Hosts.A}: $log", log.isNotEmpty() && log.all { it.contains(a.dstIp) || it.contains(Hosts.A) })
        // "directly" while everything goes through the proxy
        drawer(R.string.nav_home)
        turnOff()
        settings()
        chip(str(R.string.upstream_all))
        waitFor("all") { s.upAll }
        val rule = app.firewall.state.value.rules.first()
        app.firewall.saveRule(rule.copy(route = io.github.cinnamon415.packetwall.fw.Route.DIRECT))
        settle()
        restart()
        val a2 = assertAllowed(Hosts.A_WWW)
        assertFalse("direct by its rule", Rows.all().first { it.id == a2.id }.proxied)
        val c2 = assertAllowed(Hosts.C)
        waitFor("the rest through the proxy") { Rows.all().first { it.id == c2.id }.proxied }
    }

    @Test
    @Covers("SET-11")
    fun proxyAppPicker() {
        launch()
        upstream()
        // real apps only (uid ≥ 10000), never Packetwall: the shell's traffic cannot stand in for a proxy app
        val pick = app.apps.installed().filter { it.uid >= 10000 && !it.packageName.startsWith("io.github.cinnamon415.packetwall") }
            .minByOrNull { it.name.lowercase() }!!
        press(str(R.string.upstream_app))
        waitText(str(R.string.upstream_app_pick))
        // the picker is a dialog over the settings: look inside it only
        val inDialog = androidx.compose.ui.test.hasAnyAncestor(androidx.compose.ui.test.isDialog())
        ui.onAllNodes(hasText(str(R.string.system_apps)) and isSelectable() and inDialog)[0].performClick()
        ui.onAllNodes(hasSetTextAction() and inDialog)[0].performTextInputCompat(pick.packageName)
        val row = hasText(pick.packageName) and androidx.compose.ui.test.hasClickAction() and !hasSetTextAction() and inDialog
        ui.waitUntil("${pick.packageName} in the picker", 8000) { ui.onAllNodes(row).fetchSemanticsNodes().isNotEmpty() }
        // neither the shell nor Packetwall are offered
        ui.onAllNodes(hasSetTextAction() and inDialog)[0].performTextClearanceCompat()
        ui.onAllNodes(hasSetTextAction() and inDialog)[0].performTextInputCompat("com.android.shell")
        ui.waitUntil("shell not offered", 5000) {
            ui.onAllNodes(hasText(str(R.string.nothing_found)) and inDialog).fetchSemanticsNodes().isNotEmpty()
        }
        ui.onAllNodes(hasSetTextAction() and inDialog)[0].performTextClearanceCompat()
        ui.onAllNodes(hasSetTextAction() and inDialog)[0].performTextInputCompat(pick.packageName)
        ui.waitUntil("row", 5000) { ui.onAllNodes(row).fetchSemanticsNodes().isNotEmpty() }
        ui.onAllNodes(row)[0].performClick()
        waitFor("proxy app") { s.upApp == pick.packageName }
        // the settings row names it
        seeValue(pick.name, substring = true)
        // "None" resets it
        press(str(R.string.upstream_app))
        waitText(str(R.string.upstream_app_pick))
        ui.onAllNodes(hasText(str(R.string.upstream_app_none)) and androidx.compose.ui.test.hasClickAction() and inDialog)[0].performClick()
        waitFor("none") { s.upApp.isEmpty() }
    }

    @Test
    @Covers("LOG-20")
    fun savedLogOutlivesARestart() {
        launch()
        addAppRule(shellName, RuleSpec(Hosts.B))
        settings()
        chip(plural(R.plurals.days, 1, 1))
        waitFor("1 day") { s.logDays == 1 }
        restart()
        assertAllowed(Hosts.A)
        assertBlocked(Hosts.B)
        fun old(t: Long, host: String) = Rows.all().any { it.host == host && it.firstSeen < t }
        // closed connections are written to disk and come back with the next session
        var t = System.currentTimeMillis()
        restart()
        waitFor("saved rows back") { old(t, Hosts.A) && old(t, Hosts.B) }
        // only blocked ones from now on
        settings()
        press(str(R.string.log_clear))
        waitText(str(R.string.confirm_log_clear))
        tap(str(R.string.delete))
        press(str(R.string.log_blocked_only))
        waitFor("blocked only") { s.logBlockedOnly }
        restart()
        assertAllowed(Hosts.A)
        assertBlocked(Hosts.B)
        t = System.currentTimeMillis()
        restart()
        waitFor("blocked row back") { old(t, Hosts.B) }
        assertFalse("allowed rows not saved", old(t, Hosts.A))
        // cleared: nothing comes back
        settings()
        press(str(R.string.log_clear))
        tap(str(R.string.delete))
        t = System.currentTimeMillis()
        restart()
        Thread.sleep(1500)
        assertFalse(old(t, Hosts.B))
    }

    @Test
    @Covers("SET-06")
    fun alwaysOnRowOpensAndroidVpnSettings() {
        launch()
        settings()
        seeValue(str(R.string.always_on_title))
        assertText(str(R.string.always_on_unknown))
        tap(str(R.string.always_on_title))
        val settingsApp = device.wait(
            androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.pkg("com.android.settings")),
            10_000
        )
        assertTrue("Android's VPN settings opened", settingsApp == true)
        device.pressBack()
        backToApp()
        // once protection ran the row says what Android has
        restart()
        settings()
        seeValue(str(R.string.always_on_off))
    }
}

fun androidx.compose.ui.test.SemanticsNodeInteraction.performTextClearanceCompat() = performTextClearance()

fun androidx.compose.ui.test.SemanticsNodeInteraction.performTextInputCompat(t: String) = performTextInput(t)
