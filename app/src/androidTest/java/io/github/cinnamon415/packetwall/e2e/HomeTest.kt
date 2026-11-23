package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureStatus
import io.github.cinnamon415.packetwall.ui.formatBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** HOME: the dashboard. */
/** The WebView test browser of the AOSP emulator: a second app that makes traffic on request. */
private const val BROWSER = "org.chromium.webview_shell"

class HomeTest : E2eTest() {

    private val profile get() = app.firewall.state.value.profile!!.name

    @Test
    @Covers("HOME-01", "HOME-02", "HOME-05")
    fun offOnOff() {
        launch()
        waitText(str(R.string.status_off))
        assertText("VPN · $profile")
        assertText(str(R.string.turn_on))
        assertNoText(str(R.string.turn_off))
        assertNoText(str(R.string.action_pause))
        // no speed chart while off
        assertNoText(str(R.string.speed_max, ""), substring = true)
        turnOn()
        waitText(str(R.string.status_on))
        assertText(str(R.string.action_pause))
        assertText(str(R.string.turn_off))
        assertNoText(str(R.string.turn_on))
        turnOff()
        waitText(str(R.string.status_off))
        assertTrue("tun0 is gone", !Net.vpnUp())
        val t = System.currentTimeMillis()
        assertTrue(Net.allowed(Hosts.A).ok)
        Rows.assertNone("traffic while off", 2000) { it.firstSeen >= t }
        // "<duration> · VPN · <profile>", the duration grows (last: it moves the test clock)
        turnOn()
        val line1 = waitForValue("status line") { textsOf(" · VPN · $profile").firstOrNull { it.contains(" · VPN") } }
        assertTrue("duration first: $line1", Regex("^\\d+ s · VPN · ").containsMatchIn(line1))
        Thread.sleep(2200)
        ui.mainClock.advanceTimeBy(2200)
        val line2 = textsOf(" · VPN · $profile").first { it.contains(" · VPN") }
        assertTrue("the time grows: $line1 → $line2", line1 != line2)
    }

    @Test
    @Covers("HOME-03")
    fun firewallOnlyModeHasNoPause() {
        launch()
        drawer(R.string.nav_settings)
        tap(str(R.string.capture_packets))
        waitFor("packets off") { !app.settings.current.capturePackets }
        drawer(R.string.nav_home)
        turnOn()
        assertNoText(str(R.string.action_pause))
        assertText(str(R.string.turn_off))
        Shade.open()
        assertEquals(listOf(str(R.string.action_stop).lowercase()), Shade.actions(str(R.string.notif_running)).map { it.lowercase() })
        Shade.close()
    }

    @Test
    @Covers("HOME-04", "LOG-18")
    fun pauseKeepsBlockingButStopsLogging() {
        launch()
        val r = addGlobalRule(RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        tap(str(R.string.action_pause))
        waitText(str(R.string.status_paused))
        assertText(str(R.string.action_resume))
        assertText(str(R.string.turn_off))
        assertNoText(str(R.string.action_pause))
        assertTrue(CaptureStatus.paused)
        val t = System.currentTimeMillis()
        // the rule keeps blocking while paused
        val reply = Net.http(Hosts.B)
        assertTrue("blocked while paused: ${reply.line}", !reply.ok)
        assertTrue(Net.allowed(Hosts.A).ok)
        Rows.assertNone("rows while paused", 2500) { it.firstSeen >= t && it.app.packageName == SHELL_PKG }
        tap(str(R.string.action_resume))
        waitText(str(R.string.action_pause))
        assertAllowed(Hosts.A)
        // example.com itself is in the system DNS cache (answered 0.0.0.0 while paused, 10 s): a subdomain
        assertBlocked("www.${Hosts.B}", rule = r.id)
    }

    @Test
    @Covers("HOME-06", "HOME-07", "HOME-08", "LOG-21")
    fun tilesMatchTheLogAndOpenIt() {
        launch()
        addGlobalRule(RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        assertAllowed(Hosts.A)
        assertBlocked(Hosts.B)
        Thread.sleep(1500)
        val rows = Rows.all()
        val stats = app.connections.stats.value
        // the tile values: connections, blocked, received bytes, active
        waitText(rows.size.toString())
        val blocked = rows.count { it.blocked }
        assertTrue(blocked >= 1)
        assertText(formatBytes(stats.bytesRcvd))
        tap(str(R.string.tile_blocked).uppercase())
        waitText(str(R.string.chip_all))
        ui.onNode(hasText(str(R.string.chip_blocked)) and isSelectable()).assertIsSelectedCompat()
        assertText("$blocked / ${Rows.all().size}", substring = true)
        drawer(R.string.nav_home)
        tap(str(R.string.tile_requests).uppercase())
        ui.onNode(hasText(str(R.string.chip_all)) and isSelectable()).assertIsSelectedCompat()
        drawer(R.string.nav_home)
        tap(str(R.string.tile_active).uppercase())
        waitText("active")
        drawer(R.string.nav_home)
        tap(str(R.string.tile_received).uppercase())
        waitText(str(R.string.speed))
        drawer(R.string.nav_home)
        // header icons: chart → statistics, log → the log as it was left (here: the "active" filter)
        tapDesc(str(R.string.nav_stats))
        waitText(str(R.string.speed))
        drawer(R.string.nav_home)
        tap(str(R.string.tile_active).uppercase())
        waitText("active")
        drawer(R.string.nav_home)
        tapDesc(str(R.string.nav_logs))
        ui.onNode(hasText(str(R.string.chip_all)) and isSelectable()).assertIsSelectedCompat()
        waitText("active")
    }

    @Test
    @Covers("HOME-09", "HOME-10", "HOME-11", "HOME-12")
    fun recentBlocks() {
        launch()
        waitText(str(R.string.no_blocks))
        val hosts = listOf("example.com", "example.net", "www.example.com", "www.example.net", "iana.org", "www.iana.org")
        hosts.forEach { addGlobalRule(RuleSpec(it, subdomains = false)) }
        drawer(R.string.nav_home)
        turnOn()
        hosts.forEach {
            Net.http(it, timeoutS = 2)
            Thread.sleep(300)
        }
        assertTrue(Net.allowed(Hosts.CONTROL).ok)
        // a blocked name is answered locally: its DNS query is the blocked row
        waitFor("blocked rows of all names") { Rows.all().filter { it.blocked }.map { it.host }.toSet().containsAll(hosts) }
        Thread.sleep(1500)
        val blocked = Rows.all().filter {
            it.blocked
        }.sortedWith(compareByDescending<io.github.cinnamon415.packetwall.engine.Conn> { it.firstSeen }.thenByDescending { it.id })
        val five = blocked.take(5)
        assertNoText(str(R.string.no_blocks))
        five.forEach { c ->
            assertText(c.title)
            assertText("${c.app.name} · ", substring = true)
        }
        // older ones are not shown
        blocked.drop(5).filter { o -> five.none { it.title == o.title } }.forEach { assertNoText(it.title) }
        assertTrue("an older blocked name is left out", blocked.drop(5).any { o -> five.none { it.title == o.title } })
        assertNoText(str(R.string.action_allow))
        // tap → connection; ‹ › walk the five (and only them)
        val ids = five.map { it.id }.toSet()
        fun shownId() = waitForValue("connection subtitle") {
            textsOf("#").firstNotNullOfOrNull { Regex("^#(\\d+) · ").find(it)?.groupValues?.get(1)?.toInt() }
        }
        tap(five[0].title)
        waitText(str(R.string.conn_overview))
        val first = shownId()
        assertTrue("opened one of the five: $first in $ids", first in ids)
        val seen = mutableSetOf(first)
        // to the newest end, then all the way to the oldest
        for (dir in listOf(R.string.conn_newer, R.string.conn_older)) {
            repeat(6) {
                if (!descEnabled(str(dir))) return@repeat
                val before = shownId()
                tapDesc(str(dir))
                ui.waitUntil(timeoutMillis = 5000) { shownId() != before }
                seen += shownId()
            }
        }
        assertEquals("‹ › walk exactly the five", ids, seen)
        assertTrue("‹ › stay within the five: $seen vs $ids", ids.containsAll(seen))
        back()
        // long press → quick rule sheet
        longTap(five[0].title)
        waitText(str(R.string.for_app))
        back()
        tap(str(R.string.all))
        ui.onNode(hasText(str(R.string.chip_blocked)) and isSelectable()).assertIsSelectedCompat()
    }

    /**
     * Every app icon beside a row is that row's app (names: package → app name), at least two apps on
     * screen.
     */
    private fun assertIconsMatch(where: String, names: Map<String, String>) {
        fun rows() = iconRows().filter { (_, t) -> t.any { x -> names.values.any { x.startsWith(it) } } }
        waitFor("$where: icons of their own rows ${rows()}") {
            val rows = rows()
            rows.map { it.first }.toSet().size >= 2 && rows.all { (pkg, t) -> names[pkg] != null && t.any { it.startsWith(names[pkg]!!) } }
        }
    }

    @Test
    @Covers("HOME-17")
    fun appIconsStayWithTheirRows() {
        launch()
        addGlobalRule(RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked(Hosts.B)
        waitText("$shellName · ", substring = true)
        // another app: the browser asks for a blocked name (one of its own: the system caches DNS answers for
        // all apps); its row comes on top and the shell's moves down, the icons must move with them
        Shell.run("am start -W -a android.intent.action.VIEW -d http://icons.${Hosts.B}/ -p $BROWSER")
        Rows.await("the browser's blocked row", 20_000) { it.app.packageName == BROWSER && it.blocked }
        backToApp()
        Thread.sleep(1500)
        val names = Rows.all().filter { it.blocked }.associate { it.app.packageName to it.app.name }
        assertTrue("two apps with blocks: $names", names.size >= 2)
        assertIconsMatch("recent blocks", names)
        // statistics and the log: rows that change order with the traffic
        val all = Rows.all().associate { it.app.packageName to it.app.name }
        drawer(R.string.nav_stats)
        assertIconsMatch("statistics", all)
        openLogs()
        assertIconsMatch("log", all)
        Shell.run("am force-stop $BROWSER")
    }

    @Test
    @Covers("HOME-13")
    fun topAppsByTraffic() {
        launch()
        turnOn()
        repeat(3) { assertTrue(Net.allowed(Hosts.A).ok) }
        Thread.sleep(1500)
        assertText(str(R.string.nav_stats))
        assertText(shellName)
        val total = Rows.all().filter { it.app.packageName == SHELL_PKG }.sumOf { it.bytes }
        assertText(formatBytes(total))
    }

    @Test
    @Covers("HOME-14")
    fun profileMenuSwitchesProfiles() {
        launch()
        val setId = addSet("Strict")
        addGlobalRule(RuleSpec(Hosts.B, set = "Strict"))
        // a profile "Open" with the new set off
        drawer(R.string.nav_sets)
        tap(str(R.string.profile_new))
        type("Open")
        tap(str(R.string.ok))
        waitText("Open")
        setSwitch("Strict", false)
        waitFor("set off") { !app.firewall.state.value.isEnabled(setId) }
        drawer(R.string.nav_home)
        turnOn()
        // a fresh name for every check: a blocked name stays in the system DNS cache for 10 s
        assertAllowed(Hosts.B)
        tap(str(R.string.status_on))
        val main = str(R.string.profile_default)
        tap(main)
        waitText("VPN · $main", substring = true)
        assertBlocked("www.${Hosts.B}")
        tap(str(R.string.status_on))
        tap("Open")
        waitText("VPN · Open", substring = true)
        assertAllowed(Hosts.B)
        tap(str(R.string.status_on))
        tap(str(R.string.nav_sets))
        waitText(str(R.string.profiles))
    }

    @Test
    @Covers("HOME-16")
    fun wideLayout() {
        launch()
        device.setOrientationLeft()
        try {
            Thread.sleep(1500)
            ui.waitForIdle()
            waitText(str(R.string.status_off))
            val tiles = listOf(R.string.tile_requests, R.string.tile_blocked, R.string.tile_received, R.string.tile_active).map { id ->
                ui.onAllNodes(hasText(str(id), ignoreCase = true)).fetchSemanticsNodes().first {
                    it.boundsInWindow.width > 0
                }.boundsInWindow
            }
            // four tiles in one row, right of the status column
            val top = tiles.map { it.top }
            assertTrue("tiles in one row: $top", top.max() - top.min() < 8f)
            val status = ui.onAllNodes(hasText(str(R.string.status_off))).fetchSemanticsNodes().first {
                it.boundsInWindow.width > 0
            }.boundsInWindow
            assertTrue("status left of the tiles", status.right <= tiles.minOf { it.left })
        } finally {
            device.setOrientationNatural()
            device.unfreezeRotation()
        }
    }

    @Test
    @Covers("HOME-15")
    fun strictPrivateDnsIsShown() {
        launch()
        // the emulator is the device under test: its Private DNS goes strict for this test only
        val mode = Shell.run("settings get global private_dns_mode").trim()
        val host = Shell.run("settings get global private_dns_specifier").trim()
        try {
            Shell.run("settings put global private_dns_specifier dns.google; settings put global private_dns_mode hostname")
            drawer(R.string.nav_home)
            turnOn()
            waitText(str(R.string.private_dns_strict), 15_000)
            assertTrue(CaptureStatus.privateDnsStrict.value)
        } finally {
            Shell.run(
                (if (mode == "null") "settings delete global private_dns_mode" else "settings put global private_dns_mode $mode") + "; " +
                    (
                        if (host ==
                            "null"
                        ) {
                            "settings delete global private_dns_specifier"
                        } else {
                            "settings put global private_dns_specifier $host"
                        }
                        )
            )
        }
        // back to automatic: the notice goes
        turnOff()
        waitFor("Off on screen; state ${CaptureStatus.state.value}, tun0 ${Net.vpnUp()}") { exists(str(R.string.status_off)) }
        turnOn()
        waitNoText(str(R.string.private_dns_strict), 15_000)
    }
}

fun androidx.compose.ui.test.SemanticsNodeInteraction.assertIsSelectedCompat() = assertIsSelected()
