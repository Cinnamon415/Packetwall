package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.ui.FILTER_EXAMPLES
import io.github.cinnamon415.packetwall.ui.formatTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** LOG: the connection log. */
class LogTest : E2eTest() {

    /** Known traffic from the shell: allowed HTTP, a blocked name, TCP to an IP, raw UDP DNS, ping. Returns the rule id. */
    private fun makeTraffic(): Int {
        val r = addGlobalRule(RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        assertAllowed(Hosts.A)
        assertAllowed("one.one.one.one", Hosts.CF_IP)
        // plain HTTP to the HTTPS port: Cloudflare answers 400, the connection is allowed
        assertAllowed("one.one.one.one", Hosts.CF_IP, 443)
        assertBlocked(Hosts.B, rule = r.id)
        val dns = Net.dnsUdp(Hosts.CF_IP, Hosts.C)
        assertTrue("raw DNS answered", dns.size > 12)
        assertTrue("ping answered", Net.pingAnswered(Hosts.CF_IP))
        Rows.await("udp dns") { it.dstIp == Hosts.CF_IP && it.dstPort == 53 }
        Rows.await("icmp") { it.ipproto == 1 && it.dstIp == Hosts.CF_IP }
        Thread.sleep(1500)
        return r.id
    }

    private fun total() = Rows.all().size

    private fun subtitle(shown: Int, total: Int = total()) = "$shown / $total"

    /** The "shown / total" subtitle on screen. */
    private fun shownNow(): String? = textsOf(" / ").firstOrNull { Regex("^\\d+ / \\d+$").matches(it) }

    private fun expectShown(what: String, n: Int, total: Int = total(), rows: List<Conn> = Rows.all()) {
        try {
            ui.waitUntil(timeoutMillis = 5000) {
                pump()
                exists(subtitle(n, total))
            }
        } catch (e: Throwable) {
            val field = ui.onAllNodes(androidx.compose.ui.test.hasSetTextAction()).fetchSemanticsNodes().map {
                it.config.getOrNull(androidx.compose.ui.semantics.SemanticsProperties.EditableText)?.text
            }
            throw AssertionError(
                "$what: expected ${subtitle(n, total)}, screen shows ${shownNow()}; field $field, " +
                    "filter ${io.github.cinnamon415.packetwall.ui.LogsLink.filter.value}. Rows:\n" +
                    rows.joinToString("\n") { c ->
                        "#${c.id} ${c.protoLabel} ${c.host} ${c.dstIp}:${c.dstPort} b=${c.blocked} url=${c.url}"
                    }
            )
        }
    }

    private fun assertShown(what: String, pred: (Conn) -> Boolean) = expectShown(what, Rows.all().count(pred))

    private fun chip(text: Int) {
        val m = hasText(str(text)) and isSelectable()
        ui.onAllNodes(m)[visible(m).last()].performClickCompat()
        ui.waitForIdle()
    }

    @Test
    @Covers("LOG-01", "LOG-19")
    fun emptyStatesAndSessionLog() {
        launch()
        openLogs()
        waitText(str(R.string.empty_logs_off))
        drawer(R.string.nav_home)
        turnOn()
        openLogs()
        waitText(str(R.string.empty_logs))
        assertAllowed(Hosts.A)
        waitText(Hosts.A)
        // off: the session log stays visible; the next start begins a new one
        drawer(R.string.nav_home)
        turnOff()
        openLogs()
        assertText(Hosts.A)
        drawer(R.string.nav_home)
        turnOn()
        openLogs()
        waitText(str(R.string.empty_logs))
        assertTrue(Rows.all().none { it.host == Hosts.A })
    }

    @Test
    @Covers("LOG-02", "LOG-03", "LOG-04")
    fun rowsChipsAndOrder() {
        launch()
        val rule = makeTraffic()
        openLogs()
        val rows = Rows.all()
        waitText(subtitle(rows.size))
        // one row per connection: app, "proto, port", host or IP, status
        val http = rows.last { it.host == Hosts.A && it.dstPort == 80 }
        assertText(shellName)
        assertText("HTTP, 80")
        assertText("DNS, 53")
        assertText(Hosts.A)
        assertText(str(R.string.st_blocked))
        // ICMP to 1.1.1.1
        assertTrue(rows.any { it.protoLabel == "ICMP" })
        // newest on top: the blocked name was queried after example.org
        val yA = ui.onAllNodes(hasText(Hosts.A)).fetchSemanticsNodes().minOf { it.boundsInWindow.top }
        val yB = ui.onAllNodes(hasText(Hosts.B)).fetchSemanticsNodes().minOf { it.boundsInWindow.top }
        assertTrue("newer row above the older one", yB < yA)
        assertFalse("the HTTP/1.0 connection is closed", http.active)
        chip(R.string.chip_blocked)
        assertShown("blocked") { it.blocked }
        assertTrue(Rows.all().filter { it.blocked }.all { it.fwRule == rule })
        chip(R.string.chip_allowed)
        assertShown("allowed") { !it.blocked }
        chip(R.string.chip_all)
        assertShown("all") { true }
    }

    @Test
    @Covers("LOG-03")
    fun activeTurnsClosedWithoutReentering() {
        launch()
        turnOn()
        openLogs()
        // a connection held open for 4 s
        Thread {
            Shell.run(
                "(printf 'GET / HTTP/1.1\\r\\nHost: one.one.one.one\\r\\n\\r\\n'; sleep 4) | timeout 6 toybox nc ${Hosts.CF_IP} 80 > /dev/null"
            )
        }.start()
        val c = Rows.await("open connection") { it.dstIp == Hosts.CF_IP && it.dstPort == 80 && it.active }
        waitText(str(R.string.st_active))
        tap(c.title)
        waitText(str(R.string.st_active))
        waitFor("closed", 15_000) { Rows.all().first { it.id == c.id }.let { !it.active } }
        waitText(str(R.string.st_closed), 5000)
    }

    @Test
    @Covers("LOG-05", "LOG-17")
    fun compactViewAndStateKeptAcrossScreens() {
        launch()
        makeTraffic()
        openLogs()
        tapDesc(str(R.string.compact_view))
        waitText("HTTP, 80 · ${Hosts.A}")
        chip(R.string.chip_blocked)
        type("host ~ example")
        chip(R.string.tab_dns)
        drawer(R.string.nav_settings)
        drawer(R.string.nav_logs)
        assertText("host ~ example")
        ui.onNode(hasText(str(R.string.tab_dns)) and isSelectable()).assertIsSelectedCompat()
        ui.onNode(hasText(str(R.string.chip_blocked)) and isSelectable()).assertIsSelectedCompat()
        chip(R.string.tab_conns)
        chip(R.string.chip_all)
        type("")
        assertText("HTTP, 80 · ${Hosts.A}")
        tapDesc(str(R.string.compact_view))
        waitNoText("HTTP, 80 · ${Hosts.A}")
        assertText("HTTP, 80")
    }

    @Test
    @Covers("LOG-06", "LOG-07", "LOG-08")
    fun filterExpressions() {
        launch()
        makeTraffic()
        drawer(R.string.nav_home)
        turnOff() // the log stays as it is: counts do not move under the checks
        openLogs()
        val all = Rows.all()
        val cases = listOf<Pair<String, (Conn) -> Boolean>>(
            "host ~ example" to { it.host?.contains("example", true) == true },
            "HOST ~ EXAMPLE" to { it.host?.contains("example", true) == true },
            "app == \"$shellName\"" to { it.app.name.equals(shellName, true) },
            "pkg == $SHELL_PKG" to { it.app.packageName == SHELL_PKG },
            "port == 443" to { it.dstPort == 443 },
            "port <= 80" to { it.dstPort <= 80 },
            "port >= 443" to { it.dstPort >= 443 },
            "port != 53" to { it.dstPort != 53 },
            "proto == DNS" to { it.protoLabel.equals("DNS", true) },
            "proto == icmp" to { it.protoLabel.equals("ICMP", true) },
            "bytes > 100" to { it.bytes > 100 },
            "rcvd > 0 && sent > 0" to { it.rcvdBytes > 0 && it.sentBytes > 0 },
            "ip == ${Hosts.CF_IP}" to { it.dstIp == Hosts.CF_IP },
            "blocked" to { it.blocked },
            "allowed" to { !it.blocked },
            "active" to { it.active },
            "host ~ example && blocked" to { it.host?.contains("example", true) == true && it.blocked },
            "host ~ example and !blocked" to { it.host?.contains("example", true) == true && !it.blocked },
            "port == 80 || port == 443" to { it.dstPort == 80 || it.dstPort == 443 },
            "port == 80 or port == 443" to { it.dstPort == 80 || it.dstPort == 443 },
            "not (port == 53)" to { it.dstPort != 53 },
            "!(proto == DNS) && port != 443" to { !it.protoLabel.equals("DNS", true) && it.dstPort != 443 },
            "host !~ example" to { it.host?.contains("example", true) != true },
            "(blocked || port == 443) && host ~ ." to { (it.blocked || it.dstPort == 443) && it.host?.contains(".") == true },
            // plain text: app, host or IP, package, protocol
            "one.one" to { c -> c.app.name.contains("one.one", true) || c.title.contains("one.one", true) || c.dstIp.contains("one.one") },
            "1.1.1.1" to { c -> c.app.name.contains("1.1.1.1") || c.title.contains("1.1.1.1") || c.dstIp.contains("1.1.1.1") }
        )
        for ((expr, pred) in cases) {
            type(expr)
            val n = all.count(pred)
            expectShown("\"$expr\"", n, all.size, all)
            assertTrue("\"$expr\" matches something", n > 0 || expr == "active")
        }
        // errors: the field says what is wrong and the list is not emptied silently
        val errors = listOf(
            "host ~ \"abc" to str(R.string.filter_unterminated),
            "colour == red" to str(R.string.filter_unknown_field, "colour"),
            "(port == 80" to str(R.string.filter_missing_paren),
            "port ==" to str(R.string.filter_unexpected_end),
            "host example && blocked" to str(R.string.filter_expected_operator, "example")
        )
        for ((expr, msg) in errors) {
            type(expr)
            waitText(msg)
            assertTrue("$expr: the list is not empty", !exists(subtitle(0, all.size)))
        }
        // the help sheet: every example goes into the field and parses
        for (ex in FILTER_EXAMPLES) {
            type("")
            tapDesc(str(R.string.filter_help))
            waitText(str(R.string.fh_title))
            tap(ex)
            waitNoText(str(R.string.fh_title))
            assertText(ex)
            errors.forEach { (_, msg) -> assertNoText(msg) }
        }
    }

    @Test
    @Covers("LOG-09", "LOG-10")
    fun dnsAndHttpTabs() {
        launch()
        makeTraffic()
        openLogs()
        chip(R.string.tab_dns)
        val dns = Rows.all().filter { it.l7proto == "DNS" }
        expectShown("DNS tab", dns.size)
        assertText(str(R.string.dns_blocked_answer))
        // an allowed name shows its answer
        waitText("→ ", substring = true)
        assertNoText("HTTP, 80")
        chip(R.string.tab_http)
        val http = Rows.all().filter { !it.url.isNullOrEmpty() }
        expectShown("HTTP tab", http.size)
        assertTrue(http.any { it.host == Hosts.A })
        assertText(http.first { it.host == Hosts.A }.url!!)
    }

    @Test
    @Covers("LOG-11", "LOG-12")
    fun openRowWalkFilteredAndLongPress() {
        launch()
        makeTraffic()
        openLogs()
        type("port == 80")
        val shown = Rows.all().filter { it.dstPort == 80 }.sortedByDescending { it.id }
        waitText(subtitle(shown.size))
        tap(shown.first().title)
        waitText(str(R.string.conn_overview))
        assertFalse("newest: ‹ is disabled", descEnabled(str(R.string.conn_newer)))
        val visited = mutableListOf<String>()
        repeat(shown.size - 1) {
            tapDesc(str(R.string.conn_older))
            visited += textsOf(":80").first { it.endsWith(":80") || it.contains(":80 ") }
        }
        assertFalse("oldest: › is disabled", descEnabled(str(R.string.conn_older)))
        assertTrue("only port 80 rows: $visited", visited.all { it.contains(":80") })
        back()
        longTap(shown.first().title)
        waitText(str(R.string.for_app))
        waitText(str(R.string.who_global))
    }

    @Test
    @Covers("LOG-13")
    fun csvExportHasExactlyTheShownRows() {
        launch()
        val rule = makeTraffic()
        drawer(R.string.nav_home)
        turnOff()
        openLogs()
        type("host ~ example")
        val shown = Rows.all().filter { it.host?.contains("example", true) == true }
        waitText(subtitle(shown.size))
        tapDesc(str(R.string.more))
        val name = "e2e-${System.currentTimeMillis()}.csv"
        expectToast(str(R.string.exported)) {
            tap(str(R.string.export_csv))
            Docs.save(name)
        }
        val lines = Docs.readText("${Docs.DIR}/$name").trim().lines()
        val head = lines.first().split(",")
        assertEquals("id", head[0])
        assertTrue(head.containsAll(listOf("status", "blocked", "rule", "route", "host", "dst_port")))
        val rows = lines.drop(1).map { l -> head.zip(l.split(",")).toMap() }
        assertEquals("one CSV row per shown row", shown.map { it.id.toString() }.toSet(), rows.map { it["id"] }.toSet())
        for (r in rows) {
            val c = shown.first { it.id.toString() == r["id"] }
            assertEquals(
                if (c.blocked) {
                    "blocked"
                } else if (c.active) {
                    "active"
                } else {
                    "closed"
                },
                r["status"]
            )
            assertEquals(c.blocked.toString(), r["blocked"])
            assertEquals(if (c.fwRule != 0) c.fwRule.toString() else "", r["rule"])
            assertEquals("direct", r["route"])
            assertEquals(c.host, r["host"])
        }
        assertTrue(rows.any { it["rule"] == rule.toString() })
        Docs.remove("${Docs.DIR}/$name")
    }

    @Test
    @Covers("LOG-14")
    fun pcapngExportHasOnlyShownConnections() {
        launch()
        makeTraffic()
        drawer(R.string.nav_home)
        turnOff()
        openLogs()
        type("ip == ${Hosts.CF_IP} && port == 80")
        val shown = Rows.all().filter { it.dstIp == Hosts.CF_IP && it.dstPort == 80 }
        waitText(subtitle(shown.size))
        tapDesc(str(R.string.more))
        val name = "e2e-${System.currentTimeMillis()}.pcapng"
        expectToast(str(R.string.exported)) {
            tap(str(R.string.export_pcapng_filtered))
            Docs.save(name)
        }
        val pkts = Pcapng.packets(Docs.read("${Docs.DIR}/$name"))
        assertTrue("packets exported", pkts.isNotEmpty())
        val ports = shown.map { it.srcPort }.toSet()
        for (p in pkts) {
            val t = Pcapng.tuple(p)!!
            val (ip, sport, dport) = t
            assertTrue(
                "only 1.1.1.1:80 traffic: $t",
                (ip == Hosts.CF_IP && (dport == 80 && sport in ports)) || (sport == 80 && dport in ports)
            )
        }
        Docs.remove("${Docs.DIR}/$name")
    }

    private val listM = androidx.compose.ui.test.SemanticsMatcher.keyIsDefined(
        androidx.compose.ui.semantics.SemanticsProperties.VerticalScrollAxisRange
    )

    private fun listNode() = ui.onAllNodes(listM)[visible(listM).last()]

    /** How far the list is scrolled (lazy lists report an estimate) and how far it can go. */
    private fun scroll(): Pair<Float, Float> {
        val r = listNode().fetchSemanticsNode().config[androidx.compose.ui.semantics.SemanticsProperties.VerticalScrollAxisRange]
        return r.value() to r.maxValue()
    }

    private fun atTop() = scroll().first <= 1f

    /** The finger moves by [part] of the list height (negative: up, the list scrolls down) and stays down. */
    private fun hold(part: Float) {
        listNode().performTouchInput { down(center) }
        repeat(10) {
            listNode().performTouchInput { moveBy(androidx.compose.ui.geometry.Offset(0f, height * part / 10), delayMillis = 30) }
        }
        ui.waitForIdle()
    }

    private fun lift() = listNode().performTouchInput { up() }

    /** [n] connections from the shell to 1.1.1.1, one per port from [from]: rows told apart by "TCP, port". */
    private fun portRows(from: Int, n: Int) {
        Shell.run(
            (from until from + n).joinToString("\n") {
                "toybox nc -w 1 ${Hosts.CF_IP} $it < /dev/null > /dev/null 2>&1 &"
            } + "\nwait"
        )
        waitFor("rows to ports $from…${from + n - 1}", 20_000) {
            (from until from + n).all { p ->
                Rows.all().any {
                    it.dstIp == Hosts.CF_IP &&
                        it.dstPort == p
                }
            }
        }
    }

    /** "TCP, port" rows on screen: port → top of the text in the window. */
    private fun portsOnScreen(): Map<Int, Float> = ui.onAllNodes(has("TCP, ", substring = true), true).fetchSemanticsNodes()
        .filter { it.boundsInWindow.top >= 0 && it.boundsInWindow.bottom <= device.displayHeight }
        .mapNotNull { n ->
            val t = n.config[androidx.compose.ui.semantics.SemanticsProperties.Text].joinToString("") { it.text }
            Regex("^TCP, (\\d+)$").find(t)?.groupValues?.get(1)?.toInt()?.let { it to n.boundsInWindow.top }
        }.toMap()

    @Test
    @Covers("LOG-15", "LOG-16")
    fun jumpButtonAndScrollbar() {
        launch()
        turnOn()
        // 70 rows: several screens
        portRows(7000, 70)
        drawer(R.string.nav_home)
        turnOff()
        openLogs()
        waitText("${Rows.all().size} / ${Rows.all().size}")
        val jump = hasContentDescription(str(R.string.logs_to_top))
        val today = str(R.string.today)
        fun shown() = visible(jump).isNotEmpty()
        assertTrue("the log opens at the top", atTop())
        assertFalse("no button before scrolling", shown())
        // less than half a screen from the top: no button even while scrolling
        hold(-1f / 6)
        ui.waitForIdle()
        assertFalse("no button half a screen from the top", shown())
        lift()
        // further down it shows while scrolling
        hold(-0.6f)
        ui.waitUntil("up button while scrolling", 3000) { shown() }
        // and stays 3 s after the scroll stops: the clock goes by hand from here
        ui.mainClock.autoAdvance = false
        try {
            lift()
            ui.mainClock.advanceTimeBy(1500)
            assertTrue("still shown 1.5 s after scrolling", shown())
            ui.mainClock.advanceTimeBy(2000)
            assertFalse("hidden 3 s after scrolling", shown())
        } finally {
            ui.mainClock.autoAdvance = true
        }
        // tapping it goes to the newest row and hides it
        hold(-1f / 6)
        ui.waitUntil("shown again", 3000) { shown() }
        lift()
        ui.onAllNodes(jump)[visible(jump).last()].performClickCompat()
        ui.waitUntil("scrolled to the top", 5000) { atTop() }
        val newest = Rows.all().maxBy { it.id }
        assertTrue("the newest row is on screen", portsOnScreen().containsKey(newest.dstPort))
        ui.waitUntil("no button at the top", 2000) { !shown() }
        // the scrollbar shows while scrolling and takes drags on its thumb for 1.5 s after; at the top the
        // thumb is at the top of the track (5 dp inset, at least 56 dp tall)
        hold(-1f / 10)
        ui.mainClock.autoAdvance = false
        try {
            lift()
            ui.mainClock.advanceTimeBy(200)
            val (from, _) = scroll()
            listNode().performTouchInput { down(androidx.compose.ui.geometry.Offset(width - 17.dp.toPx(), 30.dp.toPx())) }
            repeat(10) {
                listNode().performTouchInput { moveBy(androidx.compose.ui.geometry.Offset(0f, height / 30f)) }
                ui.mainClock.advanceTimeBy(32)
            }
            ui.mainClock.advanceTimeBy(300)
            if (!exists(today)) dumpTree("no bubble")
            assertTrue("time bubble while dragging the thumb", exists(today))
            // the bubble shows the time of a row
            val times = Rows.all().map { formatTime(it.firstSeen) }.toSet()
            assertTrue("the bubble shows a row's time", times.any { exists(it) })
            assertFalse("up button hidden while dragging the scrollbar", shown())
            assertTrue("dragging the thumb down scrolled the list down", scroll().first > from + 10f)
            listNode().performTouchInput { up() }
            ui.mainClock.advanceTimeBy(500)
            assertFalse("bubble gone after the drag", exists(today))
        } finally {
            ui.mainClock.autoAdvance = true
        }
    }

    @Test
    @Covers("LOG-22", "LOG-03")
    fun newRowsAtTheTopStayInView() {
        launch()
        turnOn()
        portRows(7000, 40)
        openLogs()
        waitFor("all rows listed") { shownNow() == subtitle(total()) }
        assertTrue(atTop())
        // at the top: a new connection shows up on screen, above the others
        portRows(7100, 1)
        waitFor("the new row on screen ${portsOnScreen()}") { portsOnScreen().containsKey(7100) }
        val top = portsOnScreen()
        assertEquals("the newest is the first row: $top", 7100, top.minBy { it.value }.key)
        assertTrue("still at the very top", atTop())
        // a few more in a burst: the screen keeps following
        portRows(7101, 3)
        waitFor("the burst on screen ${portsOnScreen()}") { (7101..7103).all { portsOnScreen().containsKey(it) } }
        assertTrue(atTop())
        // scrolled down: what is on screen stays where it is, new rows go above out of sight
        hold(-0.4f)
        lift()
        Thread.sleep(800)
        val before = portsOnScreen()
        assertTrue("rows on screen: $before", before.size >= 4)
        assertFalse(atTop())
        portRows(7200, 2)
        Thread.sleep(1500)
        val after = portsOnScreen()
        for ((p, y) in before) assertEquals("row TCP, $p stays put", y, after[p] ?: -1f, 2f)
        assertFalse("the new row is above the screen", after.containsKey(7200) || after.containsKey(7201))
        // back at the top it follows again
        listNode().performTouchInput { swipeDown() }
        listNode().performTouchInput { swipeDown() }
        waitFor("back at the top") { atTop() }
        portRows(7300, 1)
        waitFor("the new row on screen again ${portsOnScreen()}") { portsOnScreen().containsKey(7300) }
        assertEquals(7300, portsOnScreen().minBy { it.value }.key)
    }

    private fun backToHome() {
        val home = str(R.string.recent_blocks)
        repeat(3) {
            if (exists(home)) return
            back()
            Thread.sleep(300)
        }
        waitText(home)
    }

    @Test
    @Covers("LOG-17", "HOME-08")
    fun filterKeptWhicheverWayTheLogIsLeft() {
        launch()
        makeTraffic()
        openLogs()
        val expr = "host ~ example"
        type(expr)
        chip(R.string.chip_blocked)
        chip(R.string.tab_dns)
        tapDesc(str(R.string.compact_view))
        fun kept(how: String) {
            waitText(expr)
            ui.onNode(hasText(str(R.string.tab_dns)) and isSelectable()).assertIsSelectedCompat()
            ui.onNode(hasText(str(R.string.chip_blocked)) and isSelectable()).assertIsSelectedCompat()
            assertTrue(
                "$how: compact view kept",
                app.getSharedPreferences(io.github.cinnamon415.packetwall.ui.LogsViewModel.PREFS, 0).getBoolean("logs.compact", false)
            )
        }
        // back to Home (the first Back may only close the keyboard), then the log icon in its header
        backToHome()
        tapDesc(str(R.string.nav_logs))
        kept("Home's log icon")
        // through the menu
        drawer(R.string.nav_apps)
        drawer(R.string.nav_logs)
        kept("the menu")
        // the app closed (back from Home finishes the activity) and opened again
        backToHome()
        device.pressBack()
        scenario?.close()
        launch()
        drawer(R.string.nav_logs)
        kept("the app reopened")
        // a new process: what is in memory is gone, the saved choices bring it back
        scenario?.close()
        io.github.cinnamon415.packetwall.ui.LogsLink.loaded = false
        io.github.cinnamon415.packetwall.ui.LogsLink.filter.value = ""
        io.github.cinnamon415.packetwall.ui.LogsLink.status.value = io.github.cinnamon415.packetwall.ui.StatusFilter.ALL
        launch()
        drawer(R.string.nav_logs)
        kept("a new process")
        // a link with its own filter replaces it (a Home tile)
        drawer(R.string.nav_home)
        tap(str(R.string.tile_active).uppercase())
        waitText("active")
        assertNoText(expr)
        ui.onNode(hasText(str(R.string.tab_conns)) and isSelectable()).assertIsSelectedCompat()
    }
}
