package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.performClick
import io.github.cinnamon415.packetwall.R
import org.junit.Assert.assertTrue
import org.junit.Test

/** STAT: the statistics screen and its links into the log. */
class StatsTest : E2eTest() {

    private fun stats() {
        drawer(R.string.nav_stats)
        ui.waitUntil("stats", 8000) { ui.onAllNodes(has(str(R.string.speed))).fetchSemanticsNodes().isNotEmpty() }
    }

    /** Opens the row [text] (scrolled to), expects the log with [filter]; back to the statistics. */
    private fun opensLog(text: String, filter: String, blocked: Boolean = false, topmost: Boolean = false) {
        seeValue(text)
        if (topmost) {
            val m = has(text) and androidx.compose.ui.test.hasClickAction()
            val nodes = ui.onAllNodes(m).fetchSemanticsNodes()
            ui.onAllNodes(m)[visible(m).minByOrNull { nodes[it].boundsInWindow.top }!!].performClick()
        } else {
            tap(text)
        }
        waitText(str(R.string.chip_all))
        assertText(filter)
        val chip = hasText(str(if (blocked) R.string.chip_blocked else R.string.chip_all)) and isSelectable()
        val sel = ui.onAllNodes(isSelectable()).fetchSemanticsNodes().map {
            it.config.getOrElse(SemanticsProperties.Text) { emptyList() }.joinToString { t -> t.text } + "=" +
                it.config.getOrNull(SemanticsProperties.Selected)
        }
        assertTrue(
            "${if (blocked) "Blocked" else "All"} chip selected: $sel",
            ui.onAllNodes(chip).fetchSemanticsNodes().any { it.config.getOrNull(SemanticsProperties.Selected) == true }
        )
        back()
        stats()
    }

    @Test
    @Covers("STAT-08")
    fun emptySectionsAreHidden() {
        launch()
        stats()
        listOf(R.string.top_apps, R.string.top_hosts, R.string.protocols, R.string.trackers_by_app, R.string.blocked_by_app).forEach {
            assertTrue("no ${str(it)} without traffic", ui.onAllNodes(has(str(it))).fetchSemanticsNodes().isEmpty())
        }
    }

    @Test
    @Covers("STAT-01", "STAT-03", "STAT-04", "STAT-05", "STAT-07", "STAT-08", "LOG-21")
    fun numbersMatchTheLogAndLinkIntoIt() {
        launch()
        addAppRule(shellName, RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        repeat(2) { assertAllowed(Hosts.A) }
        assertBlocked(Hosts.B)
        settle()
        stats()
        // connections and DNS queries as counted by the log
        val totals = app.connections.totals.value
        assertTrue(totals.total > 0)
        assertText("${totals.total}")
        assertText("${app.connections.stats.value.dnsQueries}")
        // the sections there is something for; none for trackers (no database)
        listOf(R.string.top_apps, R.string.top_hosts, R.string.protocols, R.string.blocked_by_app).forEach { seeValue(str(it)) }
        assertTrue(ui.onAllNodes(has(str(R.string.trackers_by_app))).fetchSemanticsNodes().isEmpty())
        // hosts: connections · bytes
        // DNS queries are not counted as connections to the host
        val toA = Rows.all().count { it.host == Hosts.A && it.l7proto != "DNS" }
        seeValue(Hosts.A)
        assertTrue("$toA connections to ${Hosts.A}: ${textsOf("$toA · ")}", textsOf("$toA · ").isNotEmpty())
        // blocked by app: the shell's blocked count
        val blocked = Rows.all().count { it.blocked && it.app.packageName == SHELL_PKG }
        assertTrue(blocked > 0)
        // links into the log with a filter
        opensLog(Hosts.A, "host == \"${Hosts.A}\"")
        opensLog("HTTP", "proto == \"HTTP\"")
        // the first shell row is under "Apps by traffic", the next under "Blocked by app"
        scrollIntoView(has(str(R.string.top_apps)))
        opensLog(shellName, "pkg == \"$SHELL_PKG\"", topmost = true)
    }

    @Test
    @Covers("STAT-07")
    fun blockedByAppOpensTheBlockedLog() {
        launch()
        addAppRule(shellName, RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked(Hosts.B)
        stats()
        seeValue(str(R.string.blocked_by_app))
        // the last shell row on the screen is the one under "Blocked by app"
        val m = has(shellName) and androidx.compose.ui.test.hasClickAction()
        scrollIntoView(has(str(R.string.blocked_by_app)))
        val rows = ui.onAllNodes(m).fetchSemanticsNodes()
        val last = rows.indices.maxByOrNull { rows[it].boundsInWindow.top }!!
        ui.onAllNodes(m)[last].performClick()
        waitText(str(R.string.chip_all))
        assertText("pkg == \"$SHELL_PKG\"")
        val chip = hasText(str(R.string.chip_blocked)) and isSelectable()
        assertTrue(ui.onAllNodes(chip).fetchSemanticsNodes().any { it.config.getOrNull(SemanticsProperties.Selected) == true })
    }

    @Test
    @Covers("STAT-02")
    fun speedChartAndPause() {
        launch()
        turnOn()
        repeat(3) { assertAllowed(Hosts.A) }
        stats()
        // current up/down and the peak
        val perSecond = str(R.string.per_second, "").trim()
        waitFor("current speed") { textsOf("↑ ").any { it.contains(perSecond) } && textsOf("↓ ").any { it.contains(perSecond) } }
        assertTrue(textsOf(str(R.string.speed_max, "").trim()).isNotEmpty())
        // paused: since when
        drawer(R.string.nav_home)
        tap(str(R.string.action_pause))
        waitText(str(R.string.status_paused))
        val since = io.github.cinnamon415.packetwall.engine.CaptureStatus.pausedSince.value!!
        val hhmm = io.github.cinnamon415.packetwall.ui.formatTime(since).substring(0, 5)
        stats()
        waitText(str(R.string.chart_paused_since, hhmm))
    }
}
