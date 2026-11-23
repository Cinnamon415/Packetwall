package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.performClick
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.ListParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** SRCH: one field for rules, lists, apps and connections. */
class SearchTest : E2eTest() {

    private val st get() = app.firewall.state.value

    private fun search(q: String) {
        type(q)
        // lists are searched 250 ms after typing stops: a delay on the test's clock
        ui.mainClock.advanceTimeBy(400)
        ui.waitForIdle()
    }

    /** The chip [label] with its count ("Rules 2"); null while there is no such chip. */
    private fun chipCount(label: Int): Int? {
        val m = hasText(str(label), substring = true) and isSelectable()
        return textsOfNodes(m).firstNotNullOfOrNull {
            Regex("^" + Regex.escape(str(label)) + " (\\d+)$").find(it)?.groupValues?.get(1)?.toInt()
        }
    }

    private fun textsOfNodes(m: androidx.compose.ui.test.SemanticsMatcher) = ui.onAllNodes(m).fetchSemanticsNodes().flatMap { n ->
        n.config.getOrElse(androidx.compose.ui.semantics.SemanticsProperties.Text) { emptyList() }.map { it.text }
    }

    private fun expectCount(label: Int, n: Int) = waitFor("${str(label)} $n (got ${chipCount(label)})") { chipCount(label) == n }

    private fun chip(label: Int) {
        val m = hasText(str(label), substring = true) and isSelectable()
        ui.onAllNodes(m)[visible(m).first()].performClick()
        ui.waitForIdle()
    }

    @Test
    @Covers("SRCH-01", "SRCH-02", "SRCH-06")
    fun rulesAndWhereTheyLive() {
        launch()
        addSet("Work")
        addGlobalRule(RuleSpec(Hosts.B))
        addAppRule(shellName, RuleSpec(Hosts.C, set = "Work"))
        drawer(R.string.nav_search)
        // empty: the hint, chips without numbers
        waitText(str(R.string.search_hint))
        assertTrue(exists(str(R.string.search_rules)))
        search("example")
        expectCount(R.string.search_rules, 2)
        // where each rule lives: whose, which set, which profiles
        val main = str(R.string.profile_default)
        assertText(str(R.string.search_in_set, str(R.string.set_default)), substring = true)
        assertText(str(R.string.search_in_set, "Work"), substring = true)
        assertTrue(textsOf(shellName).any { it.contains(main) })
        // a set that is off: said so
        app.firewall.setEnabled(setId("Work"), false)
        waitText(str(R.string.search_set_off), substring = true)
        // the global rule opens the global list, the app rule its app
        tap(Hosts.B, substring = true)
        waitText(str(R.string.nav_global))
        back()
        tap(Hosts.C, substring = true)
        waitText("$SHELL_PKG · uid $SHELL_UID")
        back()
        // nothing found: in everything, and in one chip
        search("zzqqxx-nothing")
        waitText(str(R.string.nothing_found))
        search("example")
        expectCount(R.string.search_rules, 2)
        chip(R.string.search_lists)
        waitText(str(R.string.nothing_found))
        chip(R.string.search_rules)
        assertNoText(str(R.string.nothing_found))
        // a rule found by part of its target only once
        val ruleRow =
            has(Hosts.B, substring = true) and androidx.compose.ui.test.hasClickAction() and !androidx.compose.ui.test.hasSetTextAction()
        assertEquals(1, count(ruleRow))
    }

    @Test
    @Covers("SRCH-03")
    fun listsByEntryAndParentDomain() {
        launch()
        val res = ListParser.parse(sequenceOf(Hosts.A, "ads.example.net", "tracker.test"))
        val id = app.firewall.importList("Ads", res, Action.BLOCK)
        waitFor("list") { st.blocklists.any { it.id == id } }
        drawer(R.string.nav_search)
        // a short query does not search lists
        search("e")
        waitFor("no lists for one letter") { chipCount(R.string.search_lists) == 0 }
        search("example")
        expectCount(R.string.search_lists, 1)
        assertText(plural(R.plurals.search_entries, 2, 2, "${Hosts.A}, ads.example.net"))
        // a host under a listed domain finds it through the parent
        search("www.${Hosts.A}")
        expectCount(R.string.search_lists, 1)
        assertText(plural(R.plurals.search_entries, 1, 1, Hosts.A))
        // an entry turned off is not found; an added one is
        app.firewall.setEntryDisabled(id, "tracker.test", true)
        app.firewall.addEntries(id, listOf("added.test"))
        search(".test")
        waitFor("only the added entry") { exists(plural(R.plurals.search_entries, 1, 1, "added.test")) }
        // opens the list on that entry
        tap("Ads")
        // only an added entry matched: the list opens on "My edits", where it is
        waitText(str(R.string.list_my_edits, 2))
        waitText("added.test")
        assertNoText(Hosts.A)
        back()
        // a downloaded entry: the entries, narrowed to it
        search("www.${Hosts.A}")
        expectCount(R.string.search_lists, 1)
        tap("Ads")
        waitText(Hosts.A)
        assertNoText("ads.example.net")
    }

    @Test
    @Covers("SRCH-04", "SRCH-05")
    fun appsAndConnections() {
        launch()
        addAppRule(shellName, RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        assertAllowed(Hosts.A)
        assertBlocked(Hosts.B)
        drawer(R.string.nav_search)
        // apps by package and by name, with their rules
        search("com.android.she")
        expectCount(R.string.search_apps, 1)
        assertText("$SHELL_PKG · ${plural(R.plurals.rules_n, 1, 1)}")
        search(shellName.lowercase().take(5))
        waitFor("by name") { (chipCount(R.string.search_apps) ?: 0) >= 1 }
        tap(shellName)
        waitText("$SHELL_PKG · uid $SHELL_UID")
        back()
        // connections: host, app, when, blocked or allowed
        search(Hosts.A)
        waitFor("connections") { (chipCount(R.string.search_conns) ?: 0) >= 1 }
        chip(R.string.search_conns)
        assertTrue(textsOf(shellName).any { it.endsWith(str(R.string.search_allowed)) })
        search(Hosts.B)
        waitFor("blocked one") { textsOf(shellName).any { it.endsWith(str(R.string.search_blocked)) } }
        // by IP and by the app's package
        val ip = Rows.of(host = Hosts.A, port = 80).last().dstIp
        search(ip)
        waitFor("by IP") { (chipCount(R.string.search_conns) ?: 0) >= 1 }
        search(SHELL_PKG)
        val n = Rows.all().count { it.app.packageName == SHELL_PKG }.coerceAtMost(100)
        expectCount(R.string.search_conns, n)
        // a row opens the connection
        search(Hosts.A)
        chip(R.string.search_conns)
        val row = hasText(Hosts.A) and androidx.compose.ui.test.hasClickAction() and !androidx.compose.ui.test.hasSetTextAction()
        ui.waitUntil("row", 5000) { count(row) > 0 }
        ui.onAllNodes(row)[visible(row).first()].performClick()
        waitText(str(R.string.conn_overview))
    }
}
