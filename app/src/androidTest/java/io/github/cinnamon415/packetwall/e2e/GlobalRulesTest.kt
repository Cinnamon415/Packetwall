package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.performClick
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.TargetKind
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** GLOB: the global rules list; SEL: selecting rules (global, app, group). */
class GlobalRulesTest : E2eTest() {

    private val st get() = app.firewall.state.value

    private fun chip(label: String) {
        val m = hasText(label) and isSelectable()
        ui.waitUntil("chip $label", 5000) { ui.onAllNodes(m).fetchSemanticsNodes().isNotEmpty() }
        val n = ui.onAllNodes(m).fetchSemanticsNodes().indices.first()
        ui.onAllNodes(m)[n].performScrollToCompat()
        ui.onAllNodes(m)[n].performClick()
        ui.waitForIdle()
    }

    /** Rule titles on screen, top to bottom, among [titles]. */
    private fun order(titles: List<String>): List<String> = titles.mapNotNull { t ->
        val m = has(t)
        visible(m).firstOrNull()?.let { t to ui.onAllNodes(m).fetchSemanticsNodes()[it].boundsInWindow.top }
    }.sortedBy { it.second }.map { it.first }

    /** The number in the top bar: shown rules. */
    private fun shown(): Int = waitForValue("subtitle") {
        val m = androidx.compose.ui.test.SemanticsMatcher("a number") { n ->
            n.config.getOrElse(SemanticsProperties.Text) { emptyList() }.any { Regex("^\\d+$").matches(it.text) }
        }
        val nodes = ui.onAllNodes(m).fetchSemanticsNodes()
        visible(m).map { nodes[it] }.minByOrNull { it.boundsInWindow.top }?.config?.get(SemanticsProperties.Text)?.first()?.text?.toInt()
    }

    private fun expectShown(what: String, n: Int) = waitFor("$what: $n shown (got ${runCatching { shown() }.getOrNull()})") { shown() == n }

    @Test
    @Covers("GLOB-01", "GLOB-02", "GLOB-03", "GLOB-04")
    fun filtersSortAndProfileButton() {
        launch()
        drawer(R.string.nav_global)
        waitText(str(R.string.no_rules_global))
        addSet("Work")
        addGlobalRule(RuleSpec(Hosts.B))
        addGlobalRule(RuleSpec(Hosts.C, set = "Work"))
        addGlobalRule(RuleSpec("203.0.113.0/24", kind = TargetKind.IP))
        addGlobalRule(RuleSpec("AS13335", kind = TargetKind.ASN))
        addGlobalRule(RuleSpec("US", kind = TargetKind.COUNTRY))
        addGlobalRule(RuleSpec(kind = TargetKind.ALL, port = 443))
        // an app rule is not listed here
        addAppRule(shellName, RuleSpec(Hosts.A))
        drawer(R.string.nav_global)
        expectShown("all global", 6)
        // search by target
        type("example")
        expectShown("search", 2)
        type("")
        expectShown("cleared", 6)
        // set chip
        chip("Work")
        expectShown("set Work", 1)
        assertText(Hosts.C)
        // single choice: "All sets" goes back
        chip(str(R.string.all_sets))
        expectShown("all sets", 6)
        // kind chips, one at a time; a second tap clears
        for ((label, n) in listOf(
            R.string.kind_hosts to 2,
            R.string.kind_ip to 1,
            R.string.kind_asn to 1,
            R.string.kind_countries to 1,
            R.string.kind_all_traffic to 1
        )) {
            chip(str(label))
            expectShown(str(label), n)
            chip(str(label))
            expectShown("${str(label)} off", 6)
        }
        chip(str(R.string.kind_ports))
        expectShown("ports", 1)
        chip(str(R.string.kind_ports))
        // sort: by name, newest first
        val titles = listOf(Hosts.B, Hosts.C, "203.0.113.0/24")
        tapDesc(str(R.string.more))
        tap(str(R.string.sort_new))
        waitFor("newest first: ${order(titles)}") { order(titles) == listOf("203.0.113.0/24", Hosts.C, Hosts.B) }
        tapDesc(str(R.string.more))
        assertTrue("✓ at the chosen sort", count(hasText("✓") and hasAnyAncestor(isPopup())) == 1)
        tap(str(R.string.sort_name))
        // by name within each kind: domains, then addresses
        waitFor("by name: ${order(titles)}") { order(titles) == listOf(Hosts.B, Hosts.C, "203.0.113.0/24") }
        // the profile button opens the profile menu
        tap("${str(R.string.profile_default)} ▾")
        assertTrue(count(hasText(str(R.string.nav_sets)) and hasAnyAncestor(isPopup())) > 0)
        back()
    }

    @Test
    @Covers("SEL-01", "SEL-02", "SEL-03", "SEL-04")
    fun selectMoveExportDelete() {
        launch()
        addSet("Work")
        val b = addGlobalRule(RuleSpec(Hosts.B))
        val c = addGlobalRule(RuleSpec(Hosts.C))
        addGlobalRule(RuleSpec(Hosts.A))
        drawer(R.string.nav_global)
        // long press selects; taps add and remove; Back clears
        longTap(Hosts.B)
        waitText(str(R.string.selected_n, 1))
        tap(Hosts.C)
        waitText(str(R.string.selected_n, 2))
        tap(Hosts.B)
        waitText(str(R.string.selected_n, 1))
        back()
        waitText(str(R.string.nav_global))
        assertNoText(str(R.string.selected_n, 1))
        // two selected → move to Work
        longTap(Hosts.B)
        tap(Hosts.C)
        waitText(str(R.string.selected_n, 2))
        tap(str(R.string.move_to_set))
        tap("Work")
        waitFor("moved") { st.rule(b.id)!!.setId == setId("Work") && st.rule(c.id)!!.setId == setId("Work") }
        waitText(str(R.string.nav_global))
        // the rows name their new set
        waitFor("rows show Work") { count(has("· Work", substring = true)) == 2 }
        // export: only the selected rules, importable
        longTap(Hosts.B)
        tap(Hosts.C)
        waitText(str(R.string.selected_n, 2))
        val name = "e2e-sel.json"
        Docs.remove("${Docs.DIR}/$name")
        expectToast(str(R.string.exported)) {
            tapDesc(str(R.string.export))
            Docs.save(name)
        }
        val rules = JSONObject(Docs.readText("${Docs.DIR}/$name")).getJSONObject("state").getJSONArray("rules")
        assertEquals(2, rules.length())
        val values = (0 until 2).map { rules.getJSONObject(it).getJSONObject("target").getString("value") }.toSet()
        assertEquals(setOf(Hosts.B, Hosts.C), values)
        // after an export the selection is done
        waitText(str(R.string.nav_global))
        drawer(R.string.nav_sets)
        tapDesc(str(R.string.more))
        tap(str(R.string.import_json))
        Docs.open(name)
        tap(str(R.string.import_action))
        waitText(str(R.string.import_json_done, 1, 2, 0, 0))
        tap(str(R.string.ok))
        assertEquals(5, st.rules.size)
        // delete two; undo returns them
        drawer(R.string.nav_global)
        val before = st.rules
        longTap(Hosts.A)
        waitText(str(R.string.selected_n, 1))
        val firstB = order(listOf(Hosts.B)).first()
        tap(firstB)
        waitText(str(R.string.selected_n, 2))
        tapDesc(str(R.string.delete))
        waitFor("deleted") { st.rules.size == 3 }
        waitText(str(R.string.undo_rules_deleted, 2))
        tap(str(R.string.undo))
        waitFor("back") { st.rules == before }
    }

    @Test
    @Covers("SEL-01", "SEL-04")
    fun selectingOnAnAppScreen() {
        launch()
        addAppRule(shellName, RuleSpec(Hosts.B))
        addAppRule(shellName, RuleSpec(Hosts.C))
        openAppRules(shellName)
        longTap(Hosts.B)
        waitText(str(R.string.selected_n, 1))
        tap(Hosts.C)
        waitText(str(R.string.selected_n, 2))
        tapDesc(str(R.string.delete))
        waitFor("deleted") { st.rules.isEmpty() }
        waitText(str(R.string.no_rules_app))
        tap(str(R.string.undo))
        waitFor("back") { st.rules.size == 2 }
    }
}
