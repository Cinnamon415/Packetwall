package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.performClick
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.Target
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** APPS: apps and groups. */
class AppsTest : E2eTest() {

    private val st get() = app.firewall.state.value

    /** App rows from top to bottom: an app row shows its package name as a line of its own (or "pkg · traffic"). */
    private fun appRows(): List<String> {
        val pkgs = app.apps.installed().map { it.packageName }.toSet()
        val m = hasClickAction()
        val nodes = ui.onAllNodes(m).fetchSemanticsNodes()
        return visible(m).map { nodes[it] }.sortedBy { it.boundsInWindow.top }.mapNotNull { n ->
            val texts = n.config.getOrElse(SemanticsProperties.Text) { emptyList() }.map { it.text }
            texts.firstNotNullOfOrNull { t -> t.substringBefore(" · ").takeIf { it in pkgs } }
        }
    }

    /** The subtitle under the title: the topmost text that is only a number (rule badges come lower). */
    private fun shownCount(): Int = waitForValue("apps subtitle") {
        val m = androidx.compose.ui.test.SemanticsMatcher("a number") { n ->
            n.config.getOrNull(SemanticsProperties.Text)?.any { Regex("^\\d+$").matches(it.text) } == true
        }
        val nodes = ui.onAllNodes(m).fetchSemanticsNodes()
        visible(m).map { nodes[it] }.minByOrNull { it.boundsInWindow.top }?.config?.get(SemanticsProperties.Text)?.first()?.text?.toInt()
    }

    private fun menu(item: Int) {
        tapDesc(str(R.string.more))
        tap(str(item))
    }

    @Test
    @Covers("APPS-01", "APPS-02", "APPS-03")
    fun listSearchFiltersAndSort() {
        launch()
        drawer(R.string.nav_apps)
        waitText(str(R.string.groups))
        val user = app.apps.installed().filter { !it.isSystem }
        val all = app.apps.installed()
        // user apps only at first: the subtitle counts them
        waitFor("count of user apps") { shownCount() == user.size }
        assertNoText(shellName)
        // system apps: the shell shows up
        menu(R.string.show_system)
        back()
        waitFor("count of all apps") { shownCount() == all.size }
        type("com.android.she")
        waitText(shellName)
        // search by name too
        type(shellName)
        waitText(SHELL_PKG, substring = true)
        type("")
        // by name: alphabetical
        menu(R.string.sort_name)
        val byName = all.sortedBy { it.name.lowercase() }.take(3).map { it.packageName }
        waitFor("sorted by name: ${appRows().take(3)} vs $byName") { appRows().take(3) == byName }
        // only with rules; by rules: the shell with its two rules first
        addAppRule(shellName, RuleSpec(Hosts.B))
        addAppRule(shellName, RuleSpec(Hosts.C))
        drawer(R.string.nav_apps)
        menu(R.string.sort_rules)
        waitFor("shell first by rules: ${appRows().take(3)}") { appRows().firstOrNull() == SHELL_PKG }
        assertTrue(exists("2"))
        menu(R.string.only_with_rules)
        back()
        waitFor("only the shell: ${appRows()}") { appRows() == listOf(SHELL_PKG) }
        assertEquals(1, shownCount())
        menu(R.string.only_with_rules)
        back()
        // by traffic: the shell made the only traffic
        drawer(R.string.nav_home)
        turnOn()
        assertAllowed(Hosts.A)
        drawer(R.string.nav_apps)
        menu(R.string.sort_traffic)
        waitFor("shell first by traffic: ${appRows().take(3)}") { appRows().firstOrNull() == SHELL_PKG }
    }

    @Test
    @Covers("APPS-04", "APPS-05")
    fun appRulesScreenAndHistory() {
        launch()
        drawer(R.string.nav_home)
        turnOn()
        repeat(2) { assertAllowed(Hosts.A) }
        openAppRules(shellName)
        assertText(shellName)
        assertText("$SHELL_PKG · uid $SHELL_UID")
        assertText(str(R.string.no_rules_app))
        val n = Rows.all().count { it.app.packageName == SHELL_PKG }
        tap(str(R.string.app_history, n))
        // the log, filtered to the app
        waitText(str(R.string.chip_all))
        assertText("pkg == \"$SHELL_PKG\"")
        waitText("$n / ${Rows.all().size}")
        back()
        // Add rule: the editor for this app
        tap(str(R.string.rule_add))
        waitText(str(R.string.rule_new))
        assertText(str(R.string.rule_for, shellName))
        tap(str(R.string.cancel))
        // in a group: its chip leads there
        drawer(R.string.nav_apps)
        type("")
        tap(str(R.string.group_new))
        type("Tools")
        tap(str(R.string.ok))
        addMembers("Tools", shellName)
        openAppRules(shellName)
        assertText(str(R.string.app_in_groups))
        tap("Tools")
        waitText(str(R.string.group_add_apps))
    }

    /** On the group screen: Add apps → the picker → [names] (system apps on) → Add N. */
    private fun addMembers(group: String, vararg names: String) {
        waitText(str(R.string.group_add_apps))
        tap(str(R.string.group_add_apps))
        waitText(str(R.string.group_add_to, group))
        assertText(str(R.string.selected_n, 0))
        val chip = hasText(str(R.string.system_apps)) and isSelectable() and hasAnyAncestor(isDialog())
        ui.onAllNodes(chip)[visible(chip).first()].performClick()
        names.forEachIndexed { i, n ->
            type(n)
            tap(n)
            waitText(str(R.string.selected_n, i + 1))
        }
        tap(str(R.string.group_add_n, names.size))
        waitNoText(str(R.string.group_add_to, group))
    }

    @Test
    @Covers("APPS-06")
    fun uninstalledAppKeepsItsRules() {
        launch()
        // rules of an app that is gone come from an import or an uninstall: set up directly
        val gone = "com.example.gone"
        app.firewall.saveRule(Rule(0, FwState.DEFAULT_SET, Who.App(gone), Target(TargetKind.DOMAIN, Hosts.B, true), Action.BLOCK))
        val r = waitForValue("rule") { st.rules.firstOrNull { it.who == Who.App(gone) } }
        drawer(R.string.nav_apps)
        type(gone)
        // listed although it is gone, marked so
        tap(str(R.string.app_not_installed_short, gone))
        waitText(str(R.string.app_not_installed))
        assertText(Hosts.B)
        // still editable
        tap(Hosts.B)
        waitText(str(R.string.rule_edit))
        setCheck(str(R.string.prop_subdomains), false)
        tap(str(R.string.save))
        waitFor("edited") { st.rule(r.id)?.target?.subdomains == false }
    }

    @Test
    @Covers("APPS-07", "APPS-08", "APPS-09", "APPS-10", "DEC-05")
    fun groups() {
        launch()
        drawer(R.string.nav_apps)
        tap(str(R.string.group_new))
        // no name: OK is off
        val ok = hasText(str(R.string.ok)) and hasClickAction() and hasAnyAncestor(isDialog())
        assertTrue(ui.onAllNodes(ok).fetchSemanticsNodes().first().config.getOrNull(SemanticsProperties.Disabled) != null)
        type("Tools")
        tap(str(R.string.ok))
        // the new group opens on its members
        waitText(str(R.string.group_tab_members, 0))
        assertText(str(R.string.group_empty))
        val g = waitForValue("group") { st.groups.firstOrNull { it.name == "Tools" } }
        addMembers("Tools", shellName)
        waitText(str(R.string.group_tab_members, 1))
        assertEquals(listOf(SHELL_PKG), st.group(g.id)!!.packages)
        // ✕ removes, the snackbar puts back
        tapDesc(str(R.string.group_remove_member, shellName))
        waitFor("removed") { st.group(g.id)!!.packages.isEmpty() }
        waitText(str(R.string.undo_member_removed, shellName))
        tap(str(R.string.undo))
        waitFor("back") { st.group(g.id)!!.packages == listOf(SHELL_PKG) }
        // a group rule applies to its members
        tap(str(R.string.group_tab_rules, 0))
        assertText(str(R.string.no_rules_group))
        tap(str(R.string.rule_add))
        fillRuleEditor(RuleSpec(Hosts.B, kind = TargetKind.DOMAIN))
        waitText(str(R.string.group_tab_rules, 1))
        val rule = st.rules.first { it.who == Who.Group(g.id) }
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked(Hosts.B, rule = rule.id)
        // rename: everywhere
        drawer(R.string.nav_apps)
        tap("Tools")
        tapDesc(str(R.string.rename))
        type("Kit")
        tap(str(R.string.ok))
        waitText("Kit")
        back()
        waitText("Kit")
        assertNoText("Tools")
        assertText(plural(R.plurals.apps_n, 1, 1))
        // delete with its rules; undo brings both back
        tap("Kit")
        tapDesc(str(R.string.more))
        tap(str(R.string.group_delete))
        waitFor("deleted") { st.group(g.id) == null && st.rules.none { it.id == rule.id } }
        waitText(str(R.string.undo_group_deleted, "Kit"))
        tap(str(R.string.undo))
        waitFor("restored") { st.group(g.id) != null && st.rule(rule.id) != null }
        assertFalse(st.group(g.id)!!.packages.isEmpty())
    }
}
