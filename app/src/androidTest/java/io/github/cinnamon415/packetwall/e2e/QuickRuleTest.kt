package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.test.performClick
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.Target
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** QR: the quick rule sheet (long press on a log row, "Add rule" on the connection screen). */
class QuickRuleTest : E2eTest() {

    private val inSheet = hasAnyAncestor(isDialog() or isPopup())

    /** The sheet's node with [text]: the first one from the top, or the last ([last]: the big button under the options). */
    private fun sheetNode(text: String, last: Boolean = false, substring: Boolean = false): Int {
        val m = has(text, substring) and inSheet
        ui.waitUntil("\"$text\" in the sheet", 5000) { count(m) > 0 }
        val nodes = ui.onAllNodes(m).fetchSemanticsNodes()
        val idx = visible(m).sortedBy { nodes[it].boundsInWindow.top }
        return if (last) idx.last() else idx.first()
    }

    private fun sheetTap(text: String, last: Boolean = false) {
        ui.onAllNodes(has(text) and inSheet)[sheetNode(text, last)].performClick()
        ui.waitForIdle()
    }

    private fun selected(text: String): Boolean {
        val n = ui.onAllNodes(has(text) and inSheet).fetchSemanticsNodes()[sheetNode(text)]
        return n.config.getOrNull(SemanticsProperties.Selected) == true
    }

    private fun inSheetNow(text: String, substring: Boolean = false) = count(has(text, substring) and inSheet) > 0

    /** Opens the sheet with a long press on the log row titled [title] (the log narrowed by [filter]). */
    private fun sheetFor(title: String, filter: String) {
        openLogs()
        type(filter)
        waitText(title)
        longTap(title)
        waitText(str(R.string.for_app))
    }

    private fun newRule(before: Set<Int>) = waitForValue("the new rule") { app.firewall.state.value.rules.firstOrNull { it.id !in before } }

    private fun ids() = app.firewall.state.value.rules.map { it.id }.toSet()

    @Test
    @Covers("QR-01", "QR-02", "QR-03", "QR-04")
    fun blockFromAnAllowedConnection() {
        launch()
        turnOn()
        val c = assertAllowed(Hosts.A_WWW)
        sheetFor(Hosts.A_WWW, "host == ${Hosts.A_WWW} && port == 80")
        // the app and "protocol · host"
        assertTrue(inSheetNow(shellName))
        assertTrue(inSheetNow("HTTP · ${Hosts.A_WWW}"))
        // the choices: Block for this app is preselected
        assertTrue("Block preselected", selected(str(R.string.action_block)))
        assertTrue("For this app preselected", selected(str(R.string.for_app)))
        // the targets: exact host, base domain with subdomains, the IP, its /24, all traffic of the app
        val subnet = c.dstIp.substringBeforeLast('.') + ".0/24"
        for (t in listOf(Hosts.A_WWW, Hosts.A, c.dstIp, subnet, str(R.string.target_all_traffic))) assertTrue("option $t", inSheetNow(t))
        assertTrue(inSheetNow(str(R.string.exact_host)))
        assertTrue(inSheetNow(str(R.string.prop_subdomains)))
        assertTrue(inSheetNow(str(R.string.target_subnet)))
        // globally: no "all traffic of the app"; back for the app: it returns
        sheetTap(str(R.string.who_global))
        assertTrue(!inSheetNow(str(R.string.target_all_traffic)))
        sheetTap(str(R.string.for_app))
        assertTrue(inSheetNow(str(R.string.target_all_traffic)))
        back()
        waitNoText(str(R.string.for_app))
        // the defaults as they are: block example.org with subdomains for the shell, in the default set
        longTap(Hosts.A_WWW)
        waitText(str(R.string.for_app))
        var before = ids()
        expectToast(str(R.string.rule_added)) { sheetTap(str(R.string.action_block), last = true) }
        val r = newRule(before)
        assertEquals(Who.App(SHELL_PKG), r.who)
        assertEquals(Target(TargetKind.DOMAIN, Hosts.A, true), r.target)
        assertEquals(Action.BLOCK, r.action)
        assertEquals(FwState.DEFAULT_SET, r.setId)
        // "all traffic", then globally: the choice falls back to the domain
        longTap(Hosts.A_WWW)
        waitText(str(R.string.for_app))
        sheetTap(str(R.string.target_all_traffic))
        sheetTap(str(R.string.who_global))
        before = ids()
        expectToast(str(R.string.rule_added)) { sheetTap(str(R.string.action_block), last = true) }
        val g = newRule(before)
        assertEquals(Who.Global, g.who)
        assertEquals(Target(TargetKind.DOMAIN, Hosts.A, true), g.target)
        // the rule works: example.org (never asked before) is blocked by the app rule, the control passes
        assertBlocked(Hosts.A, rule = r.id)
        // and it is in the app's rules
        drawer(R.string.nav_home)
        openAppRules(shellName)
        assertText(Hosts.A)
        // any other choice survives switching "for this app" / "globally" back and forth
        // (last: a block of the fake-IP /24 would cut the control host off too)
        sheetFor(Hosts.A_WWW, "host == ${Hosts.A_WWW} && port == 80")
        sheetTap(subnet)
        sheetTap(str(R.string.who_global))
        sheetTap(str(R.string.for_app))
        before = ids()
        expectToast(str(R.string.rule_added)) { sheetTap(str(R.string.action_block), last = true) }
        assertEquals(Target(TargetKind.IP, subnet), newRule(before).target)
    }

    @Test
    @Covers("QR-05")
    fun deleteTheBlockingRuleAndUndo() {
        launch()
        val r = addGlobalRule(RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked(Hosts.B, rule = r.id)
        sheetFor(Hosts.B, "host == ${Hosts.B}")
        val why = str(R.string.blocked_by_rule, Hosts.B, str(R.string.who_global)) + " · " + str(R.string.set_default)
        assertTrue("why: $why", inSheetNow(why))
        sheetTap(str(R.string.delete_blocking_rule))
        waitNoText(str(R.string.for_app))
        waitFor("rule deleted") { app.firewall.state.value.rule(r.id) == null }
        // the snackbar brings it back
        waitText(str(R.string.undo_rule_deleted))
        tap(str(R.string.undo))
        waitFor("rule restored") { app.firewall.state.value.rule(r.id) != null }
        assertEquals(r, app.firewall.state.value.rule(r.id))
        // delete for good: the site opens (a name the system has not cached as blocked)
        longTap(Hosts.B)
        waitText(str(R.string.for_app))
        sheetTap(str(R.string.delete_blocking_rule))
        waitFor("rule deleted") { app.firewall.state.value.rule(r.id) == null }
        assertAllowed("www.${Hosts.B}")
    }

    @Test
    @Covers("QR-06", "QR-07")
    fun allowDefaultsAndWarnings() {
        launch()
        addSet("Low")
        addSet("Lower")
        val block = addAppRule(shellName, RuleSpec(Hosts.B, set = "Low"))
        val low = app.firewall.state.value.sets.first { it.name == "Low" }.id
        assertEquals(low, block.setId)
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked(Hosts.B, rule = block.id)
        sheetFor(Hosts.B, "host == ${Hosts.B}")
        // unblocking: Allow, the blocking rule's set and target are preselected
        assertTrue("Allow preselected", selected(str(R.string.action_allow)))
        assertTrue("the set of the blocking rule", inSheetNow("Low"))
        val broader = str(R.string.exception_broader, Hosts.B)
        val globalVsApp = str(R.string.exception_global_vs_app)
        val lower = str(R.string.exception_lower_set, "Low")
        // the same target in the same set: the block wins the tie
        assertTrue("warning: $broader", inSheetNow(broader))
        // a global allow does not lift an app rule
        sheetTap(str(R.string.who_global))
        assertTrue("warning: $globalVsApp", inSheetNow(globalVsApp))
        sheetTap(str(R.string.for_app))
        // a lower set does not apply
        pickSet("Lower")
        assertTrue("warning: $lower", inSheetNow(lower))
        // a higher set wins: no warning
        pickSet(str(R.string.set_default))
        for (w in listOf(broader, globalVsApp, lower)) assertTrue("no warning $w", !inSheetNow(w))
        // but a global allow, even in the higher set, does not lift the app's block
        sheetTap(str(R.string.who_global))
        assertTrue("warning in a higher set too: $globalVsApp", inSheetNow(globalVsApp))
        sheetTap(str(R.string.for_app))
        val before = ids()
        expectToast(str(R.string.rule_added)) { sheetTap(str(R.string.action_allow), last = true) }
        val allow = newRule(before)
        assertEquals(
            Rule(allow.id, FwState.DEFAULT_SET, Who.App(SHELL_PKG), Target(TargetKind.DOMAIN, Hosts.B, true), Action.ALLOW),
            allow.copy(created = 0)
        )
        // as promised: it passes now (a subdomain: example.com itself is cached as blocked for 10 s)
        assertAllowed("www.${Hosts.B}", rule = allow.id)
    }

    @Test
    @Covers("QR-07")
    fun theWarningTellsTheTruth() {
        launch()
        val block = addAppRule(shellName, RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        val t0 = System.currentTimeMillis()
        assertBlocked(Hosts.B, rule = block.id)
        sheetFor(Hosts.B, "host == ${Hosts.B}")
        // warned (same target, same set): saved anyway, it still blocks
        assertTrue(inSheetNow(str(R.string.exception_broader, Hosts.B)))
        var before = ids()
        expectToast(str(R.string.rule_added)) { sheetTap(str(R.string.action_allow), last = true) }
        newRule(before)
        assertBlocked("www.${Hosts.B}", rule = block.id)
        // the exact host is narrower than the block: no warning, and it passes
        longTap(Hosts.B)
        waitText(str(R.string.for_app))
        sheetTap(str(R.string.exact_host))
        for (w in listOf(str(R.string.exception_broader, Hosts.B), str(R.string.exception_global_vs_app))) assertTrue(!inSheetNow(w))
        before = ids()
        expectToast(str(R.string.rule_added)) { sheetTap(str(R.string.action_allow), last = true) }
        val exact = newRule(before)
        assertEquals(Target(TargetKind.DOMAIN, Hosts.B, false), exact.target)
        // example.com was answered 0.0.0.0 with a 10 s TTL: wait it out
        Thread.sleep((11_000 - (System.currentTimeMillis() - t0)).coerceAtLeast(0))
        assertAllowed(Hosts.B, rule = exact.id)
    }

    @Test
    @Covers("QR-08")
    fun noAppForAConnectionWithoutUid() {
        launch()
        turnOn()
        Net.ping(Hosts.CF_IP)
        // the kernel answers ICMP for no app: the row has no uid
        val row = Rows.await("ping row", 8000) { it.dstIp == Hosts.CF_IP && it.ipproto == 1 }
        assertTrue("ICMP has no uid: ${row.uid}", row.uid < 0)
        openLogs()
        type("ip == ${Hosts.CF_IP}")
        waitText(Hosts.CF_IP)
        longTap(Hosts.CF_IP)
        waitText(str(R.string.who_global))
        // "For this app" is off, "Globally" chosen
        val forApp = ui.onAllNodes(has(str(R.string.for_app)) and inSheet).fetchSemanticsNodes().first()
        assertTrue("for this app disabled", forApp.config.getOrNull(SemanticsProperties.Disabled) != null)
        assertTrue("globally selected", selected(str(R.string.who_global)))
    }
}
