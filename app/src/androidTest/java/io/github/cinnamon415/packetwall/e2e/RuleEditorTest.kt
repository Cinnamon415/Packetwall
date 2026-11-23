package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.VpnSetup
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.Proto
import io.github.cinnamon415.packetwall.fw.Target
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The system resolver of the VPN, asked directly: (rcode, the A record of the first answer or null). */
fun dnsAnswer(name: String): Pair<Int, String?> {
    val b = Net.dnsUdp(VpnSetup.DNS4, name).map { it.toInt(16) }
    assertTrue("a DNS reply for $name", b.size >= 12)
    val rcode = b[3] and 0x0f
    val answers = (b[6] shl 8) or b[7]
    // a type A answer ends with 4 address bytes; the reply has one question and (at most) this answer
    val ip = if (answers > 0 && b.size >= 16) b.takeLast(4).joinToString(".") else null
    return rcode to ip
}

/** A name that is not blocked: its DNS query is in the log and allowed (the name itself may not exist). */
fun assertNotBlockedName(name: String) {
    settle()
    Net.http(name, timeoutS = 3)
    assertTrue(Net.allowed(Hosts.CONTROL).ok)
    Rows.await("$name asked") { it.host.equals(name, true) }
    val blocked = Rows.all().filter { it.host.equals(name, true) && it.blocked }
    assertTrue("$name should not be blocked: ${blocked.map { "#${it.id} rule=${it.fwRule}" }}", blocked.isEmpty())
}

/** RULE: the rule editor. */
class RuleEditorTest : E2eTest() {

    private val inDialog = hasAnyAncestor(isDialog())

    private fun dialogNode(text: String) = ui.onAllNodes(has(text) and inDialog)[visible(has(text) and inDialog).first()]

    private fun selectedInDialog(text: String) =
        dialogNode(text).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Selected) == true

    private fun checked(label: String): Boolean {
        val m = isToggleable() and androidx.compose.ui.test.hasParent(has(label, substring = true))
        return ui.onAllNodes(m)[visible(m).last()].fetchSemanticsNode().config.getOrNull(SemanticsProperties.ToggleableState) ==
            androidx.compose.ui.state.ToggleableState.On
    }

    private fun saveEnabled(): Boolean {
        val m = has(str(R.string.save)) and hasClickAction() and inDialog
        return ui.onAllNodes(m).fetchSemanticsNodes().first().config.getOrNull(SemanticsProperties.Disabled) == null
    }

    private fun targetField() = ui.onAllNodes(hasSetTextAction() and inDialog)[visible(hasSetTextAction() and inDialog).first()]

    private fun targetError() = targetField().fetchSemanticsNode().config.getOrNull(SemanticsProperties.Error) != null

    private fun setTarget(v: String) {
        targetField().performTextClearance()
        if (v.isNotEmpty()) targetField().performTextInput(v)
        ui.waitForIdle()
    }

    private fun setPort(v: String) {
        val m = hasSetTextAction() and has(str(R.string.port), substring = true) and inDialog
        val n = ui.onAllNodes(m)[visible(m).first()]
        n.performTextClearance()
        if (v.isNotEmpty()) n.performTextInput(v)
        ui.waitForIdle()
    }

    private fun kind(res: Int) = dialogChip(str(res))

    private fun rules() = app.firewall.state.value.rules

    @Test
    @Covers("RULE-01", "RULE-02", "RULE-07", "RULE-10")
    fun newRuleDefaultsSetsAndCancel() {
        launch()
        addSet("Work")
        drawer(R.string.nav_global)
        tap(str(R.string.rule_add))
        waitText(str(R.string.rule_new))
        // block a domain with its subdomains, globally, in the default set
        assertTrue(selectedInDialog(str(R.string.action_block)))
        assertTrue(selectedInDialog(str(R.string.target_domain)))
        assertTrue(checked(str(R.string.prop_subdomains)))
        assertText(str(R.string.rule_for, str(R.string.who_global)))
        assertTrue(count(has(str(R.string.set_default)) and inDialog) > 0)
        // block everything globally: a red warning; a port or a protocol makes it narrow
        kind(R.string.target_all)
        assertText(str(R.string.warn_global_block_all))
        setPort("443")
        assertNoText(str(R.string.warn_global_block_all))
        setPort("")
        assertText(str(R.string.warn_global_block_all))
        dialogNode("TCP").performClick()
        assertNoText(str(R.string.warn_global_block_all))
        // the set list: the user sets
        tap(str(R.string.rule_set))
        assertTrue(count(has("Work") and hasAnyAncestor(isPopup())) > 0)
        assertTrue(count(has(str(R.string.set_default)) and hasAnyAncestor(isPopup())) > 0)
        back()
        // Cancel keeps nothing
        val before = rules()
        tap(str(R.string.cancel))
        waitNoText(str(R.string.rule_new))
        assertEquals(before, rules())
        // a tap outside the dialog keeps nothing either
        tap(str(R.string.rule_add))
        waitText(str(R.string.rule_new))
        setTarget("example.com")
        device.click(4, device.displayHeight / 2)
        waitNoText(str(R.string.rule_new))
        assertEquals(before, rules())
        // a set chip picked on the list: new rules go there
        val chip = has("Work") and isSelectable()
        ui.onAllNodes(chip)[visible(chip).first()].performClick()
        tap(str(R.string.rule_add))
        waitText(str(R.string.rule_new))
        assertTrue("set preset from the chip", count(has("Work") and inDialog) > 0)
        tap(str(R.string.cancel))
        // the app's editor: everything, for the app, and no "whole internet" warning
        openAppRules(shellName)
        tap(str(R.string.rule_add))
        waitText(str(R.string.rule_new))
        assertTrue(selectedInDialog(str(R.string.target_all)))
        assertText(str(R.string.rule_for, shellName))
        assertNoText(str(R.string.warn_global_block_all))
        tap(str(R.string.save))
        val r = waitForValue("app rule") { rules().firstOrNull { it.who == Who.App(SHELL_PKG) } }
        assertEquals(Target(TargetKind.ALL), r.target.copy(subdomains = false))
        assertEquals(Action.BLOCK, r.action)
        assertEquals(FwState.DEFAULT_SET, r.setId)
    }

    @Test
    @Covers("RULE-03")
    fun validation() {
        launch()
        drawer(R.string.nav_global)
        tap(str(R.string.rule_add))
        waitText(str(R.string.rule_new))
        // empty: nothing to save, but no red field yet
        assertFalse(saveEnabled())
        assertFalse(targetError())
        val cases = listOf(
            Triple(R.string.target_domain, "example.com", true),
            Triple(R.string.target_domain, "*.example.com", true),
            Triple(R.string.target_domain, "**.example.com", true),
            Triple(R.string.target_domain, "exa mple.com", false),
            Triple(R.string.target_domain, "example..com", false),
            Triple(R.string.target_domain, "-bad.com", false),
            Triple(R.string.target_ip, "203.0.113.7", true),
            Triple(R.string.target_ip, "10.0.0.0/8", true),
            Triple(R.string.target_ip, "2001:db8::/32", true),
            Triple(R.string.target_ip, "300.1.1.1", false),
            Triple(R.string.target_ip, "10.0.0.0/33", false),
            Triple(R.string.target_ip, "example.com", false),
            Triple(R.string.kind_asn, "AS13335", true),
            Triple(R.string.kind_asn, "13335", true),
            Triple(R.string.kind_asn, "ASX", false),
            Triple(R.string.target_country, "US", true),
            Triple(R.string.target_country, "de", true),
            Triple(R.string.target_country, "USA", false),
            Triple(R.string.target_country, "1A", false)
        )
        val wrong = ArrayList<String>()
        for ((k, v, ok) in cases) {
            kind(k)
            setTarget(v)
            if (saveEnabled() != ok ||
                targetError() == ok
            ) {
                wrong += "${str(k)} \"$v\": save=${saveEnabled()} error=${targetError()} expected valid=$ok"
            }
        }
        assertTrue("validation:\n" + wrong.joinToString("\n"), wrong.isEmpty())
        // the port: empty or 1…65535
        kind(R.string.target_domain)
        setTarget("example.com")
        for ((p, ok) in listOf("" to true, "1" to true, "65535" to true, "0" to false, "65536" to false, "99999" to false)) {
            setPort(p)
            assertEquals("port \"$p\"", ok, saveEnabled())
        }
        // letters are not taken
        setPort("8a0")
        assertTrue(exists("80"))
    }

    @Test
    @Covers("RULE-04", "RULE-05", "RULE-08")
    fun protocolPortAndReject() {
        launch()
        val r = addGlobalRule(RuleSpec(Hosts.CF_IP, kind = TargetKind.IP, proto = "TCP", port = 80))
        assertEquals(Proto.TCP, r.proto)
        assertEquals(80, r.port)
        assertFalse(r.reject)
        drawer(R.string.nav_home)
        turnOn()
        // TCP/80 dropped: the request hangs until its timeout
        val t = Net.http("one.one.one.one", ip = Hosts.CF_IP, timeoutS = 5)
        assertFalse(t.ok)
        assertTrue("a dropped connection times out (${t.ms} ms, \"${t.line}\")\n${Rows.dump()}", t.ms >= 4000)
        Rows.await("blocked by the rule") { it.dstIp == Hosts.CF_IP && it.dstPort == 80 && it.blocked && it.fwRule == r.id }
        // TCP/443 of the same address is not touched
        assertTrue("TLS to ${Hosts.CF_IP}:443 passes", Tls.hello(Hosts.CF_IP, "www.cloudflare.com") > 500)
        // reject: refused at once, applied without restarting the protection
        drawer(R.string.nav_global)
        tap(Hosts.CF_IP)
        waitText(str(R.string.rule_edit))
        setCheck(str(R.string.reject_label), true)
        tap(str(R.string.save))
        waitFor("reject saved") { app.firewall.state.value.rule(r.id)?.reject == true }
        assertBlocked("one.one.one.one", ip = Hosts.CF_IP, rule = r.id, fast = true)
        // DNS: a dropped name is answered 0.0.0.0, a rejected one NXDOMAIN
        addGlobalRule(RuleSpec(Hosts.B))
        addGlobalRule(RuleSpec(Hosts.C, reject = true))
        settle()
        assertEquals(0 to "0.0.0.0", dnsAnswer(Hosts.B))
        assertEquals(3, dnsAnswer(Hosts.C).first)
        // a name without rules gets a real answer
        val free = dnsAnswer(Hosts.A)
        assertEquals(0, free.first)
        assertTrue("real address for ${Hosts.A}: $free", free.second != null && free.second != "0.0.0.0")
    }

    @Test
    @Covers("RULE-08", "RULE-09")
    fun editAndDeleteWithUndo() {
        launch()
        val r = addGlobalRule(RuleSpec(Hosts.B))
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked(Hosts.B, rule = r.id)
        drawer(R.string.nav_global)
        tap(Hosts.B)
        waitText(str(R.string.rule_edit))
        // the editor shows the rule
        assertTrue(selectedInDialog(str(R.string.action_block)))
        assertTrue(count(has(Hosts.B) and inDialog) > 0)
        assertTrue(checked(str(R.string.prop_subdomains)))
        setTarget(Hosts.C)
        tap(str(R.string.save))
        waitNoText(str(R.string.rule_edit))
        // changed in place, not added
        waitFor("edited") { app.firewall.state.value.rule(r.id)?.target?.value == Hosts.C }
        assertEquals(1, rules().size)
        // at once: example.net blocked, example.com free (a subdomain: example.com itself is cached as blocked)
        assertBlocked(Hosts.C, rule = r.id)
        assertAllowed("www.${Hosts.B}")
        // delete, then undo: the same rule comes back
        val edited = app.firewall.state.value.rule(r.id)!!
        tap(Hosts.C)
        waitText(str(R.string.rule_edit))
        tap(str(R.string.delete))
        waitNoText(str(R.string.rule_edit))
        waitFor("deleted") { rules().isEmpty() }
        assertText(str(R.string.no_rules_global))
        waitText(str(R.string.undo_rule_deleted))
        tap(str(R.string.undo))
        waitFor("restored") { app.firewall.state.value.rule(r.id) == edited }
        waitText(Hosts.C)
    }

    @Test
    @Covers("RULE-11")
    fun inactiveRulesAreMarked() {
        launch()
        val off = addSet("Off")
        addGlobalRule(RuleSpec(Hosts.B, set = "Off"))
        drawer(R.string.nav_sets)
        setSwitch("Off", false)
        waitFor("set off") { !app.firewall.state.value.isEnabled(off) }
        addGlobalRule(RuleSpec("US", kind = TargetKind.COUNTRY))
        addGlobalRule(RuleSpec("AS13335", kind = TargetKind.ASN))
        addGlobalRule(RuleSpec(Hosts.C))
        drawer(R.string.nav_global)
        assertText(str(R.string.rule_set_off), substring = true)
        assertText(str(R.string.rule_no_geo), substring = true)
        assertText(str(R.string.rule_no_asn), substring = true)
        // the plain rule has no mark: three marks for four rules
        val marks = listOf(R.string.rule_set_off, R.string.rule_no_geo, R.string.rule_no_asn).sumOf {
            count(has(str(it), substring = true))
        }
        assertEquals(3, marks)
    }

    @Test
    @Covers("RULE-12")
    fun masksAndExactNames() {
        launch()
        val one = addGlobalRule(RuleSpec("*.example.com", subdomains = false))
        val deep = addGlobalRule(RuleSpec("**.example.org", subdomains = false))
        val exact = addGlobalRule(RuleSpec(Hosts.C, subdomains = false))
        drawer(R.string.nav_home)
        turnOn()
        // * is one label
        assertBlocked("www.example.com", rule = one.id, fast = true)
        assertAllowed(Hosts.B)
        assertNotBlockedName("a.b.example.com")
        // ** is any depth
        assertBlocked("www.example.org", rule = deep.id, fast = true)
        assertBlocked("a.b.example.org", rule = deep.id, fast = true)
        // an exact name leaves its subdomains alone
        assertBlocked(Hosts.C, rule = exact.id, fast = true)
        assertAllowed("www.${Hosts.C}")
    }
}
