package io.github.cinnamon415.packetwall.e2e

import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.TargetKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DEC: the decision order, set up through the screens and proven by traffic and the reason in the log.
 * A name blocked once stays answered 0.0.0.0 in the system DNS cache for 10 s: each check uses a name not asked
 * before in the test (or waits).
 */
class DecisionTest : E2eTest() {

    private val allow = Action.ALLOW

    private fun on() {
        drawer(R.string.nav_home)
        turnOn()
    }

    @Test
    @Covers("DEC-01")
    fun noRulesAllowEverything() {
        launch()
        on()
        for (h in listOf(Hosts.A, Hosts.B, Hosts.C)) assertAllowed(h)
        assertTrue("ping passes", Net.ping(Hosts.CF_IP) > 0)
        assertTrue(Tls.hello(Hosts.CF_IP, "www.cloudflare.com") > 500)
        assertEquals("nothing blocked", emptyList<Int>(), Rows.all().filter { it.blocked && it.app.packageName == SHELL_PKG }.map { it.id })
    }

    @Test
    @Covers("DEC-02")
    fun domainWithSubdomains() {
        launch()
        val r = addGlobalRule(RuleSpec(Hosts.B))
        on()
        assertBlocked(Hosts.B, rule = r.id, fast = true)
        assertBlocked("www.${Hosts.B}", rule = r.id, fast = true)
        assertEquals(0 to "0.0.0.0", dnsAnswer("sub.${Hosts.B}"))
        // the neighbour is not touched
        assertAllowed(Hosts.C)
        assertAllowed("www.${Hosts.C}")
    }

    @Test
    @Covers("DEC-03", "DEC-04")
    fun narrowerWinsTieBlocks() {
        launch()
        val block = addGlobalRule(RuleSpec(Hosts.B))
        val www = addGlobalRule(RuleSpec("www.${Hosts.B}", action = allow, subdomains = false))
        // the same target both ways: block wins
        val tieBlock = addGlobalRule(RuleSpec(Hosts.A))
        addGlobalRule(RuleSpec(Hosts.A, action = allow))
        on()
        assertAllowed("www.${Hosts.B}", rule = www.id)
        assertBlocked(Hosts.B, rule = block.id)
        assertBlocked(Hosts.A, rule = tieBlock.id)
        assertBlocked(Hosts.A_WWW, rule = tieBlock.id)
    }

    @Test
    @Covers("DEC-05")
    fun appRulesComeFirstInASet() {
        launch()
        addGlobalRule(RuleSpec(Hosts.C))
        val appAllow = addAppRule(shellName, RuleSpec(Hosts.C, action = allow))
        // and the other way: the app's block beats a global allow of the same name
        addGlobalRule(RuleSpec(Hosts.A, action = allow))
        val appBlock = addAppRule(shellName, RuleSpec(Hosts.A))
        on()
        assertAllowed(Hosts.C, rule = appAllow.id)
        assertBlocked(Hosts.A, rule = appBlock.id)
    }

    @Test
    @Covers("DEC-06")
    fun firstEnabledSetDecides() {
        launch()
        addSet("Low")
        val low = addGlobalRule(RuleSpec(Hosts.B, set = "Low"))
        val high = addGlobalRule(RuleSpec(Hosts.B, action = allow))
        assertTrue(setPos(str(R.string.set_default)) < setPos("Low"))
        on()
        assertAllowed(Hosts.B, rule = high.id)
        // the default set off: it takes no part, the lower set decides
        drawer(R.string.nav_sets)
        setSwitch(str(R.string.set_default), false)
        waitFor("default set off") { !app.firewall.state.value.isEnabled(setId(str(R.string.set_default))) }
        assertBlocked("www.${Hosts.B}", rule = low.id)
        // and back on
        setSwitch(str(R.string.set_default), true)
        assertAllowed(Hosts.B, rule = high.id)
    }

    @Test
    @Covers("DEC-07")
    fun globalAllowAboveDoesNotLiftAnAppBlockBelow() {
        launch()
        addSet("Low")
        addGlobalRule(RuleSpec(Hosts.C, action = allow))
        val appBlock = addAppRule(shellName, RuleSpec(Hosts.C, set = "Low"))
        // a global block below is lifted by the global allow above
        addGlobalRule(RuleSpec(Hosts.A, action = allow))
        addGlobalRule(RuleSpec(Hosts.A, set = "Low"))
        on()
        assertBlocked(Hosts.C, rule = appBlock.id)
        assertAllowed(Hosts.A)
    }

    @Test
    @Covers("DEC-08")
    fun blockEverythingWithAnException() {
        launch()
        val all = addAppRule(shellName, RuleSpec(kind = TargetKind.ALL))
        // the control host must pass: it is the exception
        val except = addAppRule(shellName, RuleSpec("wikipedia.org", action = allow))
        on()
        assertAllowed(Hosts.CONTROL, rule = except.id)
        assertBlocked(Hosts.A, rule = all.id)
        assertBlocked("one.one.one.one", ip = Hosts.CF_IP, rule = all.id)
        // ping: blocked when Android tells whose it is
        val got = Net.ping(Hosts.CF_IP)
        val icmp = Rows.await("ping row") { it.dstIp == Hosts.CF_IP && it.ipproto == 1 }
        assertTrue(
            "ping of the shell (uid ${icmp.uid}, blocked=${icmp.blocked}, $got replies)",
            icmp.uid != SHELL_UID || (icmp.blocked && got == 0)
        )
    }

    @Test
    @Covers("DEC-09", "SETS-06")
    fun reorderingSetsDecidesAtOnce() {
        launch()
        addSet("Low")
        val block = addGlobalRule(RuleSpec(Hosts.A, set = "Low"))
        val allowIt = addGlobalRule(RuleSpec(Hosts.A, action = allow))
        on()
        assertAllowed(Hosts.A, rule = allowIt.id)
        moveSet("Low", up = true)
        waitFor("Low first") { setPos("Low") < setPos(str(R.string.set_default)) }
        assertBlocked(Hosts.A_WWW, rule = block.id)
        val t0 = System.currentTimeMillis()
        moveSet("Low", up = false)
        waitFor("Low back below") { setPos("Low") > setPos(str(R.string.set_default)) }
        // www.example.org was answered 0.0.0.0 with a 10 s TTL
        Thread.sleep((11_000 - (System.currentTimeMillis() - t0)).coerceAtLeast(0))
        assertAllowed(Hosts.A_WWW, rule = allowIt.id)
    }

    @Test
    @Covers("DEC-13")
    fun blockByNameWithoutDnsUsesTheSni() {
        launch()
        val r = addGlobalRule(RuleSpec("www.cloudflare.com", subdomains = false))
        on()
        // straight to the address, no DNS: the name comes from the Client Hello
        val got = Tls.hello(Hosts.CF_IP, "www.cloudflare.com")
        assertTrue("blocked after the Client Hello ($got bytes)", got < 100)
        val row = Rows.await("TLS blocked by SNI") { it.dstIp == Hosts.CF_IP && it.dstPort == 443 && it.blocked }
        assertEquals(r.id, row.fwRule)
        assertEquals("www.cloudflare.com", row.host)
        // another name on the same address passes
        assertTrue(Tls.hello(Hosts.CF_IP, "cloudflare.com") > 500)
    }
}
