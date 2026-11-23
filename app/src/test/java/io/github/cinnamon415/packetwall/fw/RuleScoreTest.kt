package io.github.cinnamon415.packetwall.fw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleScoreTest {
    private fun dom(v: String, subs: Boolean, a: Action, set: Int = 1, who: Who = Who.App("x")) =
        Rule(0, set, who, Target(TargetKind.DOMAIN, v, subs), a)

    private val st = FwState(
        sets = listOf(RuleSet(1, "Default"), RuleSet(2, "Low"), RuleSet(3, "Off")),
        order = listOf(SetState(1, true), SetState(2, true), SetState(3, false))
    )

    @Test fun scoresMatchTheEngine() {
        // the values the audit measured in pw_rules.c
        assertEquals(1037, RuleScore.domainScore("t.example.com", false))
        assertEquals(1022, RuleScore.domainScore("example.com", true))
        assertTrue(RuleScore.domainScore("*.example.com", false) > RuleScore.domainScore("example.com", true))
        assertTrue(RuleScore.domainScore("example.com", true) > RuleScore.domainScore("**.example.com", false))
        val ip = Rule(0, 1, Who.Global, Target(TargetKind.IP, "10.0.0.0/8"), Action.BLOCK)
        assertEquals((300 + 8 * 100 / 32) * 4, RuleScore.score(ip))
        assertEquals(RuleScore.score(ip) + 3, RuleScore.score(ip.copy(port = 443, proto = Proto.TCP)))
    }

    @Test fun broaderAllowLosesInTheSameSet() {
        val block = dom("t.example.com", false, Action.BLOCK)
        // the audit's case: allow example.com + subdomains in the same set does not unblock the exact host
        assertFalse(RuleScore.allowWins(st, dom("example.com", true, Action.ALLOW), block, 1))
        // same target: tie, block wins
        assertFalse(RuleScore.allowWins(st, dom("t.example.com", false, Action.ALLOW), block, 1))
        // narrower allow (port) wins
        assertTrue(RuleScore.allowWins(st, dom("t.example.com", false, Action.ALLOW).copy(port = 443), block, 1))
    }

    @Test fun setsAndWhoLevels() {
        val block = dom("t.example.com", false, Action.BLOCK, set = 2)
        assertTrue(RuleScore.allowWins(st, dom("example.com", true, Action.ALLOW, set = 1), block, 2))
        assertFalse(RuleScore.allowWins(st, dom("example.com", true, Action.ALLOW, set = 2, who = Who.Global), block, 2))
        // app beats global in the same set whatever the targets
        val global = dom("t.example.com", false, Action.BLOCK, who = Who.Global)
        assertTrue(RuleScore.allowWins(st, dom("example.com", true, Action.ALLOW), global, 1))
        // a global allow, even in a higher set, does not lift an app's block (spec 2.5.4, pw_rules.c)
        assertFalse(RuleScore.allowWins(st, dom("t.example.com", false, Action.ALLOW, set = 1, who = Who.Global), block, 2))
        // a global allow in a higher set does lift a global block
        assertTrue(RuleScore.allowWins(st, dom("t.example.com", false, Action.ALLOW, set = 1, who = Who.Global), global.copy(setId = 2), 2))
        // a disabled set never wins
        assertFalse(RuleScore.allowWins(st, dom("t.example.com", false, Action.ALLOW, set = 3), null, 2))
        // a blocklist decided: any enabled set above it wins
        assertTrue(RuleScore.allowWins(st, dom("example.com", true, Action.ALLOW, set = 1), null, 2))
    }

    @Test fun subnets() {
        assertEquals("1.2.3.0/24", RuleScore.subnet("1.2.3.4"))
        assertEquals("2001:db8:1:2:0:0:0:0/64", RuleScore.subnet("2001:db8:1:2::5"))
        assertNull(RuleScore.subnet("example.com"))
        assertNull(RuleScore.subnet("10.0.0.0/8"))
    }
}
