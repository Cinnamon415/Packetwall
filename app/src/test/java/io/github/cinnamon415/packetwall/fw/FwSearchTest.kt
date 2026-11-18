package io.github.cinnamon415.packetwall.fw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FwSearchTest {
    private val st = FwState(
        sets = listOf(RuleSet(1, "Default"), RuleSet(5, "Work"), RuleSet(9, "Ads", kind = SetKind.BLOCKLIST)),
        order = listOf(SetState(1, true), SetState(5, false), SetState(9, true)),
        rules = listOf(
            Rule(10, 1, Who.App("com.idamob.tinkoff"), Target(TargetKind.DOMAIN, "tinkoff.ru", subdomains = true), Action.BLOCK),
            Rule(11, 5, Who.Global, Target(TargetKind.DOMAIN, "id.tinkoff.ru"), Action.ALLOW),
            Rule(12, 1, Who.Group(3), Target(TargetKind.ALL), Action.BLOCK),
            Rule(13, 1, Who.Global, Target(TargetKind.IP, "10.0.0.0/8"), Action.BLOCK)
        ),
        groups = listOf(AppGroup(3, "Banks", listOf("com.idamob.tinkoff"))),
        profiles = listOf(
            Profile(20, "Main", listOf(SetState(1, true), SetState(5, false))),
            Profile(21, "Strict", listOf(SetState(1, true), SetState(5, true)))
        ),
        activeProfile = 20
    )
    private val names = { w: Who ->
        when (w) {
            is Who.App -> "T-Bank"
            is Who.Group -> "Banks"
            Who.Global -> ""
        }
    }

    @Test fun findsByTargetOwnerAndParentDomain() {
        // "tinkoff" is in the targets of 10 and 11 and in the package of 10
        assertEquals(listOf(10, 11), FwSearch.rules(st, "Tinkoff", names).map { it.rule.id }.sorted())
        // a subdomain finds the rule for its parent with subdomains, not the exact rule of another host
        assertEquals(listOf(10), FwSearch.rules(st, "api.tinkoff.ru.", names).map { it.rule.id })
        // an owner name
        assertEquals(listOf(12), FwSearch.rules(st, "bank", names).map { it.rule.id }.filter { it == 12 })
        assertEquals(listOf(13), FwSearch.rules(st, "10.0", names).map { it.rule.id })
        assertTrue(FwSearch.rules(st, "  ", names).isEmpty())
    }

    @Test fun showsWhereRulesLive() {
        val h = FwSearch.rules(st, "id.tinkoff.ru", names).first { it.rule.id == 11 }
        assertEquals("Work", h.setName)
        assertEquals(false, h.setOn)
        assertEquals(listOf("Strict"), h.profiles)
        val main = FwSearch.rules(st, "10.0", names).single()
        assertEquals(listOf("Main", "Strict"), main.profiles)
    }

    @Test fun listEntriesMatchTextAndParents() {
        val lines = sequenceOf("ads.example.com", "example.com", "!good.example.com", "other.org", "*.tracker.net")
        assertEquals(3 to listOf("ads.example.com", "example.com", "!good.example.com"), FwSearch.listEntries(lines, "example"))
        // a host under a listed domain is found by the parent entry
        assertEquals(1 to listOf("example.com"), FwSearch.listEntries(lines, "cdn.example.com"))
        assertEquals(1 to listOf("*.tracker.net"), FwSearch.listEntries(lines, "x.tracker.net"))
        assertEquals(0 to emptyList<String>(), FwSearch.listEntries(lines, ""))
    }

    @Test fun parents() {
        assertEquals(listOf("a.b.c", "b.c", "c"), FwSearch.parents("a.b.c"))
        assertTrue(FwSearch.parents("a b").isEmpty())
    }
}
