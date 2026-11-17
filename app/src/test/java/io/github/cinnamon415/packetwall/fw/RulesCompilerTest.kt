package io.github.cinnamon415.packetwall.fw

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RulesCompilerTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test fun compilesEnabledSetsInPriorityOrder() {
        val list = tmp.newFile("5.txt").apply { writeText("ads.example\n") }
        val st = FwState(
            sets = listOf(
                RuleSet(1, "Default"),
                RuleSet(2, "Off"),
                RuleSet(3, "Work"),
                RuleSet(5, "List", SetKind.BLOCKLIST, reject = true)
            ),
            order = listOf(SetState(3, true), SetState(1, true), SetState(2, false), SetState(5, true)),
            groups = listOf(AppGroup(9, "G", listOf("com.a", "com.b", "missing"))),
            rules = listOf(
                Rule(10, 1, Who.Global, Target(TargetKind.DOMAIN, " Example.ORG ", true), Action.BLOCK, reject = true),
                Rule(11, 1, Who.App("com.a"), Target(TargetKind.ALL), Action.BLOCK),
                Rule(
                    12,
                    3,
                    Who.Group(9),
                    Target(TargetKind.IP, "1.2.3.0/24"),
                    Action.ALLOW,
                    proto = Proto.TCP,
                    port = 443,
                    route = Route.UPSTREAM
                ),
                Rule(13, 2, Who.Global, Target(TargetKind.DOMAIN, "disabled.example"), Action.BLOCK),
                Rule(14, 1, Who.App("not.installed"), Target(TargetKind.ALL), Action.BLOCK),
                Rule(15, 1, Who.Global, Target(TargetKind.ASN, "AS13335"), Action.BLOCK),
                Rule(16, 1, Who.Global, Target(TargetKind.DOMAIN, ""), Action.BLOCK)
            )
        )
        val out = tmp.newFile("rules.compiled")
        RulesCompiler.compile(st, mapOf("com.a" to 10100, "com.b" to 10101)::get, { File(tmp.root, "$it.txt") }, out) {
            mapOf(13335L to listOf("104.16.0.0/13", "2606:4700::/32"))
        }
        val lines = out.readLines().filter { !it.startsWith("#") }
        assertEquals(
            listOf(
                // set "Work" first (priority 0): the group expands to its installed members
                "R\t12\t0\t1\t10100\t0\t0\tI\t1.2.3.0/24\t0\t6\t443\t2",
                "R\t12\t0\t1\t10101\t0\t0\tI\t1.2.3.0/24\t0\t6\t443\t2",
                // "Default" (priority 1); values are trimmed and lowercased, empty ones dropped
                "R\t10\t1\t0\t-1\t1\t1\tD\texample.org\t1\t0\t0\t0",
                "R\t11\t1\t2\t10100\t1\t0\tA\t-\t0\t0\t0\t0",
                "R\t15\t1\t0\t-1\t1\t0\tS\t104.16.0.0/13\t0\t0\t0\t0",
                "R\t15\t1\t0\t-1\t1\t0\tS\t2606:4700::/32\t0\t0\t0\t0",
                // the disabled set is skipped; the blocklist keeps its position (priority 2)
                "L\t2\t-5\t1\t1\t${list.absolutePath}"
            ),
            lines
        )
    }
}
