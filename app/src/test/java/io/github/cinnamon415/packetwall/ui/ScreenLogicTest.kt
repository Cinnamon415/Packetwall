package io.github.cinnamon415.packetwall.ui

import io.github.cinnamon415.packetwall.analysis.ConnFilter
import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.Proto
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.Target
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The list logic the screens' ViewModels run off the main thread. */
class ScreenLogicTest {
    private val chrome = AppInfo(10100, "com.android.chrome", "Chrome", false)
    private val bank = AppInfo(10101, "com.bank", "Bank", false)
    private val sys = AppInfo(1000, "android", "Android System", true)
    private val sys2 = AppInfo(1001, "com.android.phone", "Phone", true)

    private fun conn(id: Int, app: AppInfo, l7: String, url: String? = null, blocked: Boolean = false) =
        Conn(id, app.uid, app, 4, 6, "10.215.173.1", 40000, "1.2.3.4", 443, l7, "h$id.example", url, 10, 10, 1, 1, 0, 0, 0, 3, blocked, 0)

    private val conns = listOf(
        conn(1, chrome, "HTTP", url = "http://h1.example/"),
        conn(2, chrome, "DNS"),
        conn(3, bank, "TLS", blocked = true),
        conn(4, bank, "DNS", blocked = true)
    )

    @Test fun logsCombineStatusTabAndExpression() {
        assertEquals(listOf(1, 2, 3, 4), selectConns(conns, null, StatusFilter.ALL, LogTab.CONNECTIONS).map { it.id })
        assertEquals(listOf(3, 4), selectConns(conns, null, StatusFilter.BLOCKED, LogTab.CONNECTIONS).map { it.id })
        assertEquals(listOf(2), selectConns(conns, null, StatusFilter.ALLOWED, LogTab.DNS).map { it.id })
        assertEquals(listOf(1), selectConns(conns, null, StatusFilter.ALL, LogTab.HTTP).map { it.id })
        val bankOnly = ConnFilter.compile("app == Bank")
        assertEquals(listOf(4), selectConns(conns, bankOnly, StatusFilter.ALL, LogTab.DNS).map { it.id })
    }

    private fun rule(id: Int, set: Int, who: Who, kind: TargetKind, value: String, port: Int = 0, created: Long = 0) =
        Rule(id, set, who, Target(kind, value, true), Action.BLOCK, port = port, created = created)

    @Test fun appListHidesSystemAppsWithoutRulesAndSorts() {
        val rules = listOf(
            rule(1, 1, Who.App("com.bank"), TargetKind.DOMAIN, "a.example"),
            rule(2, 1, Who.App("com.bank"), TargetKind.DOMAIN, "b.example"),
            rule(3, 2, Who.App("android"), TargetKind.ALL, ""),
            rule(4, 2, Who.Group(9), TargetKind.ALL, "")
        )
        val installed = listOf(chrome, bank, sys, sys2)
        val traffic = mapOf("com.android.chrome" to 500L, "com.bank" to 10L)

        val byRules = buildAppList(installed, rules, traffic, AppQuery())
        assertEquals(listOf("com.bank", "android", "com.android.chrome"), byRules.apps!!.map { it.packageName })
        assertEquals(mapOf("com.bank" to 2, "android" to 1), byRules.ruleCounts)
        assertEquals(mapOf(9 to 1), byRules.groupRuleCounts)

        val byTraffic = buildAppList(installed, rules, traffic, AppQuery(showSystem = true, sort = AppSort.TRAFFIC))
        assertEquals(listOf("com.android.chrome", "com.bank", "android", "com.android.phone"), byTraffic.apps!!.map { it.packageName })

        val set1 = buildAppList(installed, rules, traffic, AppQuery(setId = 1, onlyWithRules = true))
        assertEquals(listOf("com.bank"), set1.apps!!.map { it.packageName })

        val search = buildAppList(installed, rules, traffic, AppQuery(text = " CHROME ", sort = AppSort.NAME))
        assertEquals(listOf("com.android.chrome"), search.apps!!.map { it.packageName })

        assertNull(buildAppList(null, rules, traffic, AppQuery()).apps)

        // an uninstalled app with rules is still listed (uid -1), so its rules can be reached
        val gone =
            buildAppList(installed, rules + rule(5, 1, Who.App("com.gone"), TargetKind.ALL, ""), traffic, AppQuery(onlyWithRules = true))
        assertEquals(listOf("com.bank", "android", "com.gone"), gone.apps!!.map { it.packageName })
        assertEquals(-1, gone.apps!!.last().uid)
    }

    @Test fun globalRulesFilterAndSort() {
        val rules = listOf(
            rule(1, 1, Who.Global, TargetKind.IP, "9.9.9.9", created = 3),
            rule(2, 1, Who.Global, TargetKind.DOMAIN, "b.example", port = 443, created = 1),
            rule(3, 2, Who.Global, TargetKind.DOMAIN, "a.example", created = 2),
            rule(4, 1, Who.App("com.bank"), TargetKind.DOMAIN, "a.example")
        )
        assertEquals(listOf(3, 2, 1), globalRules(rules, "", null, null, false, false).map { it.id })
        assertEquals(listOf(1, 3, 2), globalRules(rules, "", null, null, false, true).map { it.id })
        assertEquals(listOf(2), globalRules(rules, "", 1, TargetKind.DOMAIN, false, false).map { it.id })
        assertEquals(listOf(2), globalRules(rules, "", null, null, true, false).map { it.id })
        assertEquals(listOf(3), globalRules(rules, " A.EX", null, null, false, false).map { it.id })
        assertEquals(Proto.ANY, rules[0].proto)
    }
}
