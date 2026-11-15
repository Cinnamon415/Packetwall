package io.github.cinnamon415.packetwall.fw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ForeignImportTest {
    private val installed = listOf(
        ForeignImport.App("com.a", 10100, false), ForeignImport.App("com.b", 10101, false),
        ForeignImport.App("com.c", 10102, false), ForeignImport.App("android", 1000, true),
    )
    private fun Rule.short() = "${(who as? Who.App)?.pkg ?: "*"} ${action} ${target.kind}:${target.value}${if (target.subdomains) "+" else ""}" +
        (if (port != 0) ":$port" else "") + (if (proto != Proto.ANY) "/$proto" else "")

    @Test fun detect() {
        assertEquals(ForeignImport.Format.NETGUARD, ForeignImport.detect("<?xml version='1.0'?><netguard></netguard>".toByteArray()))
        assertEquals(ForeignImport.Format.PCAPDROID, ForeignImport.detect("""{"rules":[{"type":"HOST","value":"x.com"}]}""".toByteArray()))
        assertEquals(ForeignImport.Format.AFWALL, ForeignImport.detect("""{"rules":[{"com.a":{"0":true}}],"mode":"blacklist"}""".toByteArray()))
        assertEquals(ForeignImport.Format.SINGBOX, ForeignImport.detect("""{"version":2,"rules":[{"domain":["a.com"]}]}""".toByteArray()))
        assertEquals(ForeignImport.Format.PACKETWALL, ForeignImport.detect("""{"format":"packetwall-rules","state":{}}""".toByteArray()))
        assertEquals(ForeignImport.Format.RETHINK, ForeignImport.detect(byteArrayOf(0x50, 0x4b, 3, 4)))
        assertEquals(ForeignImport.Format.LIST, ForeignImport.detect("0.0.0.0 a.com\n".toByteArray()))
    }

    @Test fun pcapdroidListAndBackup() {
        val list = """{"rules":[{"type":"HOST","value":"ads.com"},{"type":"IP","value":"1.2.3.0/24"},{"type":"COUNTRY","value":"CN"},
            {"type":"APP","value":"com.a","allowlist":[{"type":"HOST","value":"ok.com"}]},{"type":"PROTOCOL","value":"QUIC"}]}"""
        val p = ForeignImport.pcapdroid(list)
        assertEquals(listOf("* BLOCK DOMAIN:ads.com+", "* BLOCK IP:1.2.3.0/24", "* BLOCK COUNTRY:cn", "com.a BLOCK ALL:", "com.a ALLOW DOMAIN:ok.com+"),
            p.rules.map { it.short() })
        assertEquals(1, p.skipped)
        val backup = """{"version":1,"settings":{"bl":{"type":"string","value":"{\"rules\":[{\"type\":\"HOST\",\"value\":\"t.com\"}]}"},
            "firewall_whitelist":{"type":"string","value":"{\"rules\":[{\"type\":\"APP\",\"value\":\"com.b\"}]}"}}}"""
        val b = ForeignImport.pcapdroid(backup)
        assertEquals(listOf("* BLOCK DOMAIN:t.com+", "com.b ALLOW ALL:"), b.rules.map { it.short() })
        assertTrue(b.notes.isNotEmpty())
    }

    @Test fun netguard() {
        val xml = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
            <netguard><application><setting key="whitelist_wifi" type="boolean" value="false" />
            <setting key="whitelist_other" type="boolean" value="false" /></application>
            <wifi><setting key="com.a" type="boolean" value="true" /><setting key="com.b" type="boolean" value="true" /></wifi>
            <mobile><setting key="com.a" type="boolean" value="true" /></mobile>
            <filter><rule pkg="com.c" version="4" protocol="6" daddr="9.9.9.9" dport="443" time="1" block="1" /></filter>
            <forward /></netguard>"""
        val p = ForeignImport.netguard(xml, installed)
        assertEquals(listOf("com.a BLOCK ALL:", "com.c BLOCK IP:9.9.9.9:443/TCP"), p.rules.map { it.short() })
        assertTrue(p.samples.any { it.contains("com.b") })     // Wi-Fi only

        // default-deny: everything without an explicit "false" on both networks is blocked (system apps excluded)
        val deny = """<netguard><application /><wifi><setting key="com.a" type="boolean" value="false" /></wifi>
            <mobile><setting key="com.a" type="boolean" value="false" /></mobile></netguard>"""
        assertEquals(listOf("com.b BLOCK ALL:", "com.c BLOCK ALL:"), ForeignImport.netguard(deny, installed).rules.map { it.short() })
    }

    @Test fun afwall() {
        val black = """{"rules":[{"com.a":{"0":true,"1":true},"com.b":{"0":true}}],"mode":"blacklist"}"""
        val p = ForeignImport.afwall(black, installed)
        assertEquals(listOf("com.a BLOCK ALL:"), p.rules.map { it.short() })
        val white = """{"rules":[],"mode":"whitelist","v2":{"version":2,"mode":"whitelist","rules":[
            {"uid":10100,"packages":["com.a"],"on":[0,1]},{"uid":10101,"packages":["com.b"],"on":[0]}]}}"""
        val w = ForeignImport.afwall(white, installed)
        assertEquals(listOf("com.c BLOCK ALL:"), w.rules.map { it.short() })   // b is Wi-Fi only -> reported
        assertTrue(w.samples.any { it.contains("com.b") })
        val any = """{"mode":"blacklist","v2":{"version":2,"mode":"blacklist","rules":[{"uid":-10,"special":"dev.afwall.special.any","on":[0,1]}]}}"""
        assertEquals(listOf("* BLOCK ALL:"), ForeignImport.afwall(any, installed).rules.map { it.short() })
    }

    @Test fun singbox() {
        val src = """{"version":2,"rules":[{"domain":["exact.com"],"domain_suffix":["suf.com",".sub.com"],"ip_cidr":["10.0.0.0/8"],
            "domain_keyword":["ads"]},{"type":"logical","mode":"and","rules":[]}]}"""
        val p = ForeignImport.singbox(src.toByteArray())
        assertEquals(listOf("=exact.com", "suf.com", "=**.sub.com", "10.0.0.0/8"), p.entries)
        assertEquals(2, p.skipped)
        assertTrue(runCatching { ForeignImport.singbox("SRS\u0001xx".toByteArray()) }.exceptionOrNull() is ForeignImport.Unsupported)
    }

    @Test fun adblockAppAndImportant() {
        val p = ForeignImport.list(sequenceOf("||ads.com^", "||track.com^\$important", "@@||ok.ads.com^",
            "||pay.com^\$app=com.a|com.b", "@@||cdn.com^\$app=com.c", "||x.com^\$app=~com.a"))
        assertEquals(listOf("ads.com", "!ok.ads.com"), p.entries)
        assertEquals(listOf("track.com"), p.important)
        assertEquals(listOf("com.a BLOCK DOMAIN:pay.com+", "com.b BLOCK DOMAIN:pay.com+", "com.c ALLOW DOMAIN:cdn.com+"), p.rules.map { it.short() })
        assertEquals(1, p.skipped)
    }

    @Test fun rethink() {
        val rows = ForeignImport.RethinkRows(
            domains = listOf(ForeignImport.RethinkRows.Domain("*.ads.com", -1000, 1, true), ForeignImport.RethinkRows.Domain("ok.com", 10100, 2, false),
                ForeignImport.RethinkRows.Domain("gone.com", -10100, 1, false)),
            ips = listOf(ForeignImport.RethinkRows.Ip("1.2.3.4", 443, "tcp", -1000, 1, true), ForeignImport.RethinkRows.Ip("5.6.7.8", 0, "", 10101, 1, false)),
            apps = listOf(ForeignImport.RethinkRows.AppRow("com.c", 10102, 5, 0), ForeignImport.RethinkRows.AppRow("com.b", 10101, 5, 1)))
        val p = ForeignImport.rethink(rows, installed)
        assertEquals(listOf("* BLOCK DOMAIN:ads.com+", "com.a ALLOW DOMAIN:ok.com", "* BLOCK IP:1.2.3.4:443/TCP", "com.c BLOCK ALL:"), p.rules.map { it.short() })
    }
}
