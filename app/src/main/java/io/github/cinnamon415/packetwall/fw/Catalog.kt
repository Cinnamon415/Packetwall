package io.github.cinnamon415.packetwall.fw

/** Built-in blocklist catalog. All lists are DNS/host lists; cosmetic rules are skipped on import. */
object Catalog {
    data class Entry(val name: String, val url: String, val note: String)

    val entries = listOf(
        Entry("HaGeZi Multi Light", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt", "ads, trackers · ~70k"),
        Entry("HaGeZi Multi Normal", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt", "ads, trackers, malware · ~150k"),
        Entry("HaGeZi Multi Pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", "stricter · ~250k"),
        Entry("HaGeZi Native: OPPO/Realme", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.oppo-realme.txt", "system telemetry"),
        Entry("HaGeZi Native: Xiaomi", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt", "system telemetry"),
        Entry("HaGeZi Native: Samsung", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt", "system telemetry"),
        Entry("OISD small", "https://small.oisd.nl/", "ads, trackers · low false positives"),
        Entry("OISD big", "https://big.oisd.nl/", "ads, trackers, malware"),
        Entry("AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "AdGuard DNS"),
        Entry("StevenBlack hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts format"),
        Entry("AdGuard Russian (network rules)", "https://filters.adtidy.org/extension/ublock/filters/1.txt", "RU · cosmetic rules skipped"),
    )
}
