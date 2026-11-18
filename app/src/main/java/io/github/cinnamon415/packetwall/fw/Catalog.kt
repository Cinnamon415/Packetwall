package io.github.cinnamon415.packetwall.fw

import io.github.cinnamon415.packetwall.R

/** Built-in blocklist catalog. All lists are DNS/host lists; cosmetic rules are skipped on import. */
object Catalog {
    enum class Category(val label: Int) {
        ADS(R.string.listcat_ads),
        MALWARE(R.string.listcat_malware),
        TELEMETRY(R.string.listcat_telemetry),
        REGIONAL(R.string.listcat_regional)
    }

    /** [note]: what it blocks and roughly how big, shown under the name. */
    data class Entry(val name: String, val url: String, val category: Category, val note: Int)

    private const val HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock"

    val entries = listOf(
        Entry("HaGeZi Multi Light", "$HAGEZI/light.txt", Category.ADS, R.string.note_hagezi_light),
        Entry("HaGeZi Multi Normal", "$HAGEZI/multi.txt", Category.ADS, R.string.note_hagezi_normal),
        Entry("HaGeZi Multi Pro", "$HAGEZI/pro.txt", Category.ADS, R.string.note_hagezi_pro),
        Entry("OISD small", "https://small.oisd.nl/", Category.ADS, R.string.note_oisd_small),
        Entry("OISD big", "https://big.oisd.nl/", Category.ADS, R.string.note_oisd_big),
        Entry(
            "AdGuard DNS filter",
            "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            Category.ADS,
            R.string.note_adguard_dns
        ),
        Entry(
            "StevenBlack hosts",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            Category.ADS,
            R.string.note_stevenblack
        ),
        Entry("HaGeZi Threat Intelligence (mini)", "$HAGEZI/tif.mini.txt", Category.MALWARE, R.string.note_hagezi_tif),
        Entry("Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt", Category.MALWARE, R.string.note_phishing_army),
        Entry("HaGeZi Native: Xiaomi", "$HAGEZI/native.xiaomi.txt", Category.TELEMETRY, R.string.note_native),
        Entry("HaGeZi Native: Samsung", "$HAGEZI/native.samsung.txt", Category.TELEMETRY, R.string.note_native),
        Entry("HaGeZi Native: OPPO/Realme", "$HAGEZI/native.oppo-realme.txt", Category.TELEMETRY, R.string.note_native),
        Entry("HaGeZi Native: Huawei", "$HAGEZI/native.huawei.txt", Category.TELEMETRY, R.string.note_native),
        Entry(
            "AdGuard Russian (network rules)",
            "https://filters.adtidy.org/extension/ublock/filters/1.txt",
            Category.REGIONAL,
            R.string.note_adguard_ru
        )
    )
}
