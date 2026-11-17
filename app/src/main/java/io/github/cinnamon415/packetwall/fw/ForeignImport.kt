package io.github.cinnamon415.packetwall.fw

import javax.xml.parsers.DocumentBuilderFactory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.w3c.dom.Element

/**
 * Converts rules of other firewalls into Packetwall rules (spec 3). Packetwall has no network-type
 * conditions and no whitelist mode, so such semantics are translated where possible and reported
 * otherwise. Rule ids/sets are assigned by [FirewallStore.applyImport].
 */
object ForeignImport {
    enum class Format(val label: String) {
        AUTO("Auto"),
        LIST("hosts / domains / uBO / AdGuard"),
        PCAPDROID("PCAPdroid"),
        NETGUARD("NetGuard"),
        AFWALL("AFWall+"),
        RETHINK("RethinkDNS"),
        SINGBOX("sing-box rule-set"),
        PACKETWALL("Packetwall JSON")
    }

    /** Installed app, for "block every app not listed" translations. */
    data class App(val pkg: String, val uid: Int, val system: Boolean)

    data class Plan(
        val format: Format,
        /** Rules for a new user set (setId 0 = placeholder). */
        val rules: List<Rule> = emptyList(),
        /** Entries for a new blocklist set (normalized list format). */
        val entries: List<String> = emptyList(),
        /** Entries that must win over the list's exceptions ($important) — a set above it. */
        val important: List<String> = emptyList(),
        val skipped: Int = 0,
        val samples: List<String> = emptyList(),
        val notes: List<Note> = emptyList()
    ) {
        val empty get() = rules.isEmpty() && entries.isEmpty() && important.isEmpty()
    }

    class Unsupported(val reason: Reason) : Exception(reason.name) {
        enum class Reason {
            /** Binary .srs rule-set: convert with "sing-box rule-set decompile" and import the JSON. */
            SINGBOX_BINARY,

            /** The RethinkDNS backup has no bravedns.db. */
            RETHINK_NO_DB
        }
    }

    /** Something the user should know about an import; [count] where the kind has one. Shown localized. */
    data class Note(val kind: NoteKind, val count: Int = 0)

    enum class NoteKind {
        PCAPDROID_WHITELIST,
        PARTIAL_NETWORK,
        NETGUARD_DEFAULT_BLOCK,
        NETGUARD_PORT_FORWARDING,
        AFWALL_ALLOWLIST,
        AFWALL_COLUMNS,
        SINGBOX_NO_EQUIVALENT,
        LIST_IMPORTANT,
        LIST_APP_RULES,
        RETHINK_BYPASS,
        RETHINK_EXCLUDED,
        RETHINK_ISOLATED
    }

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    fun detect(bytes: ByteArray): Format {
        if (bytes.size >= 4 && bytes[0] == 'P'.code.toByte() && bytes[1] == 'K'.code.toByte()) return Format.RETHINK
        if (bytes.size >= 3 && String(bytes, 0, 3, Charsets.ISO_8859_1) == "SRS") return Format.SINGBOX
        val head = String(bytes, 0, minOf(bytes.size, 4096), Charsets.UTF_8).trimStart('\uFEFF', ' ', '\n', '\r', '\t')
        if (head.startsWith("<")) return if (head.contains("<netguard")) Format.NETGUARD else Format.LIST
        if (head.startsWith("{") || head.startsWith("[")) {
            val root = try {
                json.parseToJsonElement(String(bytes, Charsets.UTF_8))
            } catch (e: Exception) {
                return Format.LIST
            }
            val o = root as? JsonObject ?: return Format.LIST
            return when {
                o["format"]?.jsonPrimitive?.contentOrNull == ExportFile.FORMAT -> Format.PACKETWALL
                o.containsKey("settings") && (o["settings"] as? JsonObject)?.containsKey("bl") == true -> Format.PCAPDROID
                o.containsKey("mode") && (o.containsKey("v2") || o.containsKey("rules") || o.containsKey("default")) -> Format.AFWALL
                (o["rules"] as? JsonArray)?.firstOrNull()?.let { it is JsonObject && it.containsKey("type") && it.containsKey("value") } ==
                    true -> Format.PCAPDROID
                o.containsKey("rules") && o.containsKey("version") -> Format.SINGBOX
                else -> Format.LIST
            }
        }
        return Format.LIST
    }

    private class Report {
        var skipped = 0
        val samples = ArrayList<String>()
        val notes = LinkedHashSet<Note>()
        fun skip(what: String) {
            skipped++
            if (samples.size < 30) samples.add(what.take(200))
        }
    }

    private fun rule(who: Who, target: Target, action: Action, proto: Proto = Proto.ANY, port: Int = 0) =
        Rule(0, 0, who, target, action, proto = proto, port = port)

    private fun hostTarget(v: String): Target? {
        val d = v.trim().lowercase().trimEnd('.')
        return when {
            d.startsWith("*.") && ListParser.isDomain(d.removePrefix("*.")) -> Target(TargetKind.DOMAIN, d.removePrefix("*."), true)
            ListParser.isDomain(d) -> Target(TargetKind.DOMAIN, d, true)
            else -> null
        }
    }

    private fun ipTarget(v: String) = v.trim().lowercase().takeIf { ListParser.isIp(it) }?.let { Target(TargetKind.IP, it) }

    // ------------------------------------------------------------------ PCAPdroid

    /** An exported list ({"rules":[…]}) or a full settings backup ("bl" = firewall blocklist, "firewall_whitelist"). */
    fun pcapdroid(text: String): Plan {
        val r = Report()
        val root = json.parseToJsonElement(text).jsonObject
        val rules = ArrayList<Rule>()
        val settings = root["settings"] as? JsonObject
        if (settings != null) {
            fun listJson(key: String) = (settings[key] as? JsonObject)?.get("value")?.jsonPrimitive?.contentOrNull
            listJson("bl")?.let { rules += pcapdroidList(json.parseToJsonElement(it).jsonObject, Action.BLOCK, r) }
            listJson("firewall_whitelist")?.let {
                rules += pcapdroidList(json.parseToJsonElement(it).jsonObject, Action.ALLOW, r)
                r.notes.add(Note(NoteKind.PCAPDROID_WHITELIST))
            }
        } else {
            rules += pcapdroidList(root, Action.BLOCK, r)
        }
        return Plan(Format.PCAPDROID, rules, skipped = r.skipped, samples = r.samples, notes = r.notes.toList())
    }

    private fun pcapdroidList(o: JsonObject, action: Action, r: Report): List<Rule> {
        val out = ArrayList<Rule>()
        for (el in o["rules"]?.jsonArray ?: JsonArray(emptyList())) {
            val ro = el as? JsonObject ?: continue
            val type = ro["type"]?.jsonPrimitive?.contentOrNull
            val value = ro["value"]?.jsonPrimitive?.contentOrNull ?: continue
            when (type) {
                "HOST" -> hostTarget(value)?.let { out += rule(Who.Global, it, action) } ?: r.skip("HOST $value")
                "IP" -> ipTarget(value)?.let { out += rule(Who.Global, it, action) } ?: r.skip("IP $value")
                "COUNTRY" -> if (value.length ==
                    2
                ) {
                    out += rule(Who.Global, Target(TargetKind.COUNTRY, value.lowercase()), action)
                } else {
                    r.skip("COUNTRY $value")
                }
                "APP" -> {
                    out += rule(Who.App(value), Target(TargetKind.ALL), action)
                    // per-app exceptions of the PCAPdroid blocklist
                    for (al in (ro["allowlist"] as? JsonArray) ?: JsonArray(emptyList())) {
                        val ao = al as? JsonObject ?: continue
                        val av = ao["value"]?.jsonPrimitive?.contentOrNull ?: continue
                        val t = when (ao["type"]?.jsonPrimitive?.contentOrNull) {
                            "HOST" -> hostTarget(av)
                            "IP" -> ipTarget(av)
                            else -> null
                        }
                        if (t != null) out += rule(Who.App(value), t, Action.ALLOW) else r.skip("allowlist $av")
                    }
                }
                else -> r.skip("$type $value")
            }
        }
        return out
    }

    // ------------------------------------------------------------------ NetGuard

    fun netguard(text: String, installed: List<App>): Plan {
        val r = Report()
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(text.byteInputStream())
        fun section(name: String): Map<String, String> {
            val m = LinkedHashMap<String, String>()
            val sec = doc.getElementsByTagName(name).item(0) as? Element ?: return m
            val list = sec.getElementsByTagName("setting")
            for (i in 0 until list.length) {
                val e = list.item(i) as Element
                m[e.getAttribute("key")] = e.getAttribute("value")
            }
            return m
        }
        val app = section("application")
        val wifi = section("wifi")
        val mobile = section("mobile")
        val defWifi = app["whitelist_wifi"]?.toBooleanStrictOrNull() ?: true
        val defMobile = app["whitelist_other"]?.toBooleanStrictOrNull() ?: true
        val manageSystem = app["manage_system"]?.toBooleanStrictOrNull() ?: false
        val sys = installed.associate { it.pkg to it.system }
        val rules = ArrayList<Rule>()
        val partial = ArrayList<String>()
        val pkgs = (wifi.keys + mobile.keys + if (defWifi || defMobile) installed.map { it.pkg } else emptyList()).toSortedSet()
        for (pkg in pkgs) {
            if (sys[pkg] == true && !manageSystem) continue
            val w = wifi[pkg]?.toBooleanStrictOrNull() ?: defWifi
            val m = mobile[pkg]?.toBooleanStrictOrNull() ?: defMobile
            when {
                w && m -> rules += rule(Who.App(pkg), Target(TargetKind.ALL), Action.BLOCK)
                w || m -> partial.add(pkg)
            }
        }
        if (partial.isNotEmpty()) {
            r.notes.add(Note(NoteKind.PARTIAL_NETWORK, partial.size))
            partial.take(10).forEach { r.skip("network-only block: $it") }
        }
        if (defWifi &&
            defMobile
        ) {
            r.notes.add(Note(NoteKind.NETGUARD_DEFAULT_BLOCK))
        }
        // per-address access rules
        val filters = doc.getElementsByTagName("rule")
        for (i in 0 until filters.length) {
            val e = filters.item(i) as Element
            val pkg = e.getAttribute("pkg")
            val addr = e.getAttribute("daddr").lowercase()
            val port = e.getAttribute("dport").toIntOrNull() ?: 0
            val proto = when (e.getAttribute("protocol")) {
                "6" -> Proto.TCP
                "17" -> Proto.UDP
                else -> Proto.ANY
            }
            val action = when (e.getAttribute("block")) {
                "1" -> Action.BLOCK
                "0" -> Action.ALLOW
                else -> null
            }
            val t = ipTarget(addr) ?: hostTarget(addr)
            if (pkg.isEmpty() || t == null || action == null) {
                r.skip("filter $pkg $addr:$port")
                continue
            }
            rules += rule(Who.App(pkg), t, action, proto, if (port in 1..65535) port else 0)
        }
        if (doc.getElementsByTagName("port").length > 0) r.notes.add(Note(NoteKind.NETGUARD_PORT_FORWARDING))
        return Plan(Format.NETGUARD, rules, skipped = r.skipped, samples = r.samples, notes = r.notes.toList())
    }

    // ------------------------------------------------------------------ AFWall+

    private const val AF_WIFI = 0
    private const val AF_DATA = 1

    fun afwall(text: String, installed: List<App>): Plan {
        val r = Report()
        val root = json.parseToJsonElement(text).jsonObject
        val v2 = root["v2"] as? JsonObject
        val mode = (v2?.get("mode") ?: root["mode"])?.jsonPrimitive?.contentOrNull ?: "whitelist"
        val whitelist = !mode.equals("blacklist", true)
        // package -> set of network type codes
        val listed = LinkedHashMap<String, MutableSet<Int>>()
        var anyApp: Set<Int>? = null
        val v2rules = (v2?.get("rules") as? JsonArray)
            ?: ((v2?.get("profiles") as? JsonArray)?.firstOrNull() as? JsonObject)?.get("rules") as? JsonArray
        if (v2rules != null) {
            for (el in v2rules) {
                val o = el as? JsonObject ?: continue
                val on = o["on"]?.jsonArray?.mapNotNull { it.jsonPrimitive.intOrNull }?.toSet() ?: continue
                if (o["special"]?.jsonPrimitive?.contentOrNull == "dev.afwall.special.any") {
                    anyApp = on
                    continue
                }
                val pkgs = o["packages"]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull }
                if (pkgs.isNullOrEmpty()) {
                    r.skip("special uid ${o["uid"]}")
                    continue
                }
                pkgs.forEach { listed.getOrPut(it) { HashSet() }.addAll(on) }
            }
        } else {
            val maps = (root["rules"] as? JsonArray)?.filterIsInstance<JsonObject>()
                ?: listOfNotNull(((root["default"] as? JsonObject)?.get("rules") as? JsonArray)?.firstOrNull() as? JsonObject)
            for (m in maps) {
                for ((pkg, v) in m) {
                    val codes =
                        (v as? JsonObject)?.filter {
                            it.value.jsonPrimitive.booleanOrNull == true
                        }?.keys?.mapNotNull { it.toIntOrNull() }?.toSet()
                            ?: continue
                    listed.getOrPut(pkg) { HashSet() }.addAll(codes)
                }
            }
        }
        val rules = ArrayList<Rule>()
        val partial = ArrayList<String>()
        fun both(s: Set<Int>?) = s != null && AF_WIFI in s && AF_DATA in s
        fun either(s: Set<Int>?) = s != null && (AF_WIFI in s || AF_DATA in s)
        if (!whitelist) {
            if (both(anyApp)) rules += rule(Who.Global, Target(TargetKind.ALL), Action.BLOCK)
            for ((pkg, s) in listed) {
                when {
                    both(s) -> rules += rule(Who.App(pkg), Target(TargetKind.ALL), Action.BLOCK)
                    either(s) -> partial.add(pkg)
                }
            }
        } else if (!both(anyApp)) {
            // allow-list mode: everything not listed for both networks is blocked
            r.notes.add(Note(NoteKind.AFWALL_ALLOWLIST))
            for (a in installed) {
                if (a.system) continue
                val s = listed[a.pkg]
                when {
                    both(s) -> {}
                    either(s) -> partial.add(a.pkg)
                    else -> rules += rule(Who.App(a.pkg), Target(TargetKind.ALL), Action.BLOCK)
                }
            }
        }
        if (partial.isNotEmpty()) {
            r.notes.add(Note(NoteKind.PARTIAL_NETWORK, partial.size))
            partial.take(10).forEach { r.skip("network-only: $it") }
        }
        r.notes.add(Note(NoteKind.AFWALL_COLUMNS))
        return Plan(Format.AFWALL, rules, skipped = r.skipped, samples = r.samples, notes = r.notes.toList())
    }

    // ------------------------------------------------------------------ sing-box

    fun singbox(bytes: ByteArray): Plan {
        if (bytes.size >= 3 && String(bytes, 0, 3, Charsets.ISO_8859_1) == "SRS") {
            throw Unsupported(Unsupported.Reason.SINGBOX_BINARY)
        }
        val r = Report()
        val root = json.parseToJsonElement(String(bytes, Charsets.UTF_8)).jsonObject
        val entries = LinkedHashSet<String>()
        fun strings(o: JsonObject, k: String): List<String> = when (val v = o[k]) {
            is JsonArray -> v.mapNotNull { it.jsonPrimitive.contentOrNull }
            is JsonPrimitive -> listOfNotNull(v.contentOrNull)
            else -> emptyList()
        }
        for (el in root["rules"]?.jsonArray ?: JsonArray(emptyList())) {
            val o = el as? JsonObject ?: continue
            if (o["type"]?.jsonPrimitive?.contentOrNull == "logical") {
                r.skip("logical rule")
                continue
            }
            strings(o, "domain").forEach { d ->
                if (ListParser.isDomain(d.lowercase())) entries.add("=${d.lowercase()}") else r.skip("domain $d")
            }
            strings(o, "domain_suffix").forEach { d0 ->
                val d = d0.lowercase()
                when {
                    d.startsWith(".") && ListParser.isDomain(d.drop(1)) -> entries.add("=**$d")
                    ListParser.isDomain(d) -> entries.add(d)
                    else -> r.skip("domain_suffix $d0")
                }
            }
            strings(o, "ip_cidr").forEach { c -> if (ListParser.isIp(c.lowercase())) entries.add(c.lowercase()) else r.skip("ip_cidr $c") }
            strings(o, "domain_keyword").forEach { r.skip("domain_keyword $it") }
            strings(o, "domain_regex").forEach { r.skip("domain_regex $it") }
            strings(o, "package_name").forEach { r.skip("package_name $it") }
        }
        if (r.skipped > 0) r.notes.add(Note(NoteKind.SINGBOX_NO_EQUIVALENT))
        return Plan(Format.SINGBOX, entries = entries.toList(), skipped = r.skipped, samples = r.samples, notes = r.notes.toList())
    }

    // ------------------------------------------------------------------ text lists (+ uBO $app=, $important)

    fun list(lines: Sequence<String>): Plan {
        val res = ListParser.parse(lines)
        val rules = res.appRules.flatMap { (pkgs, entry) ->
            val allow = entry.startsWith("!")
            val body = entry.removePrefix("!")
            val t = when {
                body.startsWith("=") -> Target(TargetKind.DOMAIN, body.removePrefix("="), false)
                ListParser.isIp(body) -> Target(TargetKind.IP, body)
                else -> Target(TargetKind.DOMAIN, body, true)
            }
            pkgs.map { rule(Who.App(it), t, if (allow) Action.ALLOW else Action.BLOCK) }
        }
        val notes = ArrayList<Note>()
        if (res.important.isNotEmpty()) notes.add(Note(NoteKind.LIST_IMPORTANT))
        if (rules.isNotEmpty()) notes.add(Note(NoteKind.LIST_APP_RULES))
        return Plan(Format.LIST, rules, res.entries, res.important, res.skipped, res.samples, notes)
    }

    // ------------------------------------------------------------------ RethinkDNS

    /** UID_EVERYBODY of RethinkDNS: universal rules. */
    private const val RETHINK_EVERYBODY = -1000

    /**
     * A RethinkDNS backup (.rbk, a zip with the Room database "bravedns.db"); the rows are read by
     * [RethinkReader] so this file stays free of Android APIs.
     */
    fun rethink(rows: RethinkRows, installed: List<App>): Plan {
        val r = Report()
        val byUid = installed.groupBy { it.uid }
        fun who(uid: Int): Who? = when {
            uid == RETHINK_EVERYBODY -> Who.Global
            uid < 0 -> null // deleted (tombstoned) rule
            else -> byUid[uid]?.firstOrNull()?.let { Who.App(it.pkg) }
        }
        val rules = ArrayList<Rule>()
        for (d in rows.domains) {
            val w = who(d.uid) ?: run {
                r.skip("domain ${d.domain} (uid ${d.uid})")
                null
            } ?: continue
            val action = when (d.status) {
                1 -> Action.BLOCK
                2 -> Action.ALLOW
                else -> null
            } ?: continue
            val t = hostTarget(d.domain) ?: run {
                r.skip("domain ${d.domain}")
                null
            } ?: continue
            rules += rule(w, if (d.wildcard || d.domain.startsWith("*.")) t else t.copy(subdomains = false), action)
        }
        for (i in rows.ips) {
            if (!i.active) continue
            val w = who(i.uid) ?: run {
                r.skip("ip ${i.ip} (uid ${i.uid})")
                null
            } ?: continue
            val action =
                when (i.status) {
                    1 -> Action.BLOCK
                    2 -> Action.ALLOW
                    else -> null
                }
                    ?: run {
                        r.skip("ip ${i.ip} status ${i.status}")
                        null
                    }
                    ?: continue
            val t = ipTarget(i.ip) ?: run {
                r.skip("ip ${i.ip}")
                null
            } ?: continue
            val proto = when (i.protocol.lowercase()) {
                "tcp", "6" -> Proto.TCP
                "udp", "17" -> Proto.UDP
                else -> Proto.ANY
            }
            rules += rule(w, t, action, proto, if (i.port in 1..65535) i.port else 0)
        }
        var partial = 0
        for (a in rows.apps) {
            val w = who(a.uid) as? Who.App ?: continue
            // FirewallStatus NONE(5) + ConnectionStatus BOTH(0) = the app is blocked
            when {
                a.firewallStatus == 5 && a.connectionStatus == 0 -> rules += rule(w, Target(TargetKind.ALL), Action.BLOCK)
                a.firewallStatus == 5 && (a.connectionStatus == 1 || a.connectionStatus == 2) -> partial++
                a.firewallStatus == 2 -> r.notes.add(Note(NoteKind.RETHINK_BYPASS))
                a.firewallStatus == 3 -> r.notes.add(Note(NoteKind.RETHINK_EXCLUDED))
                a.firewallStatus == 4 -> r.notes.add(Note(NoteKind.RETHINK_ISOLATED))
            }
        }
        if (partial > 0) r.notes.add(Note(NoteKind.PARTIAL_NETWORK, partial))
        return Plan(Format.RETHINK, rules, skipped = r.skipped, samples = r.samples, notes = r.notes.toList())
    }

    class RethinkRows(val domains: List<Domain>, val ips: List<Ip>, val apps: List<AppRow>) {
        class Domain(val domain: String, val uid: Int, val status: Int, val wildcard: Boolean)
        class Ip(val ip: String, val port: Int, val protocol: String, val uid: Int, val status: Int, val active: Boolean)
        class AppRow(val pkg: String, val uid: Int, val firewallStatus: Int, val connectionStatus: Int)
    }
}
