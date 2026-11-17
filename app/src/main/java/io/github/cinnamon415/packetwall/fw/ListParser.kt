package io.github.cinnamon415.packetwall.fw

/**
 * Converts third-party block lists into the normalized list format read by the native engine
 * (see pw_rules.c): one entry per line, "!" = opposite action (allow), "=" = exact host,
 * otherwise the domain and its subdomains. IP / CIDR entries are kept as they are.
 *
 * Supported input, detected per line: hosts files, plain domain lists, AdBlock / uBO / AdGuard
 * network rules, dnsmasq, IP / CIDR lists. Everything else ends up in the report.
 */
object ListParser {
    data class Result(
        val entries: List<String>,
        val skipped: Int,
        val samples: List<String>,
        val comments: Int,
        /** "$important" entries: they must beat the list's own exceptions. */
        val important: List<String> = emptyList(),
        /** "$app=pkg1|pkg2" entries: (packages, entry). */
        val appRules: List<Pair<List<String>, String>> = emptyList()
    )

    /** An AdBlock network rule split into its parts. */
    private class Adb(val entry: String, val apps: List<String>?, val important: Boolean)

    private val domainRe = Regex("^(\\*\\*?\\.)?([a-z0-9_*]([a-z0-9_*-]*[a-z0-9_*])?\\.)+[a-z0-9_*-]{2,}$")
    private val ipv4Re = Regex("^\\d{1,3}(\\.\\d{1,3}){3}(/\\d{1,2})?$")
    private val ipv6Re = Regex("^[0-9a-f:]+:[0-9a-f:.]*(/\\d{1,3})?$")
    private val hostsIps = setOf("0.0.0.0", "127.0.0.1", "::", "::1", "0", "::0")
    private val hostsIgnore = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
        "ip6-allrouters", "ip6-allhosts", "0.0.0.0"
    )

    /** AdBlock options that do not change the meaning for a DNS/IP firewall. */
    private val harmlessOptions = setOf(
        "important", "all", "document", "doc", "third-party", "3p",
        "first-party", "1p", "popup", "network", "~third-party"
    )

    fun isDomain(s: String) = domainRe.matches(s)
    private val asnRe = Regex("^(as)?\\d{1,10}$", RegexOption.IGNORE_CASE)
    fun isAsn(s: String) = asnRe.matches(s.trim())
    fun asnNumber(s: String): Long? = s.trim().lowercase().removePrefix("as").toLongOrNull()
    fun isIp(s: String) = ipv4Re.matches(s) || (s.contains(':') && ipv6Re.matches(s))

    fun parse(lines: Sequence<String>): Result {
        val out = LinkedHashSet<String>()
        val important = LinkedHashSet<String>()
        val appRules = ArrayList<Pair<List<String>, String>>()
        var skipped = 0
        var comments = 0
        val samples = ArrayList<String>()

        fun skip(line: String) {
            skipped++
            if (samples.size < 30) samples.add(line.take(200))
        }

        for (raw in lines) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            if (line.startsWith("#") || line.startsWith("!") || line.startsWith("[")) {
                comments++
                continue
            }
            val low = line.lowercase()
            if (low.startsWith("||") || low.startsWith("@@") || low.startsWith("|")) {
                val a = adblockParsed(low.substringBefore(" #").trim())
                when {
                    a == null -> skip(line)
                    a.apps != null -> appRules.add(a.apps to a.entry)
                    a.important -> important.add(a.entry)
                    else -> out.add(a.entry)
                }
                continue
            }
            val e = convert(line)
            when {
                e == null -> skip(line)
                e.isEmpty() -> comments++ // intentionally ignored (localhost entries…)
                else -> out.add(e)
            }
        }
        out.removeAll(important)
        return Result(out.toList(), skipped, samples, comments, important.toList(), appRules)
    }

    /** null = unsupported, "" = ignore silently, else a normalized entry. */
    fun convert(line: String): String? {
        val l = line.substringBefore(" #").trim().lowercase()

        // AdBlock / uBO / AdGuard
        if (l.startsWith("||") || l.startsWith("@@") || l.startsWith("|")) return adblock(l)
        if (l.contains("##") || l.contains("#@#") || l.contains("#?#") || l.contains("#$#")) return null

        // dnsmasq: address=/example.com/0.0.0.0, server=/example.com/
        if (l.startsWith("address=/") || l.startsWith("server=/") || l.startsWith("local=/")) {
            val d = l.substringAfter("=/").substringBefore('/')
            return if (isDomain(d)) d else null
        }

        val parts = l.split(Regex("\\s+"))
        // hosts: "0.0.0.0 a.com b.com"
        if (parts.size >= 2 && (parts[0] in hostsIps || isIp(parts[0]))) {
            val names = parts.drop(1).filter { it !in hostsIgnore }
            if (names.isEmpty()) return ""
            // a hosts line may list several names: keep the first, the others are rare
            val d = names[0]
            return if (isDomain(d)) "=$d" else null
        }
        if (parts.size != 1) return null

        val t = parts[0]
        if (isIp(t)) return t
        if (t in hostsIgnore) return ""
        // "*.example.com" in a plain list = subdomains only
        if (t.startsWith("*.") && isDomain(t.removePrefix("*."))) return "=**.${t.removePrefix("*.")}"
        if (t.startsWith(".") && isDomain(t.removePrefix("."))) return t.removePrefix(".")
        return if (isDomain(t)) t else null
    }

    private fun adblock(l: String): String? = adblockParsed(l)?.takeIf { it.apps == null }?.entry

    private fun adblockParsed(l: String): Adb? {
        var s = l
        var allow = false
        if (s.startsWith("@@")) {
            allow = true
            s = s.removePrefix("@@")
        }

        val opts = s.substringAfter('$', "")
        s = s.substringBefore('$')
        var apps: List<String>? = null
        var important = false
        if (opts.isNotEmpty()) {
            for (o in opts.split(',')) {
                val name = o.substringBefore('=')
                when {
                    name == "app" -> {
                        val v = o.substringAfter('=', "").split('|').filter { it.isNotBlank() }
                        if (v.isEmpty() || v.any { it.startsWith("~") }) return null // negated app lists: no equivalent
                        apps = v
                    }
                    name == "important" -> important = true
                    name !in harmlessOptions -> return null // $denyallow=, $client=, $dnstype=…
                }
            }
        }

        val sub: Boolean
        when {
            s.startsWith("||") -> {
                sub = true
                s = s.removePrefix("||")
            }
            s.startsWith("|http://") || s.startsWith("|https://") -> {
                sub = false
                s = s.removePrefix("|").substringAfter("://")
                if (s.substringAfter('/', "").isNotEmpty()) return null // URL path: not a host rule
                s = s.substringBefore('/')
            }
            else -> return null
        }
        s = s.removeSuffix("|").removeSuffix("^").removeSuffix("/").removeSuffix("^")
        if (s.contains('/') || s.contains('^') || s.contains('|')) return null

        // "||*.example.com^" -> subdomains only
        val body = when {
            s.startsWith("*.") && isDomain(s.removePrefix("*.")) -> "=**.${s.removePrefix("*.")}"
            isIp(s) -> s
            isDomain(s) -> if (sub) s else "=$s"
            else -> return null
        }
        return Adb(if (allow) "!$body" else body, apps, important)
    }

    /** Domain of the entry, without the flags (for search/preview). */
    fun displayOf(entry: String) = entry.removePrefix("!").removePrefix("=")

    /** "a.b.example.co.uk" -> "example.co.uk" (simple heuristic, no public suffix list). */
    fun baseDomain(host: String): String {
        val labels = host.trimEnd('.').split('.')
        if (labels.size <= 2) return host
        val tld = labels.last()
        val sld = labels[labels.size - 2]
        val keep = if (tld.length == 2 && sld.length <= 3 && sld in commonSlds) 3 else 2
        return labels.takeLast(keep).joinToString(".")
    }

    private val commonSlds = setOf("co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "msk", "spb")
}
