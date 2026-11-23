package io.github.cinnamon415.packetwall.fw

import java.net.InetAddress

/**
 * The decision order of the native engine (pw_rules.c), for the UI: will a new rule actually
 * change the decision? Keep in sync with domain_score / final_score / better() there.
 *
 * Sets are checked by priority; in a set the app's rules come first, then its groups', then global
 * ones; at one level the narrowest target wins, and on a tie block wins.
 */
object RuleScore {
    fun domainScore(pattern: String, subs: Boolean): Int {
        var literal = 0
        var anyWild = false
        var deep = false
        for (label in pattern.split('.')) {
            if ('*' !in label) {
                literal++
            } else {
                anyWild = true
                if (label == "**") deep = true
            }
        }
        var s = 1000 + literal * 10
        if (!deep && !subs) s += 4
        if (!anyWild && !subs) {
            s += 3
        } else if (!anyWild && subs) {
            s += 2
        }
        return s
    }

    fun score(r: Rule): Int {
        val t = r.target
        val base = when (t.kind) {
            TargetKind.ALL -> 0
            TargetKind.COUNTRY -> 100
            TargetKind.ASN -> 200
            TargetKind.IP -> {
                val (v6, prefix) = prefixOf(t.value)
                300 + (prefix * 100) / (if (v6) 128 else 32)
            }
            TargetKind.DOMAIN -> domainScore(t.value.lowercase(), t.subdomains)
        }
        return base * 4 + (if (r.port != 0) 2 else 0) + (if (r.proto != Proto.ANY) 1 else 0)
    }

    fun whoLevel(w: Who) = when (w) {
        Who.Global -> 0
        is Who.Group -> 1
        is Who.App -> 2
    }

    /**
     * Whether [allow] would beat the [block] decision for the same connection. [blockSet] is the
     * set that decided (a blocklist when [block] is null).
     */
    fun allowWins(st: FwState, allow: Rule, block: Rule?, blockSet: Int): Boolean {
        if (!st.isEnabled(allow.setId)) return false
        // a global allow never lifts an app's or group's block, in whatever set (spec 2.5.4)
        if (block != null && whoLevel(allow.who) == 0 && whoLevel(block.who) > 0) return false
        val pa = st.order.indexOfFirst { it.id == allow.setId }
        val pb = st.order.indexOfFirst { it.id == blockSet }
        if (pa != pb) return pb < 0 || pa < pb
        if (block == null) return true
        val la = whoLevel(allow.who)
        val lb = whoLevel(block.who)
        if (la != lb) return la > lb
        return score(allow) > score(block)
    }

    /** "1.2.3.4" → "1.2.3.0/24"; IPv6 → its /64. Null if [ip] is not an address. */
    fun subnet(ip: String): String? {
        if (!ListParser.isIp(ip) || '/' in ip) return null
        val a = runCatching { InetAddress.getByName(ip) }.getOrNull() ?: return null
        val b = a.address
        val keep = if (b.size == 4) 3 else 8
        for (i in keep until b.size) b[i] = 0
        val net = InetAddress.getByAddress(b).hostAddress ?: return null
        return "$net/${keep * 8}"
    }

    private fun prefixOf(v: String): Pair<Boolean, Int> {
        val v6 = ':' in v
        val p = v.substringAfter('/', "").toIntOrNull()
        return v6 to (p ?: if (v6) 128 else 32)
    }
}
