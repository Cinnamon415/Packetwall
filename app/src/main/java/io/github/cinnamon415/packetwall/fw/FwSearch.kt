package io.github.cinnamon415.packetwall.fw

/**
 * "Where is this rule": finds rules and list entries for a word, a domain or an address.
 *
 * A domain query also finds what would match it: "ads.example.com" finds a rule for
 * "example.com" with subdomains and the list entry "example.com".
 */
object FwSearch {
    /** A rule and where it lives: whose it is, its set, and the profiles that have that set on. */
    data class RuleHit(val rule: Rule, val setName: String, val setOn: Boolean, val profiles: List<String>)

    /** Entries of one list that match, with a few examples. */
    data class ListHit(val setId: Int, val name: String, val count: Int, val examples: List<String>)

    fun needle(q: String) = q.trim().lowercase().removeSuffix(".")

    /** The parent domains of [d], itself first: a.b.c → a.b.c, b.c, c. */
    fun parents(d: String): List<String> {
        if (d.isEmpty() || d.any { it == ' ' || it == '/' }) return emptyList()
        val out = ArrayList<String>()
        var s = d
        while (true) {
            out.add(s)
            val i = s.indexOf('.')
            if (i < 0) break
            s = s.substring(i + 1)
        }
        return out
    }

    /**
     * Rules whose target, owner or set contains [q], plus domain rules that would match [q].
     * [whoName] gives the shown name of an app or group owner (for the text match).
     */
    fun rules(st: FwState, q: String, whoName: (Who) -> String): List<RuleHit> {
        val n = needle(q)
        if (n.isEmpty()) return emptyList()
        val up = parents(n).drop(1).toHashSet()
        return st.rules.filter { r ->
            val v = r.target.value.lowercase()
            v.contains(n) ||
                (r.target.kind == TargetKind.DOMAIN && r.target.subdomains && v in up) ||
                (r.who != Who.Global && whoName(r.who).lowercase().contains(n)) ||
                (r.who as? Who.App)?.pkg?.contains(n) == true
        }.sortedWith(compareBy({ st.order.indexOfFirst { o -> o.id == it.setId } }, { it.target.value }))
            .map { r ->
                RuleHit(
                    r,
                    st.set(r.setId)?.name ?: "",
                    st.isEnabled(r.setId),
                    st.profiles.filter { p -> p.sets.any { it.id == r.setId && it.enabled } }.map { it.name }
                )
            }
    }

    /**
     * Matching entries of one list. An entry matches when it contains [q] or is a parent
     * domain of it (lists block subdomains). "!" (an exception) and "*." are ignored for the match.
     */
    fun listEntries(lines: Sequence<String>, q: String, examples: Int = 3): Pair<Int, List<String>> {
        val n = needle(q)
        if (n.isEmpty()) return 0 to emptyList()
        val up = parents(n).toHashSet()
        var count = 0
        val ex = ArrayList<String>(examples)
        for (line in lines) {
            val body = line.removePrefix("!").removePrefix("*.")
            if (line.contains(n) || body in up) {
                count++
                if (ex.size < examples) ex.add(line)
            }
        }
        return count to ex
    }
}
