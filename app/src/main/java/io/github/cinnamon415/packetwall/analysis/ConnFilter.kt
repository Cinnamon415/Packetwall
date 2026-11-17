package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.engine.Conn

/**
 * Wireshark-like filter for the connection log.
 *
 *   app == "T-Bank" && blocked
 *   host ~ tracker || port == 853
 *   !(proto == DNS) && bytes > 10000
 *
 * Fields: app, pkg, uid, host, ip, port, proto, bytes, sent, rcvd, tracker; flags blocked, allowed, active, tracker.
 * Operators: == != ~ (contains) !~ < <= > >=, && || ! and parentheses; "and"/"or"/"not" work too.
 * Text comparisons ignore case. Input without any operator is a plain text search.
 */
object ConnFilter {
    /** [token]: the offending text, where the kind has one. Shown localized by the UI. */
    class ParseError(val kind: Kind, val token: String, val pos: Int) : Exception("$kind '$token' at $pos") {
        enum class Kind { UNEXPECTED, UNTERMINATED_STRING, UNEXPECTED_END, MISSING_PAREN, UNKNOWN_FIELD, EXPECTED_OPERATOR }
    }

    private sealed interface Node {
        fun eval(c: Conn): Boolean
    }
    private class And(val a: Node, val b: Node) : Node {
        override fun eval(c: Conn) = a.eval(c) && b.eval(c)
    }
    private class Or(val a: Node, val b: Node) : Node {
        override fun eval(c: Conn) = a.eval(c) || b.eval(c)
    }
    private class Not(val a: Node) : Node {
        override fun eval(c: Conn) = !a.eval(c)
    }
    private class Flag(val f: (Conn) -> Boolean) : Node {
        override fun eval(c: Conn) = f(c)
    }
    private class Cmp(val field: String, val op: String, val value: String) : Node {
        private val num = value.toLongOrNull()
        override fun eval(c: Conn): Boolean {
            val v = fieldValue(c, field)
            if (v is Long) {
                val n = num ?: return false
                return when (op) {
                    "==" -> v == n
                    "!=" -> v != n
                    "<" -> v < n
                    "<=" -> v <= n
                    ">" -> v > n
                    ">=" -> v >= n
                    "~" -> v.toString().contains(value)
                    "!~" -> !v.toString().contains(value)
                    else -> false
                }
            }
            val sv = (v as? String ?: "").lowercase()
            val x = value.lowercase()
            return when (op) {
                "==" -> sv == x
                "!=" -> sv != x
                "~" -> sv.contains(x)
                "!~" -> !sv.contains(x)
                "<" -> sv < x
                "<=" -> sv <= x
                ">" -> sv > x
                ">=" -> sv >= x
                else -> false
            }
        }
    }

    /** Tracker name of a host (set by the app when the tracker database is available). */
    @Volatile var trackerOf: (String?) -> String? = { null }

    val fields =
        listOf("app", "pkg", "uid", "host", "ip", "port", "proto", "bytes", "sent", "rcvd", "tracker", "blocked", "allowed", "active")
    private val flags = mapOf<String, (Conn) -> Boolean>(
        "blocked" to { it.blocked },
        "allowed" to { !it.blocked },
        "active" to { it.active },
        "tracker" to { (it.tracker ?: trackerOf(it.host)) != null }
    )

    private fun fieldValue(c: Conn, f: String): Any? = when (f) {
        "app" -> c.app.name
        "pkg" -> c.app.packageName
        "uid" -> c.uid.toLong()
        "host" -> c.host ?: ""
        "ip" -> c.dstIp
        "port" -> c.dstPort.toLong()
        "proto" -> c.protoLabel
        "bytes" -> c.bytes
        "sent" -> c.sentBytes
        "rcvd" -> c.rcvdBytes
        "tracker" -> c.tracker ?: trackerOf(c.host) ?: ""
        else -> null
    }

    /** Returns a predicate, or throws [ParseError]. Blank input matches everything. */
    fun compile(text: String): (Conn) -> Boolean {
        val t = text.trim()
        if (t.isEmpty()) return { true }
        if (!looksLikeExpression(t)) {
            val q = t.lowercase()
            return { c ->
                c.app.name.lowercase().contains(q) ||
                    c.title.lowercase().contains(q) ||
                    c.dstIp.contains(q) ||
                    c.app.packageName.contains(q) ||
                    c.protoLabel.lowercase() == q
            }
        }
        val p = Parser(tokenize(t))
        val n = p.parseOr()
        if (!p.done()) throw ParseError(ParseError.Kind.UNEXPECTED, p.peek()?.text ?: "", p.peek()?.pos ?: t.length)
        return n::eval
    }

    private fun looksLikeExpression(t: String): Boolean {
        val ops = listOf("==", "!=", "~", "&&", "||", "<", ">", "(", "!")
        if (ops.any { t.contains(it) }) return true
        val words = t.lowercase().split(Regex("\\s+"))
        return words.any { it in flags || it == "and" || it == "or" || it == "not" }
    }

    private data class Tok(val text: String, val pos: Int, val quoted: Boolean = false)

    private fun tokenize(s: String): List<Tok> {
        val out = ArrayList<Tok>()
        var i = 0
        while (i < s.length) {
            val ch = s[i]
            when {
                ch.isWhitespace() -> i++
                ch == '"' || ch == '\'' -> {
                    val end = s.indexOf(ch, i + 1)
                    if (end < 0) throw ParseError(ParseError.Kind.UNTERMINATED_STRING, "", i)
                    out.add(Tok(s.substring(i + 1, end), i, true))
                    i = end + 1
                }
                s.startsWith("&&", i) ||
                    s.startsWith("||", i) ||
                    s.startsWith("==", i) ||
                    s.startsWith("!=", i) ||
                    s.startsWith("<=", i) ||
                    s.startsWith(">=", i) ||
                    s.startsWith("!~", i) -> {
                    out.add(Tok(s.substring(i, i + 2), i))
                    i +=
                        2
                }
                ch in "()!<>~" -> {
                    out.add(Tok(ch.toString(), i))
                    i++
                }
                else -> {
                    val st = i
                    while (i < s.length && !s[i].isWhitespace() && s[i] !in "()!<>~=&|\"'") i++
                    if (i == st) throw ParseError(ParseError.Kind.UNEXPECTED, s[i].toString(), i)
                    out.add(Tok(s.substring(st, i), st))
                }
            }
        }
        return out
    }

    private class Parser(val toks: List<Tok>) {
        var i = 0
        fun peek() = toks.getOrNull(i)
        fun done() = i >= toks.size
        private fun next() = toks.getOrNull(i++) ?: throw ParseError(ParseError.Kind.UNEXPECTED_END, "", Int.MAX_VALUE)
        private fun isKw(t: Tok?, vararg k: String) = t != null && !t.quoted && k.any { it.equals(t.text, ignoreCase = true) }

        fun parseOr(): Node {
            var n = parseAnd()
            while (isKw(peek(), "||", "or")) {
                i++
                n = Or(n, parseAnd())
            }
            return n
        }

        fun parseAnd(): Node {
            var n = parseNot()
            while (isKw(peek(), "&&", "and")) {
                i++
                n = And(n, parseNot())
            }
            return n
        }

        fun parseNot(): Node {
            if (isKw(peek(), "!", "not")) {
                i++
                return Not(parseNot())
            }
            return parseAtom()
        }

        fun parseAtom(): Node {
            val t = next()
            if (!t.quoted && t.text == "(") {
                val n = parseOr()
                if (!isKw(peek(), ")")) throw ParseError(ParseError.Kind.MISSING_PAREN, "", peek()?.pos ?: Int.MAX_VALUE)
                i++
                return n
            }
            val name = t.text.lowercase()
            flags[name]?.let { if (!isKw(peek(), "==", "!=", "~", "!~", "<", "<=", ">", ">=")) return Flag(it) }
            if (name !in fields) throw ParseError(ParseError.Kind.UNKNOWN_FIELD, t.text, t.pos)
            val op = next()
            if (op.quoted ||
                op.text !in setOf("==", "!=", "~", "!~", "<", "<=", ">", ">=")
            ) {
                throw ParseError(ParseError.Kind.EXPECTED_OPERATOR, op.text, op.pos)
            }
            val v = next()
            return Cmp(name, op.text, v.text)
        }
    }
}
