package io.github.cinnamon415.packetwall.analysis

import java.net.InetAddress

/**
 * A small protocol dissector for the packet screen: IPv4/IPv6, TCP/UDP/ICMP, DNS, TLS handshake
 * (SNI/ALPN), HTTP/1.x and the QUIC long header. Every field knows its byte range, so the hex view
 * can highlight it.
 */
object Dissector {
    class Field(val name: String, val value: String, val start: Int, val len: Int, val children: List<Field> = emptyList())

    class Summary(
        val proto: String, // top protocol: TCP, UDP, DNS, TLS, HTTP, QUIC, ICMP
        val info: String, // "SYN", "Client Hello · example.com", "A? example.com"…
        val tcpSeq: Long? = null,
        val tcpAck: Long? = null,
        val tcpFlags: Int = 0,
        val payloadOff: Int = 0, // offset of the L7 payload inside the packet
        val payloadLen: Int = 0
    )

    private class R(val b: ByteArray, val base: Int, val end: Int) {
        fun u8(o: Int) = if (o < end) b[o].toInt() and 0xff else 0
        fun u16(o: Int) = (u8(o) shl 8) or u8(o + 1)
        fun u32(o: Int) = (u16(o).toLong() shl 16) or u16(o + 2).toLong()
        fun has(o: Int, n: Int) = o + n <= end
    }

    // ------------------------------------------------------------------ summary (list rows)

    fun summary(b: ByteArray, off: Int, len: Int): Summary {
        val r = R(b, off, off + len)
        val ver = r.u8(off) shr 4
        val (proto, l4, l4end) = when (ver) {
            4 -> Triple(r.u8(off + 9), off + (r.u8(off) and 0xf) * 4, minOf(off + len, off + r.u16(off + 2)))
            6 -> Triple(r.u8(off + 6), off + 40, off + len)
            else -> return Summary("IP", "?")
        }
        when (proto) {
            6 -> {
                if (!r.has(l4, 20)) return Summary("TCP", "")
                val sp = r.u16(l4)
                val dp = r.u16(l4 + 2)
                val seq = r.u32(l4 + 4)
                val ack = r.u32(l4 + 8)
                val hl = (r.u8(l4 + 12) shr 4) * 4
                val flags = r.u8(l4 + 13)
                val po = l4 + hl
                val pl = maxOf(0, l4end - po)
                val fl = tcpFlags(flags)
                if (pl > 0) {
                    app(r, po, pl, sp, dp, tcp = true)?.let { (p, i) -> return Summary(p, i, seq, ack, flags, po - off, pl) }
                    return Summary("TCP", "$fl · $pl B", seq, ack, flags, po - off, pl)
                }
                return Summary("TCP", fl, seq, ack, flags, po - off, 0)
            }
            17 -> {
                if (!r.has(l4, 8)) return Summary("UDP", "")
                val sp = r.u16(l4)
                val dp = r.u16(l4 + 2)
                val po = l4 + 8
                val pl = maxOf(0, minOf(l4end, l4 + r.u16(l4 + 4)) - po)
                app(r, po, pl, sp, dp, tcp = false)?.let { (p, i) -> return Summary(p, i, payloadOff = po - off, payloadLen = pl) }
                return Summary("UDP", "$pl B", payloadOff = po - off, payloadLen = pl)
            }
            1, 58 -> return Summary("ICMP", icmpType(r.u8(l4), proto == 58))
            else -> return Summary("IP/$proto", "")
        }
    }

    private fun app(r: R, po: Int, pl: Int, sp: Int, dp: Int, tcp: Boolean): Pair<String, String>? {
        if (pl <= 0) return null
        if (sp == 53 || dp == 53) {
            val o = if (tcp) po + 2 else po
            return "DNS" to dnsInfo(r, o)
        }
        if (tcp && r.u8(po) in 0x14..0x17 && r.u8(po + 1) == 3) return "TLS" to tlsInfo(r, po, pl)
        if (tcp) {
            val head = String(r.b, po, minOf(pl, 64), Charsets.ISO_8859_1)
            if (head.startsWith("HTTP/")) return "HTTP" to head.substringBefore("\r").take(48)
            if (methods.any { head.startsWith("$it ") }) {
                val line = String(r.b, po, minOf(pl, 200), Charsets.ISO_8859_1).substringBefore("\r")
                return "HTTP" to line.substringBeforeLast(" HTTP/")
            }
        }
        if (!tcp &&
            (sp == 443 || dp == 443) &&
            (r.u8(po) and 0x80) != 0
        ) {
            return "QUIC" to "Initial/Handshake, v${"%08x".format(r.u32(po + 1))}"
        }
        if (!tcp && (sp == 443 || dp == 443)) return "QUIC" to "short header · $pl B"
        return null
    }

    private val methods = listOf("GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT")

    fun tcpFlags(f: Int): String = buildList {
        if (f and 0x02 != 0) add("SYN")
        if (f and 0x10 != 0) add("ACK")
        if (f and 0x08 != 0) add("PSH")
        if (f and 0x01 != 0) add("FIN")
        if (f and 0x04 != 0) add("RST")
        if (f and 0x20 != 0) add("URG")
    }.joinToString(",").ifEmpty { "-" }

    private fun icmpType(t: Int, v6: Boolean) = if (v6) {
        when (t) {
            128 -> "Echo request"
            129 -> "Echo reply"
            1 -> "Unreachable"
            else -> "type $t"
        }
    } else {
        when (t) {
            8 -> "Echo request"
            0 -> "Echo reply"
            3 -> "Unreachable"
            11 -> "Time exceeded"
            else -> "type $t"
        }
    }

    private val dnsTypes = mapOf(
        1 to "A", 2 to "NS", 5 to "CNAME", 6 to "SOA", 12 to "PTR", 15 to "MX", 16 to "TXT",
        28 to "AAAA", 33 to "SRV", 65 to "HTTPS", 64 to "SVCB"
    )

    private fun dnsName(r: R, start: Int, msg: Int): Pair<String, Int> {
        val parts = ArrayList<String>()
        var o = start
        var next = -1
        var jumps = 0
        while (r.has(o, 1) && jumps < 20) {
            val l = r.u8(o)
            if (l == 0) {
                o++
                break
            }
            if (l and 0xc0 == 0xc0) {
                if (next < 0) next = o + 2
                o = msg + (((l and 0x3f) shl 8) or r.u8(o + 1))
                jumps++
                continue
            }
            if (!r.has(o + 1, l)) break
            parts.add(String(r.b, o + 1, l, Charsets.ISO_8859_1))
            o += 1 + l
        }
        return parts.joinToString(".") to (if (next >= 0) next else o)
    }

    private fun dnsInfo(r: R, m: Int): String {
        if (!r.has(m, 12)) return ""
        val flags = r.u16(m + 2)
        val qd = r.u16(m + 4)
        val an = r.u16(m + 6)
        val resp = flags and 0x8000 != 0
        var o = m + 12
        var q = ""
        var qt = ""
        if (qd > 0) {
            val (n, e) = dnsName(r, o, m)
            q = n
            qt = dnsTypes[r.u16(e)] ?: "type ${r.u16(e)}"
            o = e + 4
        }
        if (!resp) return "$qt? $q"
        val rcode = flags and 0xf
        if (rcode == 3) return "$qt $q → NXDOMAIN"
        val answers = ArrayList<String>()
        repeat(an) {
            if (!r.has(o, 10)) return@repeat
            val (_, e) = dnsName(r, o, m)
            val t = r.u16(e)
            val rl = r.u16(e + 8)
            val d = e + 10
            when {
                t == 1 && rl == 4 -> answers.add(ip(r.b, d, 4))
                t == 28 && rl == 16 -> answers.add(ip(r.b, d, 16))
                t == 5 -> answers.add(dnsName(r, d, m).first)
            }
            o = d + rl
        }
        return "$qt $q → ${answers.take(3).joinToString(", ").ifEmpty { "∅" }}"
    }

    /** SNI and ALPN of a ClientHello, if present (parsed by [TlsInfo]). */
    fun clientHello(b: ByteArray, off: Int, len: Int): Pair<String?, List<String>>? {
        if (len < 6 || b[off].toInt() != 0x16) return null
        return TlsInfo.client(b.copyOfRange(off, minOf(off + len, b.size)))?.let { it.sni to it.alpn }
    }

    private fun tlsInfo(r: R, po: Int, pl: Int): String {
        val ct = r.u8(po)
        return when (ct) {
            0x16 -> when (r.u8(po + 5)) {
                1 -> "Client Hello" + (clientHello(r.b, po, pl)?.first?.let { " · $it" } ?: "")
                2 -> "Server Hello"
                11 -> "Certificate"
                else -> "Handshake"
            }
            0x17 -> "Application Data · $pl B"
            0x15 -> "Alert"
            0x14 -> "Change Cipher Spec"
            else -> "TLS"
        }
    }

    private fun ip(b: ByteArray, o: Int, n: Int): String = try {
        InetAddress.getByAddress(b.copyOfRange(o, o + n)).hostAddress ?: ""
    } catch (e: Exception) {
        "?"
    }

    // ------------------------------------------------------------------ full tree (packet screen)

    /** Field offsets are relative to [off]. */
    fun tree(b: ByteArray, off: Int, len: Int): List<Field> {
        val r = R(b, off, off + len)
        val out = ArrayList<Field>()
        fun f(name: String, value: String, s: Int, l: Int, ch: List<Field> = emptyList()) = Field(name, value, s - off, l, ch)
        val ver = r.u8(off) shr 4
        val proto: Int
        val l4: Int
        val l4end: Int
        if (ver == 4) {
            val ihl = (r.u8(off) and 0xf) * 4
            proto = r.u8(off + 9)
            l4 = off + ihl
            l4end = minOf(off + len, off + r.u16(off + 2))
            out.add(
                f(
                    "IPv4",
                    "${ip(b, off + 12, 4)} → ${ip(b, off + 16, 4)}",
                    off,
                    ihl,
                    listOf(
                        f("Version / IHL", "4 / $ihl", off, 1),
                        f("Total length", "${r.u16(off + 2)}", off + 2, 2),
                        f("Identification", "0x%04x".format(r.u16(off + 4)), off + 4, 2),
                        f("Flags / fragment", "0x%04x".format(r.u16(off + 6)), off + 6, 2),
                        f("TTL", "${r.u8(off + 8)}", off + 8, 1),
                        f("Protocol", "$proto", off + 9, 1),
                        f("Checksum", "0x%04x".format(r.u16(off + 10)), off + 10, 2),
                        f("Source", ip(b, off + 12, 4), off + 12, 4),
                        f("Destination", ip(b, off + 16, 4), off + 16, 4)
                    )
                )
            )
        } else if (ver == 6) {
            proto = r.u8(off + 6)
            l4 = off + 40
            l4end = off + len
            out.add(
                f(
                    "IPv6",
                    "${ip(b, off + 8, 16)} → ${ip(b, off + 24, 16)}",
                    off,
                    40,
                    listOf(
                        f("Payload length", "${r.u16(off + 4)}", off + 4, 2),
                        f("Next header", "$proto", off + 6, 1),
                        f("Hop limit", "${r.u8(off + 7)}", off + 7, 1),
                        f("Source", ip(b, off + 8, 16), off + 8, 16),
                        f("Destination", ip(b, off + 24, 16), off + 24, 16)
                    )
                )
            )
        } else {
            return listOf(f("Data", "$len B", off, len))
        }

        when (proto) {
            6 -> if (r.has(l4, 20)) {
                val hl = (r.u8(l4 + 12) shr 4) * 4
                val flags = r.u8(l4 + 13)
                out.add(
                    f(
                        "TCP",
                        "${r.u16(l4)} → ${r.u16(l4 + 2)} [${tcpFlags(flags)}]",
                        l4,
                        hl,
                        listOf(
                            f("Source port", "${r.u16(l4)}", l4, 2),
                            f("Destination port", "${r.u16(l4 + 2)}", l4 + 2, 2),
                            f("Sequence", "${r.u32(l4 + 4)}", l4 + 4, 4),
                            f("Acknowledgment", "${r.u32(l4 + 8)}", l4 + 8, 4),
                            f("Header length", "$hl", l4 + 12, 1),
                            f("Flags", "0x%02x ${tcpFlags(flags)}".format(flags), l4 + 13, 1),
                            f("Window", "${r.u16(l4 + 14)}", l4 + 14, 2),
                            f("Checksum", "0x%04x".format(r.u16(l4 + 16)), l4 + 16, 2)
                        ) + if (hl > 20) listOf(f("Options", "${hl - 20} B", l4 + 20, hl - 20)) else emptyList()
                    )
                )
                appTree(r, l4 + hl, maxOf(0, l4end - l4 - hl), r.u16(l4), r.u16(l4 + 2), true, out, ::f)
            }
            17 -> if (r.has(l4, 8)) {
                out.add(
                    f(
                        "UDP",
                        "${r.u16(l4)} → ${r.u16(l4 + 2)}",
                        l4,
                        8,
                        listOf(
                            f("Source port", "${r.u16(l4)}", l4, 2),
                            f("Destination port", "${r.u16(l4 + 2)}", l4 + 2, 2),
                            f("Length", "${r.u16(l4 + 4)}", l4 + 4, 2),
                            f("Checksum", "0x%04x".format(r.u16(l4 + 6)), l4 + 6, 2)
                        )
                    )
                )
                appTree(r, l4 + 8, maxOf(0, minOf(l4end, l4 + r.u16(l4 + 4)) - l4 - 8), r.u16(l4), r.u16(l4 + 2), false, out, ::f)
            }
            1, 58 -> if (r.has(l4, 4)) {
                out.add(
                    f(
                        if (proto ==
                            58
                        ) {
                            "ICMPv6"
                        } else {
                            "ICMP"
                        },
                        icmpType(r.u8(l4), proto == 58),
                        l4,
                        l4end - l4,
                        listOf(
                            f("Type", "${r.u8(l4)}", l4, 1),
                            f("Code", "${r.u8(l4 + 1)}", l4 + 1, 1),
                            f("Checksum", "0x%04x".format(r.u16(l4 + 2)), l4 + 2, 2)
                        )
                    )
                )
            }
        }
        return out
    }

    private fun appTree(
        r: R,
        po: Int,
        pl: Int,
        sp: Int,
        dp: Int,
        tcp: Boolean,
        out: MutableList<Field>,
        f: (String, String, Int, Int, List<Field>) -> Field
    ) {
        if (pl <= 0) return
        val s = summary0(r, po, pl, sp, dp, tcp)
        if (s == null) {
            out.add(f("Data", "$pl B", po, pl, emptyList()))
            return
        }
        val children = ArrayList<Field>()
        when (s.first) {
            "DNS" -> {
                val m = if (tcp) po + 2 else po
                children.add(f("Transaction ID", "0x%04x".format(r.u16(m)), m, 2, emptyList()))
                children.add(
                    f(
                        "Flags",
                        "0x%04x".format(r.u16(m + 2)) + if (r.u16(m + 2) and 0x8000 !=
                            0
                        ) {
                            " response"
                        } else {
                            " query"
                        },
                        m + 2,
                        2,
                        emptyList()
                    )
                )
                children.add(f("Questions / answers", "${r.u16(m + 4)} / ${r.u16(m + 6)}", m + 4, 4, emptyList()))
            }
            "TLS" -> {
                children.add(f("Content type", "${r.u8(po)}", po, 1, emptyList()))
                children.add(f("Version", "0x%04x".format(r.u16(po + 1)), po + 1, 2, emptyList()))
                children.add(f("Length", "${r.u16(po + 3)}", po + 3, 2, emptyList()))
                clientHello(r.b, po, pl)?.let { (sni, alpn) ->
                    sni?.let { children.add(f("SNI", it, po, 0, emptyList())) }
                    if (alpn.isNotEmpty()) children.add(f("ALPN", alpn.joinToString(", "), po, 0, emptyList()))
                }
            }
            "HTTP" -> {
                val text = String(r.b, po, minOf(pl, 2048), Charsets.ISO_8859_1)
                var o = po
                text.split("\r\n").takeWhile { it.isNotEmpty() }.take(30).forEachIndexed { i, line ->
                    if (i == 0 || !line.contains(':')) {
                        children.add(f(line.take(80), "", o, line.length, emptyList()))
                    } else {
                        children.add(f(line.substringBefore(":").take(40), line.substringAfter(":").trim(), o, line.length, emptyList()))
                    }
                    o += line.length + 2
                }
            }
        }
        out.add(f(s.first, s.second, po, pl, children))
    }

    private fun summary0(r: R, po: Int, pl: Int, sp: Int, dp: Int, tcp: Boolean) = app(r, po, pl, sp, dp, tcp)
}
