package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.BadDataException
import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.engine.Conn
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Reads a pcap or pcapng file (Wireshark, tcpdump, PCAPdroid, Packetwall's own recordings) into a
 * [PacketStore] and groups the packets into connections, so the usual connection and packet views
 * can show it. Link types: raw IP, IPv4/IPv6, Ethernet (VLAN tags skipped), Linux cooked v1/v2, BSD
 * loopback. Other link types and non-IP frames are counted in [Result.skipped].
 */
object CaptureFile {
    class Result(val store: PacketStore, val conns: List<Conn>, val packets: Int, val skipped: Int)

    private const val LINK_NULL = 0
    private const val LINK_ETHERNET = 1
    private const val LINK_RAW = 101
    private const val LINK_SLL = 113
    private const val LINK_IPV4 = 228
    private const val LINK_IPV6 = 229
    private const val LINK_SLL2 = 276

    /** [bytes] is the whole file; [appOf] names the app of a uid found in Packetwall's own comments. */
    fun read(bytes: ByteArray, appOf: (Int) -> AppInfo?): Result {
        if (bytes.size < 24) throw BadDataException("not a capture file")
        val store = PacketStore()
        store.reset(Long.MAX_VALUE / 4)
        val flows = FlowBuilder(appOf)
        var skipped = 0
        val add: (Long, Int, ByteArray, Int, Int, Int, Int, Boolean) -> Unit = { ts, link, frame, off, len, origLen, uid, dropped ->
            val ip = ipPayload(link, frame, off, len)
            if (ip == null) {
                skipped++
            } else {
                flows.add(store, ts, frame.copyOfRange(ip, off + len), origLen - (ip - off), uid, dropped)
            }
        }
        val magic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.BIG_ENDIAN).int
        when (magic) {
            0x0A0D0D0A -> readPcapng(bytes, add)
            0xA1B2C3D4.toInt(), 0xA1B23C4D.toInt() -> readPcap(bytes, ByteOrder.BIG_ENDIAN, magic == 0xA1B23C4D.toInt(), add)
            0xD4C3B2A1.toInt(), 0x4D3CB2A1 -> readPcap(bytes, ByteOrder.LITTLE_ENDIAN, magic == 0x4D3CB2A1, add)
            else -> throw BadDataException("not a pcap or pcapng file")
        }
        return Result(store, flows.conns(), store.info.value.packets, skipped)
    }

    private fun readPcap(b: ByteArray, order: ByteOrder, nanos: Boolean, add: (Long, Int, ByteArray, Int, Int, Int, Int, Boolean) -> Unit) {
        val bb = ByteBuffer.wrap(b).order(order)
        val link = bb.getInt(20) and 0x0fffffff
        var pos = 24
        while (pos + 16 <= b.size) {
            val sec = bb.getInt(pos).toLong() and 0xffffffffL
            val frac = bb.getInt(pos + 4).toLong() and 0xffffffffL
            val incl = bb.getInt(pos + 8)
            val orig = bb.getInt(pos + 12)
            pos += 16
            if (incl < 0 || pos + incl > b.size) break
            add(sec * 1_000_000 + if (nanos) frac / 1000 else frac, link, b, pos, incl, orig, -1, false)
            pos += incl
        }
    }

    private fun readPcapng(b: ByteArray, add: (Long, Int, ByteArray, Int, Int, Int, Int, Boolean) -> Unit) {
        var order = ByteOrder.LITTLE_ENDIAN
        val links = ArrayList<Int>()
        val tsres = ArrayList<Long>() // units per second of each interface
        var pos = 0
        while (pos + 12 <= b.size) {
            val type = ByteBuffer.wrap(b, pos, 4).order(order).int
            if (type == 0x0A0D0D0A) {
                // a new section: byte order from its magic, interfaces start over
                order =
                    if (ByteBuffer.wrap(b, pos + 8, 4).order(ByteOrder.LITTLE_ENDIAN).int ==
                        0x1A2B3C4D
                    ) {
                        ByteOrder.LITTLE_ENDIAN
                    } else {
                        ByteOrder.BIG_ENDIAN
                    }
                links.clear()
                tsres.clear()
            }
            val bb = ByteBuffer.wrap(b).order(order)
            val len = bb.getInt(pos + 4)
            if (len < 12 || pos + len > b.size) break
            when (type) {
                1 -> { // IDB
                    links.add(bb.getShort(pos + 8).toInt() and 0xffff)
                    tsres.add(ifTsResolution(bb, pos + 16, pos + len - 4))
                }
                6 -> { // EPB
                    val ifc = bb.getInt(pos + 8)
                    val ts = (bb.getInt(pos + 12).toLong() and 0xffffffffL shl 32) or (bb.getInt(pos + 16).toLong() and 0xffffffffL)
                    val cap = bb.getInt(pos + 20)
                    val orig = bb.getInt(pos + 24)
                    if (ifc in links.indices && cap >= 0 && pos + 28 + cap <= pos + len) {
                        var uid = -1
                        var dropped = false
                        var o = pos + 28 + ((cap + 3) and 3.inv())
                        val end = pos + len - 4
                        while (o + 4 <= end) {
                            val code = bb.getShort(o).toInt() and 0xffff
                            val olen = bb.getShort(o + 2).toInt() and 0xffff
                            if (code == 0 || o + 4 + olen > end) break
                            if (code == 1) {
                                val c = String(b, o + 4, olen, Charsets.UTF_8)
                                if (c.startsWith("u-")) {
                                    uid = c.substring(2).toIntOrNull() ?: -1
                                } else if (c == "dropped") {
                                    dropped = true
                                }
                            }
                            o += 4 + ((olen + 3) and 3.inv())
                        }
                        add(toMicros(ts, tsres[ifc]), links[ifc], b, pos + 28, cap, orig, uid, dropped)
                    }
                }
                3 -> { // SPB: interface 0, no timestamp
                    if (links.isNotEmpty()) {
                        val orig = bb.getInt(pos + 8)
                        add(0, links[0], b, pos + 12, minOf(orig, len - 16), orig, -1, false)
                    }
                }
            }
            pos += len
        }
    }

    /** if_tsresol option of an IDB: units per second (default microseconds). */
    private fun ifTsResolution(bb: ByteBuffer, from: Int, to: Int): Long {
        var o = from
        while (o + 4 <= to) {
            val code = bb.getShort(o).toInt() and 0xffff
            val olen = bb.getShort(o + 2).toInt() and 0xffff
            if (code == 0) break
            if (code == 9 && olen >= 1) {
                val v = bb.get(o + 4).toInt() and 0xff
                val exp = v and 0x7f
                return if (v and 0x80 != 0) 1L shl minOf(exp, 62) else Math.pow(10.0, minOf(exp, 18).toDouble()).toLong()
            }
            o += 4 + ((olen + 3) and 3.inv())
        }
        return 1_000_000
    }

    private fun toMicros(ts: Long, perSecond: Long) = when {
        perSecond == 1_000_000L -> ts
        perSecond > 1_000_000L -> ts / (perSecond / 1_000_000L)
        else -> ts * (1_000_000L / perSecond)
    }

    /** Offset of the IP header inside the frame, or null for non-IP frames. */
    fun ipPayload(link: Int, b: ByteArray, off: Int, len: Int): Int? {
        fun u16(o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)
        fun isIp(o: Int) = o < off + len && ((b[o].toInt() shr 4) and 0xf).let { it == 4 || it == 6 }
        val at = when (link) {
            LINK_RAW, LINK_IPV4, LINK_IPV6 -> off
            LINK_NULL -> off + 4
            LINK_ETHERNET -> {
                var o = off + 12
                if (o + 2 > off + len) return null
                var type = u16(o)
                while ((type == 0x8100 || type == 0x88A8) && o + 6 <= off + len) { // VLAN tags
                    o += 4
                    type = u16(o)
                }
                if (type != 0x0800 && type != 0x86DD) return null
                o + 2
            }
            LINK_SLL -> if (len >= 16 && u16(off + 14).let { it == 0x0800 || it == 0x86DD }) off + 16 else return null
            LINK_SLL2 -> if (len >= 20 && u16(off).let { it == 0x0800 || it == 0x86DD }) off + 20 else return null
            else -> return null
        }
        return if (len - (at - off) >= 20 && isIp(at)) at else null
    }

    /** Groups packets into connections: the side that sent the first packet is the client. */
    private class FlowBuilder(private val appOf: (Int) -> AppInfo?) {
        class Flow(val id: Int, val first: ByteArray) {
            var uid = -1
            var sent = 0L
            var rcvd = 0L
            var sentPkts = 0
            var rcvdPkts = 0
            var firstTs = Long.MAX_VALUE
            var lastTs = 0L
            var blocked = 0
            var proto = ""
            var host: String? = null
        }
        private val flows = LinkedHashMap<FlowKey, Flow>()

        fun add(store: PacketStore, ts: Long, ip: ByteArray, origLen: Int, uid: Int, dropped: Boolean) {
            val fwd = PacketStore.keyOf(ip, 0, ip.size, true) ?: return
            val rev = PacketStore.keyOf(ip, 0, ip.size, false) ?: return
            val tx = when {
                flows.containsKey(rev) && fwd != rev -> false
                else -> true
            }
            val f = flows.getOrPut(if (tx) fwd else rev) { Flow(flows.size + 1, ip) }
            store.addPacket(ts, ip, maxOf(origLen, ip.size), tx, uid, dropped)
            if (uid >= 0) f.uid = uid
            if (tx) {
                f.sent += origLen
                f.sentPkts++
            } else {
                f.rcvd += origLen
                f.rcvdPkts++
            }
            if (dropped) f.blocked++
            f.firstTs = minOf(f.firstTs, ts)
            f.lastTs = maxOf(f.lastTs, ts)
            if (f.host == null || f.proto.isEmpty()) {
                val s = Dissector.summary(ip, 0, ip.size)
                if (f.proto.isEmpty() && s.proto !in listOf("TCP", "UDP", "ICMP", "IP")) f.proto = s.proto
                if (f.host == null) f.host = hostFrom(s) ?: if (s.proto == "HTTP") httpHost(ip) else null
            }
        }

        /** The Host header of an HTTP request in this packet. */
        private fun httpHost(ip: ByteArray): String? {
            val text = String(ip, 0, minOf(ip.size, 4096), Charsets.ISO_8859_1)
            val i = text.indexOf("\r\nHost:", ignoreCase = true)
            if (i < 0) return null
            return text.substring(i + 7).substringBefore('\r').trim().substringBefore(':').takeIf { it.contains('.') }
        }

        private fun hostFrom(s: Dissector.Summary): String? = when (s.proto) {
            "TLS" -> s.info.substringAfter(" · ", "").takeIf { it.isNotEmpty() && it.contains('.') }
            "DNS" -> s.info.substringAfter("? ", "").substringBefore(' ').takeIf { it.contains('.') }
            "HTTP" -> s.info.substringAfter(" · ", "").takeIf { it.contains('.') }
            else -> null
        }

        fun conns(): List<Conn> = flows.values.map { f ->
            val b = f.first
            val v4 = (b[0].toInt() shr 4) == 4
            val proto = if (v4) b[9].toInt() and 0xff else b[6].toInt() and 0xff
            val src = InetAddress.getByAddress(if (v4) b.copyOfRange(12, 16) else b.copyOfRange(8, 24)).hostAddress ?: ""
            val dst = InetAddress.getByAddress(if (v4) b.copyOfRange(16, 20) else b.copyOfRange(24, 40)).hostAddress ?: ""
            val l4 = if (v4) (b[0].toInt() and 0xf) * 4 else 40
            val ports = (proto == 6 || proto == 17) && b.size >= l4 + 4
            fun port(o: Int) = if (ports) ((b[l4 + o].toInt() and 0xff) shl 8) or (b[l4 + o + 1].toInt() and 0xff) else 0
            // no app in a foreign capture: the client address says more than a dash
            val app = (if (f.uid >= 0) appOf(f.uid) else null) ?: AppInfo(f.uid, "", src, false)
            Conn(
                f.id, f.uid, app, if (v4) 4 else 6, proto, src, port(0), dst, port(2), f.proto, f.host, null,
                f.sent, f.rcvd, f.sentPkts, f.rcvdPkts, f.blocked, f.firstTs / 1000, f.lastTs / 1000, CLOSED, f.blocked > 0, 0
            )
        }.sortedByDescending { it.firstSeen }

        private companion object {
            const val CLOSED = 3
        }
    }
}
