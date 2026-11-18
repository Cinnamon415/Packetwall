package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.BadDataException
import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.engine.Conn
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.RandomAccessFile
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

/**
 * Reads a pcap or pcapng file (Wireshark, tcpdump, PCAPdroid, Packetwall's own recordings) and
 * groups its packets into connections, so the usual connection and packet views can show it.
 * Link types: raw IP, IPv4/IPv6, Ethernet (VLAN tags skipped), Linux cooked v1/v2, BSD loopback;
 * other link types and non-IP frames are counted as skipped.
 *
 * The file is read as a stream and never held in memory: [parse] writes the IP packets, a fixed-size
 * index and the connection table into a directory, and [load] opens it with the packets read from
 * disk on demand ([FilePackets]). Memory use depends on the number of connections, not on the file
 * size. [parse] runs in a separate process (ParserService), so even a failure there cannot touch
 * the VPN.
 */
object CaptureFile {
    class Summary(val packets: Int, val skipped: Int, val truncated: Boolean)

    class Loaded(val conns: List<Conn>, val packets: FilePackets, val skipped: Int, val truncated: Boolean)

    /** Stop after this many packets or connections (the rest is reported as not read). */
    const val MAX_PACKETS = 10_000_000
    const val MAX_FLOWS = 500_000

    /** Larger blocks or packets mean a damaged file. */
    private const val MAX_BLOCK = 16 shl 20

    private const val LINK_NULL = 0
    private const val LINK_ETHERNET = 1
    private const val LINK_RAW = 101
    private const val LINK_SLL = 113
    private const val LINK_IPV4 = 228
    private const val LINK_IPV6 = 229
    private const val LINK_SLL2 = 276

    internal const val DATA = "packets.dat"
    internal const val INDEX = "index.bin"
    internal const val ORDER = "order.bin"
    internal const val FLOWS = "flows.bin"
    private const val VERSION = 1

    /** One packet in [INDEX]: data offset, timestamp (µs), captured and original length, flow id, flags. */
    internal const val REC = 32
    internal const val F_TX = 1
    internal const val F_DROPPED = 2

    /** Parses [input] into [dir] (emptied first); stops reading after [maxBytes] of input. */
    fun parse(input: InputStream, dir: File, maxBytes: Long = Long.MAX_VALUE): Summary {
        dir.deleteRecursively()
        if (!dir.mkdirs()) throw java.io.IOException("cannot create ${dir.path}")
        val w = Writer(dir)
        try {
            val r = Reader(BufferedInputStream(input, 1 shl 20), maxBytes)
            val head = ByteArray(4)
            if (!r.read(head, 0, 4)) throw BadDataException("not a capture file")
            when (ByteBuffer.wrap(head).order(ByteOrder.BIG_ENDIAN).int) {
                0x0A0D0D0A -> readPcapng(r, head, w)
                0xA1B2C3D4.toInt() -> readPcap(r, ByteOrder.BIG_ENDIAN, false, w)
                0xA1B23C4D.toInt() -> readPcap(r, ByteOrder.BIG_ENDIAN, true, w)
                0xD4C3B2A1.toInt() -> readPcap(r, ByteOrder.LITTLE_ENDIAN, false, w)
                0x4D3CB2A1 -> readPcap(r, ByteOrder.LITTLE_ENDIAN, true, w)
                else -> throw BadDataException("not a pcap or pcapng file")
            }
            if (r.capped) w.truncated = true
        } finally {
            w.close()
        }
        return w.finish()
    }

    /** Opens a directory written by [parse]; [appOf] names the app of a uid from Packetwall's own comments. */
    fun load(dir: File, appOf: (Int) -> AppInfo?): Loaded {
        DataInputStream(BufferedInputStream(File(dir, FLOWS).inputStream())).use { d ->
            if (d.readInt() != VERSION) throw BadDataException("unknown index version")
            d.readInt() // packets
            val skipped = d.readInt()
            val truncated = d.readBoolean()
            val n = d.readInt()
            val start = IntArray(n + 1)
            val count = IntArray(n + 1)
            val uids = IntArray(n + 1) { -1 }
            val conns = ArrayList<Conn>(n)
            repeat(n) {
                val id = d.readInt()
                val uid = d.readInt()
                val ipver = d.readInt()
                val proto = d.readInt()
                val src = d.readUTF()
                val sport = d.readInt()
                val dst = d.readUTF()
                val dport = d.readInt()
                val l7 = d.readUTF()
                val host = d.readUTF().ifEmpty { null }
                val sent = d.readLong()
                val rcvd = d.readLong()
                val sentPkts = d.readInt()
                val rcvdPkts = d.readInt()
                val blocked = d.readInt()
                val first = d.readLong()
                val last = d.readLong()
                start[id] = d.readInt()
                count[id] = d.readInt()
                uids[id] = uid
                // no app in a foreign capture: the client address says more than a dash
                val app = (if (uid >= 0) appOf(uid) else null) ?: AppInfo(uid, "", src, false)
                conns += Conn(
                    id, uid, app, ipver, proto, src, sport, dst, dport, l7, host, null,
                    sent, rcvd, sentPkts, rcvdPkts, blocked, first / 1000, last / 1000, CLOSED, blocked > 0, 0
                )
            }
            conns.sortByDescending { it.firstSeen }
            return Loaded(conns, FilePackets(dir, start, count, uids), skipped, truncated)
        }
    }

    // ------------------------------------------------------------------ reading

    /** The input, counted: past [max] bytes it reports the end of the file and sets [capped]. */
    private class Reader(private val input: InputStream, private val max: Long) {
        var total = 0L
        var capped = false

        /** Reads exactly [n] bytes; false at the end of the input (or of the allowed size). */
        fun read(b: ByteArray, off: Int, n: Int): Boolean {
            if (total + n > max) {
                capped = true
                return false
            }
            var got = 0
            while (got < n) {
                val k = input.read(b, off + got, n - got)
                if (k < 0) return false
                got += k
            }
            total += n
            return true
        }
    }

    private fun readPcap(r: Reader, order: ByteOrder, nanos: Boolean, w: Writer) {
        val rest = ByteArray(20)
        if (!r.read(rest, 0, 20)) throw EOFException("pcap header")
        val link = ByteBuffer.wrap(rest).order(order).getInt(16) and 0x0fffffff
        val hdr = ByteArray(16)
        val hb = ByteBuffer.wrap(hdr).order(order)
        var buf = ByteArray(65536)
        while (!w.full && r.read(hdr, 0, 16)) {
            val sec = hb.getInt(0).toLong() and 0xffffffffL
            val frac = hb.getInt(4).toLong() and 0xffffffffL
            val incl = hb.getInt(8)
            val orig = hb.getInt(12)
            if (incl < 0 || incl > MAX_BLOCK) break
            if (incl > buf.size) buf = ByteArray(incl)
            if (!r.read(buf, 0, incl)) break
            w.packet(sec * 1_000_000 + if (nanos) frac / 1000 else frac, link, buf, 0, incl, orig, -1, false)
        }
    }

    private fun readPcapng(r: Reader, magic: ByteArray, w: Writer) {
        var order = ByteOrder.LITTLE_ENDIAN
        val links = ArrayList<Int>()
        val tsres = ArrayList<Long>() // units per second of each interface
        var b = ByteArray(65536)
        System.arraycopy(magic, 0, b, 0, 4)
        var have = 4 // bytes of the current block already in b
        while (!w.full) {
            if (!r.read(b, have, 8 - have)) break
            val type = ByteBuffer.wrap(b, 0, 4).order(order).int
            if (type == 0x0A0D0D0A) {
                // a new section: byte order from its magic, interfaces start over
                if (!r.read(b, 8, 4)) break
                order = if (ByteBuffer.wrap(b, 8, 4).order(ByteOrder.LITTLE_ENDIAN).int == 0x1A2B3C4D) {
                    ByteOrder.LITTLE_ENDIAN
                } else {
                    ByteOrder.BIG_ENDIAN
                }
                links.clear()
                tsres.clear()
                have = 12
            } else {
                have = 8
            }
            val len = ByteBuffer.wrap(b, 4, 4).order(order).int
            if (len < 12 || len % 4 != 0 || len > MAX_BLOCK) break
            if (len > b.size) b = b.copyOf(len)
            if (!r.read(b, have, len - have)) break
            have = 0
            val bb = ByteBuffer.wrap(b, 0, len).order(order)
            when (type) {
                1 -> { // IDB
                    if (len >= 20) {
                        links.add(bb.getShort(8).toInt() and 0xffff)
                        tsres.add(ifTsResolution(bb, 16, len - 4))
                    }
                }
                6 -> { // EPB
                    if (len < 32) continue
                    val ifc = bb.getInt(8)
                    val ts = (bb.getInt(12).toLong() and 0xffffffffL shl 32) or (bb.getInt(16).toLong() and 0xffffffffL)
                    val cap = bb.getInt(20)
                    val orig = bb.getInt(24)
                    if (ifc in links.indices && cap >= 0 && 28 + cap <= len - 4) {
                        var uid = -1
                        var dropped = false
                        var o = 28 + ((cap + 3) and 3.inv())
                        val end = len - 4
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
                        w.packet(toMicros(ts, tsres[ifc]), links[ifc], b, 28, cap, orig, uid, dropped)
                    }
                }
                3 -> { // SPB: interface 0, no timestamp
                    if (links.isNotEmpty() && len >= 16) {
                        val orig = bb.getInt(8)
                        w.packet(0, links[0], b, 12, minOf(orig, len - 16), orig, -1, false)
                    }
                }
            }
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
        perSecond <= 0L -> ts
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

    // ------------------------------------------------------------------ writing

    /** Writes the packets and the index as they come, and the connection table at the end. */
    private class Writer(private val dir: File) {
        private val data = BufferedOutputStream(FileOutputStream(File(dir, DATA)), 1 shl 18)
        private val index = BufferedOutputStream(FileOutputStream(File(dir, INDEX)), 1 shl 16)
        private val rec = ByteBuffer.allocate(REC).order(ByteOrder.LITTLE_ENDIAN)
        private val flows = FlowBuilder()
        private var dataOff = 0L
        var packets = 0
        var skipped = 0
        var truncated = false
        val full get() = truncated

        fun packet(ts: Long, link: Int, b: ByteArray, off: Int, len: Int, origLen: Int, uid: Int, dropped: Boolean) {
            val ip = ipPayload(link, b, off, len)
            if (ip == null) {
                skipped++
                return
            }
            val ipLen = off + len - ip
            val f = flows.add(b, ip, ipLen, ts, maxOf(origLen - (ip - off), ipLen), uid, dropped)
            if (f == null) {
                // too many connections: the rest of the file is not read
                truncated = true
                return
            }
            data.write(b, ip, ipLen)
            rec.clear()
            rec.putLong(dataOff).putLong(ts).putInt(ipLen).putInt(maxOf(origLen - (ip - off), ipLen)).putInt(f.first.id)
                .putInt((if (f.second) F_TX else 0) or (if (dropped) F_DROPPED else 0))
            index.write(rec.array())
            dataOff += ipLen
            packets++
            if (packets >= MAX_PACKETS) truncated = true
        }

        fun close() {
            data.close()
            index.close()
        }

        /** Groups the index by connection ([ORDER]) and writes the connection table ([FLOWS]). */
        fun finish(): Summary {
            val list = flows.list()
            val start = IntArray(list.size + 2)
            for (f in list) start[f.id + 1] = f.count
            for (i in 1 until start.size) start[i] += start[i - 1]
            val cursor = start.copyOf()
            RandomAccessFile(File(dir, ORDER), "rw").use { raf ->
                raf.setLength(packets.toLong() * 4)
                if (packets > 0) {
                    val order = raf.channel.map(FileChannel.MapMode.READ_WRITE, 0, packets.toLong() * 4).order(ByteOrder.LITTLE_ENDIAN)
                    val one = ByteArray(REC)
                    val rb = ByteBuffer.wrap(one).order(ByteOrder.LITTLE_ENDIAN)
                    DataInputStream(BufferedInputStream(File(dir, INDEX).inputStream(), 1 shl 16)).use { input ->
                        for (i in 0 until packets) {
                            input.readFully(one)
                            val flow = rb.getInt(24)
                            order.putInt(cursor[flow] * 4, i)
                            cursor[flow]++
                        }
                    }
                }
            }
            DataOutputStream(BufferedOutputStream(FileOutputStream(File(dir, FLOWS)))).use { d ->
                d.writeInt(VERSION)
                d.writeInt(packets)
                d.writeInt(skipped)
                d.writeBoolean(truncated)
                d.writeInt(list.size)
                for (f in list) {
                    val c = f.describe()
                    d.writeInt(f.id)
                    d.writeInt(f.uid)
                    d.writeInt(c.ipver)
                    d.writeInt(c.proto)
                    d.writeUTF(c.src)
                    d.writeInt(c.sport)
                    d.writeUTF(c.dst)
                    d.writeInt(c.dport)
                    d.writeUTF(f.proto)
                    d.writeUTF(f.host ?: "")
                    d.writeLong(f.sent)
                    d.writeLong(f.rcvd)
                    d.writeInt(f.sentPkts)
                    d.writeInt(f.rcvdPkts)
                    d.writeInt(f.blocked)
                    d.writeLong(f.firstTs)
                    d.writeLong(f.lastTs)
                    d.writeInt(start[f.id])
                    d.writeInt(f.count)
                }
            }
            return Summary(packets, skipped, truncated)
        }
    }

    /** Groups packets into connections: the side that sent the first packet is the client. */
    private class FlowBuilder {
        class Flow(val id: Int, val first: ByteArray) {
            var uid = -1
            var sent = 0L
            var rcvd = 0L
            var sentPkts = 0
            var rcvdPkts = 0
            var count = 0
            var firstTs = Long.MAX_VALUE
            var lastTs = 0L
            var blocked = 0
            var proto = ""
            var host: String? = null

            class Addr(val ipver: Int, val proto: Int, val src: String, val sport: Int, val dst: String, val dport: Int)

            fun describe(): Addr {
                val b = first
                val v4 = (b[0].toInt() shr 4) == 4
                val proto = if (v4) b[9].toInt() and 0xff else b[6].toInt() and 0xff
                val src = InetAddress.getByAddress(if (v4) b.copyOfRange(12, 16) else b.copyOfRange(8, 24)).hostAddress ?: ""
                val dst = InetAddress.getByAddress(if (v4) b.copyOfRange(16, 20) else b.copyOfRange(24, 40)).hostAddress ?: ""
                val l4 = if (v4) (b[0].toInt() and 0xf) * 4 else 40
                val ports = (proto == 6 || proto == 17) && b.size >= l4 + 4
                fun port(o: Int) = if (ports) ((b[l4 + o].toInt() and 0xff) shl 8) or (b[l4 + o + 1].toInt() and 0xff) else 0
                return Addr(if (v4) 4 else 6, proto, src, port(0), dst, port(2))
            }
        }
        private val flows = HashMap<FlowKey, Flow>()
        private val order = ArrayList<Flow>()

        /** The packet's connection and whether it goes client → server; null when there are too many connections. */
        fun add(b: ByteArray, off: Int, len: Int, ts: Long, origLen: Int, uid: Int, dropped: Boolean): Pair<Flow, Boolean>? {
            val fwd = PacketStore.keyOf(b, off, len, true) ?: return null
            val rev = PacketStore.keyOf(b, off, len, false) ?: return null
            val tx = !(fwd != rev && flows.containsKey(rev))
            var f = flows[if (tx) fwd else rev]
            if (f == null) {
                if (order.size >= MAX_FLOWS) return null
                // the headers are enough to name the connection later
                f = Flow(order.size + 1, b.copyOfRange(off, off + minOf(len, 80)))
                flows[fwd] = f
                order.add(f)
            }
            if (uid >= 0) f.uid = uid
            if (tx) {
                f.sent += origLen
                f.sentPkts++
            } else {
                f.rcvd += origLen
                f.rcvdPkts++
            }
            f.count++
            if (dropped) f.blocked++
            f.firstTs = minOf(f.firstTs, ts)
            f.lastTs = maxOf(f.lastTs, ts)
            if (f.host == null || f.proto.isEmpty()) {
                val s = Dissector.summary(b, off, len)
                if (f.proto.isEmpty() && s.proto !in listOf("TCP", "UDP", "ICMP", "IP")) f.proto = s.proto
                if (f.host == null) f.host = hostFrom(s) ?: if (s.proto == "HTTP") httpHost(b, off, len) else null
            }
            return f to tx
        }

        fun list(): List<Flow> = order

        /** The Host header of an HTTP request in this packet. */
        private fun httpHost(b: ByteArray, off: Int, len: Int): String? {
            val text = String(b, off, minOf(len, 4096), Charsets.ISO_8859_1)
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
    }

    private const val CLOSED = 3
}
