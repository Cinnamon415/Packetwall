package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.engine.Conn
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.OutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * In-memory ring of captured packets, fed with the pcapng stream of the native dumper
 * (CaptureService.dumpPcapData). Packets are indexed by connection so the connection screen can
 * show them; the whole buffer (or one connection) can be exported as pcapng.
 *
 * Each [Pkt] keeps its raw Enhanced Packet Block, so export is a plain concatenation and keeps the
 * per-packet options (uid comment, direction flags, "dropped").
 */
class PacketStore {
    class Pkt(
        val seq: Long,
        /** Microseconds since the epoch. */
        val ts: Long,
        val uid: Int,
        val tx: Boolean,
        val dropped: Boolean,
        val origLen: Int,
        /** The raw EPB; the packet (raw IP) is at [DATA_OFF] for [capLen] bytes. */
        val block: ByteArray,
        val capLen: Int,
        val key: String,
    ) {
        val dataOff get() = DATA_OFF
    }

    /** Live consumers of the pcapng stream (PC streaming, disk recording). */
    interface Sink {
        /** Called first with the file preamble + metadata blocks, then with every new block. */
        fun onBlock(block: ByteArray)
    }
    private val sinks = java.util.concurrent.CopyOnWriteArrayList<Sink>()

    fun addSink(s: Sink) {
        synchronized(lock) { s.onBlock(header()) }
        sinks.add(s)
    }
    fun removeSink(s: Sink) { sinks.remove(s) }

    /** SHB + IDB + metadata blocks: the start of a valid pcapng file. */
    fun header(): ByteArray = synchronized(lock) {
        val o = java.io.ByteArrayOutputStream()
        o.write(if (preamble.isEmpty()) defaultPreamble() else preamble)
        extraBlocks.values.forEach { o.write(it) }
        o.toByteArray()
    }

    private val lock = Any()
    private val packets = ArrayDeque<Pkt>()
    private val byKey = HashMap<String, ArrayDeque<Pkt>>()
    private var bytes = 0L
    private var nextSeq = 0L
    private var preamble = ByteArray(0)
    private val extraBlocks = LinkedHashMap<String, ByteArray>()
    private var pending = ByteArray(0)
    @Volatile var capacity = 16L shl 20

    data class Info(val packets: Int = 0, val bytes: Long = 0, val dropped: Long = 0, val firstTs: Long = 0)
    private val _info = MutableStateFlow(Info())
    val info: StateFlow<Info> = _info
    private var evicted = 0L

    /** Bumped when packets are added, so open views can refresh. */
    private val _version = MutableStateFlow(0L)
    val version: StateFlow<Long> = _version

    fun reset(capacityBytes: Long) = synchronized(lock) {
        capacity = capacityBytes
        packets.clear(); byKey.clear(); bytes = 0; evicted = 0
        preamble = ByteArray(0); extraBlocks.clear(); pending = ByteArray(0)
        _info.value = Info()
        _version.value = _version.value + 1
    }

    /** Called on the capture thread with complete pcapng blocks. */
    fun feed(chunk: ByteArray) {
        val data = if (pending.isEmpty()) chunk else pending + chunk
        val bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        var pos = 0
        synchronized(lock) {
            while (data.size - pos >= 12) {
                val type = bb.getInt(pos)
                val len = bb.getInt(pos + 4)
                if (len < 12 || len % 4 != 0) { pos = data.size; break }   // corrupt: drop the rest
                if (data.size - pos < len) break
                val block = data.copyOfRange(pos, pos + len)
                when (type) {
                    0x0A0D0D0A, 0x00000001 -> preamble += block               // SHB, IDB
                    0x00000006 -> { addEpb(block); sinks.forEach { it.onBlock(block) } }
                    else -> {                                                   // uid map, secrets…
                        if (extraBlocks.put(block.contentHashCode().toString(), block) == null) sinks.forEach { it.onBlock(block) }
                    }
                }
                pos += len
            }
            pending = if (pos < data.size) data.copyOfRange(pos, data.size) else ByteArray(0)
            _info.value = Info(packets.size, bytes, evicted, packets.firstOrNull()?.ts ?: 0)
        }
        _version.value = _version.value + 1
    }

    private fun addEpb(block: ByteArray) {
        val bb = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
        val ts = (bb.getInt(12).toLong() and 0xffffffffL shl 32) or (bb.getInt(16).toLong() and 0xffffffffL)
        val capLen = bb.getInt(20)
        val origLen = bb.getInt(24)
        if (capLen <= 0 || DATA_OFF + capLen > block.size) return

        // options
        var uid = -1
        var tx = true
        var dropped = false
        var o = DATA_OFF + ((capLen + 3) and 3.inv())
        val end = block.size - 4
        while (o + 4 <= end) {
            val code = bb.getShort(o).toInt() and 0xffff
            val olen = bb.getShort(o + 2).toInt() and 0xffff
            if (code == 0) break
            val v = o + 4
            if (v + olen > end) break
            when (code) {
                1 -> {
                    val s = String(block, v, olen, Charsets.US_ASCII)
                    if (s.startsWith("u-")) uid = s.substring(2).toIntOrNull() ?: -1
                    else if (s == "dropped") dropped = true
                }
                2 -> if (olen >= 4) tx = (bb.getInt(v) and 0x3) != 1
            }
            o = v + ((olen + 3) and 3.inv())
        }

        val key = keyOf(block, DATA_OFF, capLen, tx) ?: return
        val p = Pkt(nextSeq++, ts, uid, tx, dropped, origLen, block, capLen, key)
        packets.addLast(p)
        byKey.getOrPut(key) { ArrayDeque() }.addLast(p)
        bytes += block.size
        while (bytes > capacity && packets.isNotEmpty()) {
            val old = packets.removeFirst()
            bytes -= old.block.size
            evicted++
            byKey[old.key]?.let { q -> q.removeFirstOrNull(); if (q.isEmpty()) byKey.remove(old.key) }
        }
    }

    /** Packets of a connection (same 5-tuple, inside its lifetime). */
    fun packetsOf(c: Conn): List<Pkt> {
        val key = keyOf(c) ?: return emptyList()
        val from = c.firstSeen * 1000 - 2_000_000
        val to = c.lastSeen * 1000 + 5_000_000
        return synchronized(lock) { byKey[key]?.filter { it.ts in from..to } ?: emptyList() }
    }

    fun all(): List<Pkt> = synchronized(lock) { packets.toList() }

    /** Writes a pcapng file: preamble, metadata blocks, then the packets. */
    fun writePcapng(out: OutputStream, only: List<Pkt>? = null) {
        val (pre, extra, list) = synchronized(lock) { Triple(preamble, extraBlocks.values.toList(), only ?: packets.toList()) }
        out.write(if (pre.isEmpty()) defaultPreamble() else pre)
        extra.forEach { out.write(it) }
        list.forEach { out.write(it.block) }
    }

    private fun defaultPreamble(): ByteArray {
        val shb = ByteBuffer.allocate(28).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0x0A0D0D0A).putInt(28).putInt(0x1A2B3C4D).putShort(1).putShort(0).putLong(-1L).putInt(28)
        val idb = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(1).putInt(20).putShort(101 /* LINKTYPE_RAW */).putShort(0).putInt(0).putInt(20)
        return shb.array() + idb.array()
    }

    companion object {
        /** Offset of the packet data inside an EPB. */
        const val DATA_OFF = 28

        private fun hex(b: ByteArray, off: Int, len: Int): String {
            val sb = StringBuilder(len * 2)
            for (i in off until off + len) sb.append(String.format("%02x", b[i]))
            return sb.toString()
        }

        /** "proto|clientIp|clientPort|serverIp|serverPort", ports 0 for ICMP. */
        fun keyOf(b: ByteArray, off: Int, len: Int, tx: Boolean): String? {
            if (len < 20) return null
            val ver = (b[off].toInt() shr 4) and 0xf
            val proto: Int; val src: String; val dst: String; val l4: Int
            when (ver) {
                4 -> {
                    val ihl = (b[off].toInt() and 0xf) * 4
                    proto = b[off + 9].toInt() and 0xff
                    src = hex(b, off + 12, 4); dst = hex(b, off + 16, 4); l4 = off + ihl
                }
                6 -> {
                    if (len < 40) return null
                    proto = b[off + 6].toInt() and 0xff
                    src = hex(b, off + 8, 16); dst = hex(b, off + 24, 16); l4 = off + 40
                }
                else -> return null
            }
            var sp = 0; var dp = 0
            if ((proto == 6 || proto == 17) && l4 + 4 <= off + len) {
                sp = ((b[l4].toInt() and 0xff) shl 8) or (b[l4 + 1].toInt() and 0xff)
                dp = ((b[l4 + 2].toInt() and 0xff) shl 8) or (b[l4 + 3].toInt() and 0xff)
            }
            val p = if (proto == 58) 1 else proto
            return if (tx) "$p|$src|$sp|$dst|$dp" else "$p|$dst|$dp|$src|$sp"
        }

        fun keyOf(c: Conn): String? = try {
            val s = InetAddress.getByName(c.srcIp).address
            val d = InetAddress.getByName(c.dstIp).address
            val icmp = c.ipproto == 1 || c.ipproto == 58
            val p = if (c.ipproto == 58) 1 else c.ipproto
            "$p|${hex(s, 0, s.size)}|${if (icmp) 0 else c.srcPort}|${hex(d, 0, d.size)}|${if (icmp) 0 else c.dstPort}"
        } catch (e: Exception) { null }
    }
}
