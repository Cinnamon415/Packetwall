package io.github.cinnamon415.packetwall.analysis

import java.io.File
import java.io.RandomAccessFile
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * Minimal reader of the MaxMind DB format (https://maxmind.github.io/MaxMind-DB/), enough for the
 * DB-IP Lite databases: binary search tree + data section decoder. The file is memory mapped.
 */
class MmdbReader(file: File) {
    private val buf: ByteBuffer
    private val nodeCount: Int
    private val recordSize: Int
    private val ipVersion: Int
    private val treeSize: Int
    private val dataStart: Int
    val metadata: Map<String, Any?>
    private var ipv4Start = 0

    init {
        RandomAccessFile(file, "r").use { raf ->
            buf = raf.channel.map(FileChannel.MapMode.READ_ONLY, 0, raf.length())
        }
        val marker = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()) + "MaxMind.com".toByteArray()
        var m = -1
        var i = buf.limit() - marker.size
        val stop = maxOf(0, buf.limit() - 128 * 1024)
        while (i >= stop) {
            var ok = true
            for (j in marker.indices) if (buf.get(i + j) != marker[j]) { ok = false; break }
            if (ok) { m = i + marker.size; break }
            i--
        }
        require(m >= 0) { "not a MaxMind DB file" }
        @Suppress("UNCHECKED_CAST")
        metadata = Decoder(buf, 0).decode(m).first as Map<String, Any?>
        nodeCount = (metadata["node_count"] as Number).toInt()
        recordSize = (metadata["record_size"] as Number).toInt()
        ipVersion = (metadata["ip_version"] as Number).toInt()
        require(recordSize == 24 || recordSize == 28 || recordSize == 32) { "record size $recordSize" }
        treeSize = (recordSize * 2 / 8) * nodeCount
        dataStart = treeSize + 16
        if (ipVersion == 6) {
            var node = 0
            for (k in 0 until 96) { if (node >= nodeCount) break; node = record(node, 0) }
            ipv4Start = node
        }
    }

    private fun u8(o: Int) = buf.get(o).toInt() and 0xff

    private fun record(node: Int, bit: Int): Int {
        val base = node * recordSize * 2 / 8
        return when (recordSize) {
            24 -> { val o = base + bit * 3; (u8(o) shl 16) or (u8(o + 1) shl 8) or u8(o + 2) }
            28 -> if (bit == 0) ((u8(base + 3) and 0xf0) shl 20) or (u8(base) shl 16) or (u8(base + 1) shl 8) or u8(base + 2)
                  else ((u8(base + 3) and 0x0f) shl 24) or (u8(base + 4) shl 16) or (u8(base + 5) shl 8) or u8(base + 6)
            else -> buf.getInt(base + bit * 4)
        }
    }

    /** The data record for an address, or null. */
    fun lookup(addr: InetAddress): Any? {
        val bytes = addr.address
        var node = if (bytes.size == 4 && ipVersion == 6) ipv4Start else 0
        val bits = bytes.size * 8
        var i = 0
        while (i < bits && node < nodeCount) {
            val bit = (bytes[i / 8].toInt() shr (7 - i % 8)) and 1
            node = record(node, bit)
            i++
        }
        if (node <= nodeCount) return null           // == nodeCount: not found
        val off = (node - nodeCount) - 16 + dataStart
        return Decoder(buf, dataStart).decode(off).first
    }

    private class Decoder(val b: ByteBuffer, val base: Int) {
        private fun u8(o: Int) = b.get(o).toInt() and 0xff

        fun decode(off: Int): Pair<Any?, Int> {
            var o = off
            val ctrl = u8(o++)
            var type = ctrl shr 5
            if (type == 1) {                                     // pointer
                val ss = (ctrl shr 3) and 0x3
                val vv = ctrl and 0x7
                val p = when (ss) {
                    0 -> (vv shl 8) or u8(o)
                    1 -> ((vv shl 16) or (u8(o) shl 8) or u8(o + 1)) + 2048
                    2 -> ((vv shl 24) or (u8(o) shl 16) or (u8(o + 1) shl 8) or u8(o + 2)) + 526336
                    else -> b.getInt(o)
                }
                return decode(base + p).first to (o + ss + 1)
            }
            if (type == 0) type = 7 + u8(o++)                     // extended
            var size = ctrl and 0x1f
            when (size) {
                29 -> size = 29 + u8(o++)
                30 -> { size = 285 + ((u8(o) shl 8) or u8(o + 1)); o += 2 }
                31 -> { size = 65821 + ((u8(o) shl 16) or (u8(o + 1) shl 8) or u8(o + 2)); o += 3 }
            }
            return when (type) {
                2 -> { val a = ByteArray(size); for (k in 0 until size) a[k] = b.get(o + k); String(a, Charsets.UTF_8) to o + size }
                3 -> b.getDouble(o) to o + 8
                4 -> { val a = ByteArray(size); for (k in 0 until size) a[k] = b.get(o + k); a to o + size }
                5, 6, 9, 10 -> { var v = 0L; for (k in 0 until size) v = (v shl 8) or u8(o + k).toLong(); v to o + size }
                7 -> {
                    val m = LinkedHashMap<String, Any?>()
                    repeat(size) {
                        val (k, n1) = decode(o); val (v, n2) = decode(n1)
                        m[k.toString()] = v; o = n2
                    }
                    m to o
                }
                8 -> { var v = 0; for (k in 0 until size) v = (v shl 8) or u8(o + k); v to o + size }
                11 -> {
                    val l = ArrayList<Any?>(size)
                    repeat(size) { val (v, n) = decode(o); l.add(v); o = n }
                    l to o
                }
                14 -> (size != 0) to o
                15 -> b.getFloat(o) to o + 4
                else -> null to o + size
            }
        }
    }
}
