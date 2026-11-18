package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.engine.Conn
import java.io.File
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Packets of an opened capture file, read from disk when a view asks for them. The index and the
 * per-connection order are memory-mapped (outside the Java heap); only the packets on screen are in
 * memory. Connection ids are the flow ids of [CaptureFile].
 */
class FilePackets internal constructor(dir: File, private val start: IntArray, private val count: IntArray, private val uids: IntArray) :
    PacketSource {
    private val data = RandomAccessFile(File(dir, CaptureFile.DATA), "r")
    private val n = (File(dir, CaptureFile.INDEX).length() / CaptureFile.REC).toInt()
    private val index: MappedByteBuffer? = map(File(dir, CaptureFile.INDEX))
    private val order: MappedByteBuffer? = map(File(dir, CaptureFile.ORDER))

    private fun map(f: File): MappedByteBuffer? = if (f.length() == 0L) {
        null
    } else {
        RandomAccessFile(f, "r").use {
            it.channel.map(FileChannel.MapMode.READ_ONLY, 0, it.length())
        }.also { it.order(ByteOrder.LITTLE_ENDIAN) }
    }

    override val info: StateFlow<PacketStore.Info> = MutableStateFlow(
        PacketStore.Info(n, data.length(), 0, if (n > 0) index!!.getLong(8) else 0)
    )

    override fun count(): Int = n

    /** The connection (flow id) of the [i]-th packet. */
    fun flowOf(i: Int): Int = index?.getInt(i * CaptureFile.REC + 24) ?: 0

    override fun packetAt(i: Int): PacketStore.Pkt? {
        val idx = index ?: return null
        if (i !in 0 until n) return null
        val o = i * CaptureFile.REC
        val off = idx.getLong(o)
        val ts = idx.getLong(o + 8)
        val cap = idx.getInt(o + 16)
        val orig = idx.getInt(o + 20)
        val flow = idx.getInt(o + 24)
        val flags = idx.getInt(o + 28)
        val bytes = ByteArray(cap)
        synchronized(data) {
            data.seek(off)
            data.readFully(bytes)
        }
        val tx = flags and CaptureFile.F_TX != 0
        val dropped = flags and CaptureFile.F_DROPPED != 0
        val block = PacketStore.epb(ts, bytes, 0, cap, orig, tx, uids.getOrElse(flow) { -1 }, dropped)
        val key = PacketStore.keyOf(bytes, 0, cap, tx) ?: FlowKey(0, 0)
        return PacketStore.Pkt(i.toLong(), ts, uids.getOrElse(flow) { -1 }, tx, dropped, orig, block, cap, key)
    }

    override fun bySeq(seq: Long): PacketStore.Pkt? = if (seq in 0 until n) packetAt(seq.toInt()) else null

    /** Positions (in capture order) of the packets of connection [id]. */
    private fun positions(id: Int, limit: Int): Sequence<Int> {
        val o = order ?: return emptySequence()
        if (id !in 1 until start.size) return emptySequence()
        val from = start[id]
        val k = minOf(count[id], limit)
        return (0 until k).asSequence().map { o.getInt((from + it) * 4) }
    }

    override fun packetsOf(c: Conn, limit: Int): List<PacketStore.Pkt> = positions(c.id, limit).mapNotNull { packetAt(it) }.toList()

    override fun writeConn(out: OutputStream, c: Conn) {
        out.write(PacketStore.defaultHeader())
        positions(c.id, Int.MAX_VALUE).forEach { i -> packetAt(i)?.let { out.write(it.block) } }
    }

    /** The whole file as pcapng (raw IP, with Packetwall's uid comments where known). */
    fun writeAll(out: OutputStream) {
        out.write(PacketStore.defaultHeader())
        for (i in 0 until n) packetAt(i)?.let { out.write(it.block) }
    }

    fun close() = runCatching { data.close() }
}
