package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.engine.Conn
import java.io.OutputStream
import kotlinx.coroutines.flow.StateFlow

/**
 * Packets for the connection and packet views: the live buffer ([PacketStore], in memory) or an
 * opened capture file ([FilePackets], read from disk on demand).
 */
interface PacketSource {
    val info: StateFlow<PacketStore.Info>

    /** Packets of [c] in capture order, at most [limit]. */
    fun packetsOf(c: Conn, limit: Int = Int.MAX_VALUE): List<PacketStore.Pkt>

    fun count(): Int

    /** The [i]-th packet in capture order. */
    fun packetAt(i: Int): PacketStore.Pkt?

    fun bySeq(seq: Long): PacketStore.Pkt?

    /** A pcapng file with every packet of [c] (not limited). */
    fun writeConn(out: OutputStream, c: Conn)
}
