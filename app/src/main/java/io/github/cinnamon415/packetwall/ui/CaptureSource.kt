package io.github.cinnamon415.packetwall.ui

import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.analysis.FilePackets
import io.github.cinnamon415.packetwall.analysis.PacketSource
import io.github.cinnamon415.packetwall.engine.Conn
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Where the connection and packet views read from: the live capture or an opened capture file. */
interface CaptureSource {
    val conns: StateFlow<List<Conn>>
    val packets: PacketSource

    /** Live: connections can still change and rules apply to them. */
    val live: Boolean
}

class LiveSource(app: PacketwallApp) : CaptureSource {
    override val conns = app.connections.conns
    override val packets = app.packets
    override val live = true
}

/** An opened pcap/pcapng file: connections in memory, packets read from [dir] on demand. */
class FileSource(
    val name: String,
    conns: List<Conn>,
    override val packets: FilePackets,
    val skipped: Int,
    val truncated: Boolean,
    val dir: File
) : CaptureSource {
    override val conns: StateFlow<List<Conn>> = MutableStateFlow(conns)
    override val live = false
}

/** The file open in "File analysis" (one at a time; gone with the process). */
object OpenedFile {
    @Volatile var current: FileSource? = null
}
