package io.github.cinnamon415.packetwall.ui

import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.analysis.PacketStore
import io.github.cinnamon415.packetwall.engine.Conn
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Where the connection and packet views read from: the live capture or an opened capture file. */
interface CaptureSource {
    val conns: StateFlow<List<Conn>>
    val packets: PacketStore

    /** Live: connections can still change and rules apply to them. */
    val live: Boolean
}

class LiveSource(app: PacketwallApp) : CaptureSource {
    override val conns = app.connections.conns
    override val packets = app.packets
    override val live = true
}

/** An opened pcap/pcapng file. */
class FileSource(val name: String, conns: List<Conn>, override val packets: PacketStore, val skipped: Int) : CaptureSource {
    override val conns: StateFlow<List<Conn>> = MutableStateFlow(conns)
    override val live = false
}

/** The file open in "File analysis" (one at a time; gone with the process). */
object OpenedFile {
    @Volatile var current: FileSource? = null
}
