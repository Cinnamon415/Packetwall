package io.github.cinnamon415.packetwall.engine

import kotlinx.coroutines.flow.MutableStateFlow

sealed interface CaptureState {
    data object Stopped : CaptureState

    data class Running(val since: Long) : CaptureState
}

/** What the running capture reports to the UI, the tile and the widget. Written by [CaptureService] only. */
object CaptureStatus {
    val state = MutableStateFlow<CaptureState>(CaptureState.Stopped)

    /** null = no upstream configured, else whether the proxy accepts connections. */
    val upstreamUp = MutableStateFlow<Boolean?>(null)

    /** The SOCKS5 UDP ASSOCIATE relay is established. */
    val udpRelayUp = MutableStateFlow(false)

    /** DoH URL while the built-in DNS-over-HTTPS proxy is in use. */
    val dohActive = MutableStateFlow<String?>(null)

    /** Android's "Always-on VPN" and "Block connections without VPN" for Packetwall, as seen at the last start. */
    val alwaysOn = MutableStateFlow<Pair<Boolean, Boolean>?>(null)

    /** Private DNS is in strict mode: queries are encrypted, rules by name only see SNI. */
    val privateDnsStrict = MutableStateFlow(false)

    /**
     * Capture paused: the rules keep filtering, but no packets are kept, recorded or streamed and no
     * new connections are logged. The time it started, or null when not paused.
     */
    val pausedSince = MutableStateFlow<Long?>(null)

    /**
     * The running session keeps packets (Settings: keep packets in memory, read at start). Without
     * them Packetwall is a firewall only: nothing is recorded, so there is no pause.
     */
    val packetsKept = MutableStateFlow(true)

    /** Start of the current (or last) protection session: Home and Statistics count from here. */
    val sessionStart = MutableStateFlow(0L)

    val paused get() = pausedSince.value != null

    val running get() = state.value is CaptureState.Running
}
