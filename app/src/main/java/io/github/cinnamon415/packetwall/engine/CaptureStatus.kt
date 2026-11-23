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

    /**
     * Android's "Always-on VPN" and "Block connections without VPN" for Packetwall, read at start and
     * again by [refreshAlwaysOn] (Android does not tell a running VPN when the user changes them);
     * null while protection is off.
     */
    val alwaysOn = MutableStateFlow<Pair<Boolean, Boolean>?>(null)

    /** Reads both settings from the running VPN service; null while it is not running. */
    @Volatile
    var alwaysOnProbe: (() -> Pair<Boolean, Boolean>)? = null

    /** Re-reads [alwaysOn] from the running service (a binder call: not on the main thread). */
    fun refreshAlwaysOn() {
        val probe = alwaysOnProbe ?: return
        try {
            alwaysOn.value = probe()
        } catch (e: Exception) {
            // the service stopped meanwhile: keep the last value
        }
    }

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

    /**
     * What the last command asked for: on after a start, off after a stop. Starting and stopping take
     * a moment, so a quick second tap on the tile or the widget must toggle this, not [state]: two taps
     * are off and on again, not two stops. Back to false when the capture ends on its own.
     */
    val wanted = MutableStateFlow(false)
}
