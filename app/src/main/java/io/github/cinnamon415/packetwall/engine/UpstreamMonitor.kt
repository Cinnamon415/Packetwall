package io.github.cinnamon415.packetwall.engine

import android.util.Log
import io.github.cinnamon415.packetwall.Settings
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** How the engine treats the upstream proxy right now. */
data class UpstreamDecision(val active: Boolean, val blockUdp: Boolean)

/**
 * [up]: the proxy accepts connections. When it is down the engine either keeps proxying (kill
 * switch, connections fail) or sends traffic directly. UDP is blocked when asked to, or when the
 * relay is wanted but not available and the kill switch is on.
 */
fun upstreamDecision(up: Boolean, relayWanted: Boolean, relayAlive: Boolean, s: Settings.Values): UpstreamDecision {
    val active = up || s.upOnDown == ON_DOWN_KILL
    val blockUdp = active && (s.upUdp == UDP_BLOCK || (relayWanted && !relayAlive && s.upOnDown == ON_DOWN_KILL))
    return UpstreamDecision(active, blockUdp)
}

// Settings.Values.upUdp / upOnDown / upType codes
const val UDP_DIRECT = 0
const val UDP_BLOCK = 1
const val UDP_PROXY = 2
const val ON_DOWN_KILL = 0
const val TYPE_SOCKS5 = 0
const val TYPE_HTTP = 1

/**
 * Checks every 10 s that the upstream proxy accepts connections (every 3 s while a wanted UDP
 * relay is missing), keeps the SOCKS5 UDP association open, and tells the engine what to do.
 */
class UpstreamMonitor(private val ip: String, private val s: Settings.Values) {
    private var thread: Thread? = null

    /** UDP through the proxy only exists for SOCKS5 (UDP ASSOCIATE). */
    private val relayWanted = s.upUdp == UDP_PROXY && s.upType == TYPE_SOCKS5

    fun start() {
        NativeBridge.setUpstreamState(true, s.upUdp != UDP_DIRECT)
        thread = Thread(::loop, "UpstreamMonitor").also { it.start() }
    }

    fun stop() {
        thread?.interrupt()
        thread = null
        CaptureStatus.upstreamUp.value = null
    }

    private fun loop() {
        var assoc: UdpAssociation? = null
        try {
            while (!Thread.currentThread().isInterrupted) {
                val up = reachable()
                if (CaptureStatus.upstreamUp.value != up) Log.i(TAG, "upstream ${if (up) "up" else "down"}")
                CaptureStatus.upstreamUp.value = up
                if (relayWanted) {
                    if (up && assoc?.alive != true) {
                        assoc?.close()
                        assoc = UdpAssociation(ip, s.upPort, s.upUser, s.upPass).takeIf { it.open() }
                        NativeBridge.setUdpRelay(assoc?.relayIp ?: "", assoc?.relayPort ?: 0)
                    } else if (!up && assoc != null) {
                        assoc.close()
                        assoc = null
                        NativeBridge.setUdpRelay("", 0)
                    }
                }
                val relayAlive = assoc?.alive == true
                CaptureStatus.udpRelayUp.value = relayAlive
                val d = upstreamDecision(up, relayWanted, relayAlive, s)
                NativeBridge.setUpstreamState(d.active, d.blockUdp)
                Thread.sleep(if (relayWanted && !relayAlive) 3_000 else 10_000)
            }
        } catch (_: InterruptedException) {
        } finally {
            assoc?.close()
            NativeBridge.setUdpRelay("", 0)
            CaptureStatus.udpRelayUp.value = false
        }
    }

    private fun reachable() = try {
        Socket().use { it.connect(InetSocketAddress(ip, s.upPort), 2000) }
        true
    } catch (_: Exception) {
        false
    }

    companion object {
        private const val TAG = "UpstreamMonitor"

        /** Resolves the proxy host with a 4 s limit (a literal IP is returned as is); null on failure. */
        fun resolve(host: String): String? {
            val ex = Executors.newSingleThreadExecutor()
            return try {
                ex.submit<String?> { InetAddress.getByName(host.trim()).hostAddress }.get(4, TimeUnit.SECONDS)
            } catch (e: Exception) {
                Log.w(TAG, "cannot resolve upstream $host", e)
                null
            } finally {
                ex.shutdownNow()
            }
        }
    }
}
