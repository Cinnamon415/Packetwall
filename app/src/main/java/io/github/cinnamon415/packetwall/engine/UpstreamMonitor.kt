package io.github.cinnamon415.packetwall.engine

import android.util.Log
import io.github.cinnamon415.packetwall.Settings
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * How the engine treats the upstream proxy right now. [kill]: the proxy is down with the kill switch
 * on, so the engine blocks (and logs) what would use it.
 */
data class UpstreamDecision(val active: Boolean, val blockUdp: Boolean, val kill: Boolean = false)

/**
 * [up]: the proxy accepts connections. When it is down the engine either blocks what would use
 * it (kill switch) or sends traffic directly. UDP is blocked when asked to, or when the
 * relay is wanted but not available and the kill switch is on.
 */
fun upstreamDecision(up: Boolean, relayWanted: Boolean, relayAlive: Boolean, s: Settings.Values): UpstreamDecision {
    val active = up || s.upOnDown == ON_DOWN_KILL
    val blockUdp = active && (s.upUdp == UDP_BLOCK || (relayWanted && !relayAlive && s.upOnDown == ON_DOWN_KILL))
    return UpstreamDecision(active, blockUdp, kill = !up && s.upOnDown == ON_DOWN_KILL)
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
 *
 * The proxy is configured by host name; [ip] is its current address (null while it cannot be
 * resolved). It is resolved again while unknown and after repeated failures, and the engine is
 * told the new address. While it is unknown the engine runs with an unroutable proxy address, so
 * with the kill switch nothing leaks.
 */
class UpstreamMonitor(private val host: String, initialIp: String?, private val s: Settings.Values) {
    private var thread: Thread? = null

    @Volatile var ip: String? = initialIp
        private set

    /** Optimistic until the first probe, which runs right away. */
    @Volatile var up: Boolean = initialIp != null
        private set

    /** UDP through the proxy only exists for SOCKS5 (UDP ASSOCIATE). */
    private val relayWanted = s.upUdp == UDP_PROXY && s.upType == TYPE_SOCKS5

    /** Where DNS goes when it should use the upstream: through it while it is up, else blocked (kill switch) or direct. */
    fun dnsRoute(): DnsRoute {
        val addr = ip?.takeIf { up }?.let { InetSocketAddress(it, s.upPort) }
            ?: return if (s.upOnDown == ON_DOWN_KILL) DnsRoute.Blocked else DnsRoute.Direct
        return if (s.upType == TYPE_HTTP) DnsRoute.ViaHttp(addr, s.upUser, s.upPass) else DnsRoute.ViaSocks(addr, s.upUser, s.upPass)
    }

    fun start() {
        NativeBridge.setUpstreamState(true, s.upUdp != UDP_DIRECT, false)
        thread = Thread(::loop, "UpstreamMonitor").also { it.start() }
    }

    fun stop() {
        thread?.interrupt()
        thread = null
        CaptureStatus.upstreamUp.value = null
    }

    private fun loop() {
        var assoc: UdpAssociation? = null
        var failures = 0
        var upStreak = 0
        try {
            while (!Thread.currentThread().isInterrupted) {
                if (ip == null || failures >= RERESOLVE_AFTER) {
                    failures = 0
                    val now = resolve(host)
                    if (now != null && now != ip) {
                        Log.i(TAG, "upstream address changed")
                        ip = now
                        NativeBridge.setUpstreamAddress(now, s.upPort)
                        assoc?.close()
                        assoc = null
                    }
                }
                val target = ip
                val reachable = target != null && reachable(target)
                if (!reachable) failures++ else failures = 0
                if (up != reachable || CaptureStatus.upstreamUp.value == null) Log.i(TAG, "upstream ${if (reachable) "up" else "down"}")
                up = reachable
                CaptureStatus.upstreamUp.value = reachable
                if (relayWanted && target != null) {
                    if (reachable && assoc?.alive != true) {
                        assoc?.close()
                        assoc = UdpAssociation(target, s.upPort, s.upUser, s.upPass).takeIf { it.open() }
                        NativeBridge.setUdpRelay(assoc?.relayIp ?: "", assoc?.relayPort ?: 0)
                    } else if (!reachable && assoc != null) {
                        assoc.close()
                        assoc = null
                        NativeBridge.setUdpRelay("", 0)
                    }
                }
                val relayAlive = assoc?.alive == true
                CaptureStatus.udpRelayUp.value = relayAlive
                val d = upstreamDecision(reachable, relayWanted, relayAlive, s)
                NativeBridge.setUpstreamState(d.active, d.blockUdp, d.kill)
                // down or missing relay: check often; up: back off to a minute (each probe wakes the radio)
                upStreak = if (reachable && !(relayWanted && !relayAlive)) upStreak + 1 else 0
                Thread.sleep(if (upStreak == 0) 3_000 else minOf(60_000L, 10_000L shl minOf(upStreak - 1, 3)))
            }
        } catch (_: InterruptedException) {
        } finally {
            assoc?.close()
            NativeBridge.setUdpRelay("", 0)
            CaptureStatus.udpRelayUp.value = false
        }
    }

    private fun reachable(addr: String) = try {
        Socket().use { it.connect(InetSocketAddress(addr, s.upPort), 2000) }
        true
    } catch (_: Exception) {
        false
    }

    companion object {
        private const val TAG = "UpstreamMonitor"
        private const val RERESOLVE_AFTER = 3

        /** The engine's proxy address while the real one is unknown: connecting to it always fails. */
        const val UNROUTABLE = "0.0.0.0"

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
