package io.github.cinnamon415.packetwall.engine

import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * A SOCKS5 UDP ASSOCIATE (RFC 1928 section 4/7) kept open on a TCP control connection. The relay
 * address it returns is handed to the native engine, which wraps every UDP datagram for it. The
 * association lives as long as the control connection: [alive] turns false when it closes.
 */
class UdpAssociation(private val host: String, private val port: Int, private val user: String, private val pass: String) {
    @Volatile var alive = false
        private set
    var relayIp: String = ""
        private set
    var relayPort = 0
        private set
    private var sock: Socket? = null

    /** Blocking: handshake + UDP ASSOCIATE. Returns false (with a log) on any failure. */
    fun open(): Boolean = try {
        val s = Socket()
        s.connect(InetSocketAddress(host, port), 3000)
        s.soTimeout = 4000
        sock = s
        // UDP ASSOCIATE, client address unknown: 0.0.0.0:0
        val relay = Socks5.request(s, user, pass, Socks5.CMD_UDP_ASSOCIATE, null)
        relayPort = relay.port
        // 0.0.0.0 / :: means "the proxy's own address"
        relayIp = if (relay.address.isAnyLocalAddress) InetAddress.getByName(host).hostAddress!! else relay.address.hostAddress!!
        s.soTimeout = 0
        alive = true
        Thread({
            try {
                while (s.getInputStream().read() >= 0) { }
            } catch (_: Exception) {}
            alive = false
            Log.i(TAG, "UDP association closed")
        }, "UdpAssociation").apply { isDaemon = true }.start()
        Log.i(TAG, "UDP relay $relayIp:$relayPort")
        true
    } catch (e: Exception) {
        Log.w(TAG, "UDP ASSOCIATE failed: ${e.message}")
        close()
        false
    }

    fun close() {
        alive = false
        try {
            sock?.close()
        } catch (_: Exception) {}
        sock = null
    }

    companion object {
        private const val TAG = "UdpAssociation"
    }
}
