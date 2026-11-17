package io.github.cinnamon415.packetwall.engine

import android.util.Log
import java.io.DataInputStream
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
        val out = s.getOutputStream()
        val inp = DataInputStream(s.getInputStream())
        val auth = user.isNotEmpty()
        out.write(byteArrayOf(5, 1, if (auth) 2 else 0))
        out.flush()
        val ver = inp.readUnsignedByte()
        val method = inp.readUnsignedByte()
        require(ver == 5) { "not a SOCKS5 server" }
        when (method) {
            0 -> {}
            2 -> {
                require(auth) { "the proxy wants a login" }
                val u = user.toByteArray()
                val p = pass.toByteArray()
                out.write(byteArrayOf(1, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p)
                out.flush()
                inp.readUnsignedByte()
                require(inp.readUnsignedByte() == 0) { "authentication failed" }
            }
            else -> throw IllegalStateException("no acceptable auth method ($method)")
        }
        // UDP ASSOCIATE, client address unknown: 0.0.0.0:0
        out.write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
        out.flush()
        require(inp.readUnsignedByte() == 5) { "bad reply" }
        val rep = inp.readUnsignedByte()
        require(rep == 0) { "UDP ASSOCIATE refused ($rep)" }
        inp.readUnsignedByte()
        val addr = when (inp.readUnsignedByte()) {
            1 -> ByteArray(4).also { inp.readFully(it) }.let { InetAddress.getByAddress(it).hostAddress!! }
            4 -> ByteArray(16).also { inp.readFully(it) }.let { InetAddress.getByAddress(it).hostAddress!! }
            3 -> ByteArray(inp.readUnsignedByte()).also { inp.readFully(it) }.let { InetAddress.getByName(String(it)).hostAddress!! }
            else -> throw IllegalStateException("bad address type")
        }
        relayPort = inp.readUnsignedShort()
        // 0.0.0.0 / :: means "the proxy's own address"
        relayIp = if (addr == "0.0.0.0" || addr == "::") InetAddress.getByName(host).hostAddress!! else addr
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
