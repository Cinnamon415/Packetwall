package io.github.cinnamon415.packetwall.engine

import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import javax.net.SocketFactory

/** SOCKS5 client side (RFC 1928, login per RFC 1929), shared by the UDP association and the DoH tunnel. */
object Socks5 {
    /** The proxy refused the request; [code] is the SOCKS5 reply (5 = the host refused the connection). */
    class Refused(val code: Int) : IOException("request refused ($code)")

    const val CMD_CONNECT = 1
    const val CMD_UDP_ASSOCIATE = 3

    /**
     * Greets the proxy on [s], logs in when [user] is set, and sends [cmd] for [dst]. Returns the
     * address from the reply (the relay for UDP ASSOCIATE). Throws [IOException] on any refusal.
     */
    fun request(s: Socket, user: String, pass: String, cmd: Int, dst: InetSocketAddress?): InetSocketAddress {
        val out = s.getOutputStream()
        val inp = DataInputStream(s.getInputStream())
        val auth = user.isNotEmpty()
        out.write(byteArrayOf(5, 1, if (auth) 2 else 0))
        out.flush()
        if (inp.readUnsignedByte() != 5) throw IOException("not a SOCKS5 server")
        when (val method = inp.readUnsignedByte()) {
            0 -> {}
            2 -> {
                if (!auth) throw IOException("the proxy wants a login")
                val u = user.toByteArray()
                val p = pass.toByteArray()
                if (u.size > 255 || p.size > 255) throw IOException("login too long")
                out.write(byteArrayOf(1, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p)
                out.flush()
                inp.readUnsignedByte()
                if (inp.readUnsignedByte() != 0) throw IOException("authentication failed")
            }
            else -> throw IOException("no acceptable auth method ($method)")
        }
        val port = dst?.port ?: 0
        // a name not resolved here (unresolved, or the placeholder 0.0.0.0 of UpstreamHttp): the proxy resolves it
        val name = dst?.takeIf { it.isUnresolved || it.address.isAnyLocalAddress }?.hostString
            ?.takeIf { it.isNotEmpty() && !isIpLiteral(it) }
        val target = if (name != null) {
            val n = name.toByteArray()
            if (n.size > 255) throw IOException("host name too long")
            byteArrayOf(3, n.size.toByte()) + n
        } else {
            val addr = dst?.address?.address ?: ByteArray(4)
            byteArrayOf(if (addr.size == 16) 4 else 1) + addr
        }
        out.write(byteArrayOf(5, cmd.toByte(), 0) + target + byteArrayOf((port shr 8).toByte(), port.toByte()))
        out.flush()
        if (inp.readUnsignedByte() != 5) throw IOException("bad reply")
        val rep = inp.readUnsignedByte()
        if (rep != 0) throw Refused(rep)
        inp.readUnsignedByte()
        val boundAddr = when (inp.readUnsignedByte()) {
            1 -> ByteArray(4).also { inp.readFully(it) }.let { InetAddress.getByAddress(it) }
            4 -> ByteArray(16).also { inp.readFully(it) }.let { InetAddress.getByAddress(it) }
            3 -> ByteArray(inp.readUnsignedByte()).also { inp.readFully(it) }.let { InetAddress.getByName(String(it)) }
            else -> throw IOException("bad address type")
        }
        return InetSocketAddress(boundAddr, inp.readUnsignedShort())
    }

    private fun isIpLiteral(s: String) = s.contains(':') || s.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))

    /**
     * Sockets whose connect() goes through the SOCKS5 proxy at [proxy] with a login. java.net's own
     * SOCKS support cannot log in on Android, so OkHttp gets this factory instead (DoH and Packetwall's
     * own downloads via the upstream). A destination given by name is resolved by the proxy.
     */
    class TunnelSocketFactory(private val proxy: InetSocketAddress, private val user: String, private val pass: String) : SocketFactory() {
        override fun createSocket(): Socket = TunnelSocket()

        override fun createSocket(host: String, port: Int): Socket = TunnelSocket().apply {
            connect(InetSocketAddress.createUnresolved(host, port))
        }

        override fun createSocket(host: String, port: Int, localHost: InetAddress?, localPort: Int): Socket = createSocket(host, port)

        override fun createSocket(host: InetAddress, port: Int): Socket = TunnelSocket().apply { connect(InetSocketAddress(host, port)) }

        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            createSocket(address, port)

        private inner class TunnelSocket : Socket() {
            override fun connect(endpoint: SocketAddress) = connect(endpoint, 0)

            override fun connect(endpoint: SocketAddress, timeout: Int) {
                super.connect(proxy, timeout)
                val dst = endpoint as InetSocketAddress
                val previous = soTimeout
                if (timeout > 0) soTimeout = timeout
                request(this, user, pass, CMD_CONNECT, dst)
                soTimeout = previous
            }
        }
    }
}
