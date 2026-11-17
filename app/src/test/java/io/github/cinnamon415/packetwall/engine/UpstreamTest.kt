package io.github.cinnamon415.packetwall.engine

import io.github.cinnamon415.packetwall.Settings
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UpstreamTest {
    private fun s(type: Int = TYPE_SOCKS5, onDown: Int = ON_DOWN_KILL, user: String = "") = Settings.Values(
        upstream = true,
        upHost = "proxy.example",
        upPort = 1080,
        upType = type,
        upOnDown = onDown,
        upUser = user,
        upPass = "pw"
    )

    @Test fun dnsFollowsTheProxy() {
        val addr = InetSocketAddress("10.0.0.5", 1080)
        assertEquals(DnsRoute.ViaSocks(addr, "", "pw"), UpstreamMonitor("proxy.example", "10.0.0.5", s()).dnsRoute())
        assertEquals(DnsRoute.ViaHttp(addr, "u", "pw"), UpstreamMonitor("proxy.example", "10.0.0.5", s(TYPE_HTTP, user = "u")).dnsRoute())
        // host not resolved: blocked with the kill switch, direct otherwise
        assertEquals(DnsRoute.Blocked, UpstreamMonitor("proxy.example", null, s()).dnsRoute())
        assertEquals(DnsRoute.Direct, UpstreamMonitor("proxy.example", null, s(onDown = 1)).dnsRoute())
    }

    /** A one-shot fake SOCKS5 server: expects a login, accepts CONNECT, records what it got. */
    @Test fun socks5ConnectWithLogin() {
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        var login = ""
        var dst = ByteArray(0)
        val t = thread {
            server.accept().use { c ->
                val i = DataInputStream(c.getInputStream())
                val o = c.getOutputStream()
                i.readFully(ByteArray(3)) // 5, 1, method 2
                o.write(byteArrayOf(5, 2))
                i.readUnsignedByte()
                val u = ByteArray(i.readUnsignedByte()).also { i.readFully(it) }
                val p = ByteArray(i.readUnsignedByte()).also { i.readFully(it) }
                login = "${String(u)}:${String(p)}"
                o.write(byteArrayOf(1, 0))
                dst = ByteArray(10).also { i.readFully(it) } // 5, 1, 0, 1, ip4, port
                o.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34))
            }
        }
        java.net.Socket().use { sock ->
            sock.connect(server.localSocketAddress)
            val bound = Socks5.request(sock, "alice", "s3cret", Socks5.CMD_CONNECT, InetSocketAddress("1.1.1.1", 443))
            assertEquals(0x1234, bound.port)
        }
        t.join(2000)
        server.close()
        assertEquals("alice:s3cret", login)
        assertArrayEquals(byteArrayOf(5, 1, 0, 1, 1, 1, 1, 1, 1, 0xBB.toByte()), dst)
    }

    @Test fun refusedLoginIsAnError() {
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val t = thread {
            server.accept().use { c ->
                val i = DataInputStream(c.getInputStream())
                i.readFully(ByteArray(3))
                c.getOutputStream().write(byteArrayOf(5, 2))
                i.readUnsignedByte()
                i.readFully(ByteArray(i.readUnsignedByte()))
                i.readFully(ByteArray(i.readUnsignedByte()))
                c.getOutputStream().write(byteArrayOf(1, 1)) // failure
            }
        }
        val failed = runCatching {
            java.net.Socket().use { sock ->
                sock.connect(server.localSocketAddress)
                Socks5.request(sock, "alice", "wrong", Socks5.CMD_CONNECT, InetSocketAddress("1.1.1.1", 443))
            }
        }.isFailure
        t.join(2000)
        server.close()
        assertTrue(failed)
    }
}
