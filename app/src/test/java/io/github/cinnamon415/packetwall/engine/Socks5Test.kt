package io.github.cinnamon415.packetwall.engine

import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Socks5Test {
    /** The CONNECT request a fake SOCKS5 server (no login) receives for [dst]: ATYP and address bytes. */
    private fun requestFor(dst: InetSocketAddress): Pair<Int, ByteArray> {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { srv ->
            var got: Pair<Int, ByteArray>? = null
            val t = thread {
                srv.accept().use { s ->
                    val inp = DataInputStream(s.getInputStream())
                    val out = s.getOutputStream()
                    inp.readUnsignedByte()
                    inp.readFully(ByteArray(inp.readUnsignedByte()))
                    out.write(byteArrayOf(5, 0))
                    inp.readFully(ByteArray(3))
                    val atyp = inp.readUnsignedByte()
                    val addr = when (atyp) {
                        1 -> ByteArray(4).also { inp.readFully(it) }
                        4 -> ByteArray(16).also { inp.readFully(it) }
                        else -> ByteArray(inp.readUnsignedByte()).also { inp.readFully(it) }
                    }
                    inp.readUnsignedShort()
                    got = atyp to addr
                    out.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                }
            }
            Socket().use { c ->
                c.connect(srv.localSocketAddress)
                Socks5.request(c, "", "", Socks5.CMD_CONNECT, dst)
            }
            t.join(3000)
            return got!!
        }
    }

    @Test
    fun aNameGoesToTheProxyUnresolved() {
        val (atyp, addr) = requestFor(InetSocketAddress.createUnresolved("example.com", 443))
        assertEquals(3, atyp)
        assertEquals("example.com", String(addr))
    }

    @Test
    fun theNamedPlaceholderOfUpstreamHttpIsSentAsTheName() {
        val placeholder = InetAddress.getByAddress("lists.example.org", ByteArray(4))
        val (atyp, addr) = requestFor(InetSocketAddress(placeholder, 443))
        assertEquals(3, atyp)
        assertEquals("lists.example.org", String(addr))
    }

    @Test
    fun addressesStayAddresses() {
        val (a4, b4) = requestFor(InetSocketAddress(InetAddress.getByName("1.1.1.1"), 443))
        assertEquals(1, a4)
        assertArrayEquals(byteArrayOf(1, 1, 1, 1), b4)
        val (a6, b6) = requestFor(InetSocketAddress(InetAddress.getByName("2606:4700:4700::1111"), 443))
        assertEquals(4, a6)
        assertEquals(16, b6.size)
        // an address literal given as a name is not sent as a name
        val (al, _) = requestFor(InetSocketAddress.createUnresolved("1.1.1.1", 443))
        assertEquals(1, al)
    }

    @Test
    fun localHosts() {
        assertTrue(isLocalHost("localhost", false))
        assertTrue(isLocalHost("127.0.0.1", false))
        assertTrue(isLocalHost("[::1]", false))
        assertFalse("LAN without the bypass goes through the proxy", isLocalHost("192.168.1.10", false))
        assertTrue(isLocalHost("192.168.1.10", true))
        assertTrue(isLocalHost("10.0.2.2", true))
        assertTrue(isLocalHost("fd00::1", true))
        assertFalse(isLocalHost("8.8.8.8", true))
        assertFalse("names are remote", isLocalHost("nas.local", true))
    }
}
