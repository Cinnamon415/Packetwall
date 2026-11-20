package io.github.cinnamon415.packetwall.engine

import java.nio.ByteBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EchoPacketTest {
    private val app4 = byteArrayOf(10, 215.toByte(), 173.toByte(), 1)
    private val dst4 = byteArrayOf(1, 1, 1, 1)

    private fun echo4(type: Int = 8, proto: Int = 1): ByteArray {
        val icmp = ByteBuffer.allocate(8 + 16).put(type.toByte()).put(0).putShort(0).putShort(0x1234).putShort(7).put(
            ByteArray(16) {
                it.toByte()
            }
        ).array()
        val p = ByteBuffer.allocate(20 + icmp.size)
            .put(0x45).put(0).putShort((20 + icmp.size).toShort()).putShort(99).putShort(0x4000).put(64).put(proto.toByte()).putShort(0)
            .put(app4).put(dst4).put(icmp).array()
        return p
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)

    @Test fun ipv4Reply() {
        val req = echo4()
        val r = EchoPacket.reply(req)!!
        assertArrayEquals(dst4, r.copyOfRange(12, 16))
        assertArrayEquals(app4, r.copyOfRange(16, 20))
        assertEquals(0, r[20].toInt()) // echo reply
        assertEquals(0x1234, u16(r, 24)) // same id
        assertEquals(7, u16(r, 26)) // same sequence
        assertArrayEquals(req.copyOfRange(28, req.size), r.copyOfRange(28, r.size)) // same payload
        // a correct checksum sums to zero
        assertEquals(0, EchoPacket.checksum(r, 0, 20, 0))
        assertEquals(0, EchoPacket.checksum(r, 20, r.size - 20, 0))
        assertEquals("1.1.1.1", EchoPacket.destination(req)!!.hostAddress)
    }

    @Test fun notAnEchoRequest() {
        assertNull(EchoPacket.reply(echo4(type = 0)))
        assertNull(EchoPacket.reply(echo4(proto = 17)))
        assertNull(EchoPacket.reply(ByteArray(10)))
    }

    @Test fun ipv6Reply() {
        val src = ByteArray(16).also {
            it[0] = 0xfd.toByte()
            it[15] = 1
        }
        val dst = ByteArray(16).also {
            it[0] = 0x26
            it[1] = 0x06
            it[15] = 0x11
        }
        val icmp = ByteBuffer.allocate(8 + 8).put(128.toByte()).put(0).putShort(0).putShort(5).putShort(1).put(ByteArray(8) { 9 }).array()
        val req = ByteBuffer.allocate(40 + icmp.size).putInt(0x60000000).putShort(icmp.size.toShort()).put(58).put(64)
            .put(src).put(dst).put(icmp).array()
        val r = EchoPacket.reply(req)!!
        assertArrayEquals(dst, r.copyOfRange(8, 24))
        assertArrayEquals(src, r.copyOfRange(24, 40))
        assertEquals(129, r[40].toInt() and 0xff)
        // ICMPv6 checksum includes the pseudo-header
        var pseudo = 0L
        for (i in 8 until 40 step 2) pseudo += u16(r, i)
        pseudo += icmp.size + 58
        assertEquals(0, EchoPacket.checksum(r, 40, icmp.size, pseudo))
    }
}
