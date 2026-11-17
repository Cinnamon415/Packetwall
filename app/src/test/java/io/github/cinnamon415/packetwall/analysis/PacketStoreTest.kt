package io.github.cinnamon415.packetwall.analysis

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketStoreTest {
    /** IPv4 + TCP SYN 10.215.173.1:40000 -> 93.184.216.34:443 */
    private fun syn(): ByteArray {
        val b = ByteBuffer.allocate(40)
        b.put(0x45.toByte()).put(0).putShort(40).putShort(1).putShort(0x4000).put(64).put(6).putShort(0)
        b.put(byteArrayOf(10, 215.toByte(), 173.toByte(), 1)).put(byteArrayOf(93, 184.toByte(), 216.toByte(), 34))
        b.putShort(
            40000.toShort()
        ).putShort(443).putInt(1000).putInt(0).put(0x50).put(0x02).putShort(0xffff.toShort()).putShort(0).putShort(0)
        return b.array()
    }

    private fun epb(pkt: ByteArray, tx: Boolean, comments: List<String>): ByteArray {
        val opts = ByteArrayOutputStream()
        fun opt(code: Int, v: ByteArray) {
            val o = ByteBuffer.allocate(4 + ((v.size + 3) and 3.inv())).order(ByteOrder.LITTLE_ENDIAN)
            o.putShort(code.toShort()).putShort(v.size.toShort()).put(v)
            opts.write(o.array())
        }
        opt(2, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(if (tx) 2 else 1).array())
        comments.forEach { opt(1, it.toByteArray()) }
        opts.write(ByteArray(4))
        val padded = (pkt.size + 3) and 3.inv()
        val total = 28 + padded + opts.size() + 4
        val b = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        b.putInt(6).putInt(total).putInt(0).putInt(0).putInt(1_000_000).putInt(pkt.size).putInt(pkt.size)
        b.put(pkt)
        b.position(28 + padded)
        b.put(opts.toByteArray())
        b.putInt(total)
        return b.array()
    }

    @Test fun parsesEpbOptionsAndIndexes() {
        val s = PacketStore()
        s.reset(1 shl 20)
        s.feed(epb(syn(), tx = true, comments = listOf("u-10123", "dropped")))
        val p = s.all().single()
        assertEquals(10123, p.uid)
        assertTrue(p.tx)
        assertTrue(p.dropped)
        assertEquals("6|0ad7ad01|40000|5db8d822|443", p.key)
        val sum = Dissector.summary(p.block, p.dataOff, p.capLen)
        assertEquals("TCP", sum.proto)
        assertEquals("SYN", sum.info)
        assertEquals(1000L, sum.tcpSeq)
    }

    @Test fun splitChunksAndEviction() {
        val s = PacketStore()
        s.reset(300)
        val block = epb(syn(), true, listOf("u-1"))
        val two = block + block
        s.feed(two.copyOfRange(0, 50))
        s.feed(two.copyOfRange(50, two.size)) // block split across chunks
        assertEquals(2, s.all().size)
        repeat(5) { s.feed(block) }
        assertTrue(s.all().sumOf { it.block.size } <= 300)
        val out = ByteArrayOutputStream()
        s.writePcapng(out)
        assertTrue(out.size() > 0)
    }
}
