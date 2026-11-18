package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.engine.AppInfo
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class CaptureFileTest {
    @get:Rule val tmp = TemporaryFolder()
    private var n = 0

    private class Read(val summary: CaptureFile.Summary, val loaded: CaptureFile.Loaded) {
        val packets get() = summary.packets
        val skipped get() = summary.skipped
        val conns get() = loaded.conns
        val store get() = loaded.packets
    }

    /** Parses as the parser process does (stream onto disk), then loads like the UI. */
    private fun read(bytes: ByteArray, maxBytes: Long = Long.MAX_VALUE, appOf: (Int) -> AppInfo? = { null }): Read {
        val dir = File(tmp.root, "c${n++}")
        val s = CaptureFile.parse(ByteArrayInputStream(bytes), dir, maxBytes)
        return Read(s, CaptureFile.load(dir, appOf))
    }
    private fun ip4(proto: Int, src: ByteArray, dst: ByteArray, l4: ByteArray): ByteArray {
        val b = ByteBuffer.allocate(20 + l4.size)
        b.put(0x45.toByte()).put(0).putShort((20 + l4.size).toShort()).putShort(1).putShort(0x4000).put(64).put(proto.toByte()).putShort(0)
        b.put(src).put(dst).put(l4)
        return b.array()
    }

    private fun tcp(sp: Int, dp: Int, flags: Int, payload: ByteArray = ByteArray(0)): ByteArray {
        val b = ByteBuffer.allocate(20 + payload.size)
        b.putShort(
            sp.toShort()
        ).putShort(dp.toShort()).putInt(1000).putInt(0).put(0x50).put(flags.toByte()).putShort(-1).putShort(0).putShort(0)
        b.put(payload)
        return b.array()
    }

    private fun udp(sp: Int, dp: Int, payload: ByteArray): ByteArray {
        val b = ByteBuffer.allocate(8 + payload.size)
        b.putShort(sp.toShort()).putShort(dp.toShort()).putShort((8 + payload.size).toShort()).putShort(0).put(payload)
        return b.array()
    }

    private fun dnsQuery(name: String): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        name.split('.').forEach {
            o.write(it.length)
            o.write(it.toByteArray())
        }
        o.write(byteArrayOf(0, 0, 1, 0, 1))
        return o.toByteArray()
    }

    private val phone = byteArrayOf(192.toByte(), 168.toByte(), 1, 23)
    private val server = byteArrayOf(93, 184.toByte(), 216.toByte(), 34)
    private val dns = byteArrayOf(1, 1, 1, 1)

    private fun eth(ip: ByteArray, vlan: Boolean = false): ByteArray {
        val b = ByteBuffer.allocate(14 + (if (vlan) 4 else 0) + ip.size)
        b.put(ByteArray(12))
        if (vlan) b.putShort(0x8100.toShort()).putShort(5)
        b.putShort(0x0800).put(ip)
        return b.array()
    }

    /** Classic pcap, little endian, microseconds. */
    private fun pcap(link: Int, frames: List<ByteArray>): ByteArray {
        val o = ByteArrayOutputStream()
        val h = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        h.putInt(0xA1B2C3D4.toInt()).putShort(2).putShort(4).putInt(0).putInt(0).putInt(65535).putInt(link)
        o.write(h.array())
        frames.forEachIndexed { i, f ->
            val r = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            r.putInt(1_700_000_000 + i).putInt(0).putInt(f.size).putInt(f.size)
            o.write(r.array())
            o.write(f)
        }
        return o.toByteArray()
    }

    @Test fun ethernetPcapBecomesConnections() {
        val frames = listOf(
            eth(ip4(17, phone, dns, udp(40000, 53, dnsQuery("www.example.org")))),
            eth(ip4(6, phone, server, tcp(50000, 80, 0x02)), vlan = true),
            eth(ip4(6, server, phone, tcp(80, 50000, 0x12))),
            eth(ip4(6, phone, server, tcp(50000, 80, 0x18, "GET / HTTP/1.1\r\nHost: www.example.org\r\n\r\n".toByteArray())))
        )
        val r = read(pcap(1, frames))
        assertEquals(4, r.packets)
        assertEquals(0, r.skipped)
        assertEquals(2, r.conns.size)
        val web = r.conns.single { it.dstPort == 80 }
        assertEquals("192.168.1.23", web.srcIp)
        assertEquals(2, web.sentPkts)
        assertEquals(1, web.rcvdPkts)
        assertEquals("www.example.org", web.host)
        val q = r.conns.single { it.dstPort == 53 }
        assertEquals("DNS", q.l7proto)
        assertEquals("www.example.org", q.host)
        // the connection views find the packets through the same keys
        assertEquals(3, r.store.packetsOf(web).size)
        assertTrue(r.store.packetsOf(web).first().tx)
        assertTrue(!r.store.packetsOf(web)[1].tx)
    }

    @Test fun ownPcapngWithUidComments() {
        val live = PacketStore()
        live.reset(1 shl 20)
        live.addPacket(1_000_000, ip4(6, phone, server, tcp(50000, 443, 0x02)), 40, true, 10123, false)
        live.addPacket(1_100_000, ip4(6, server, phone, tcp(443, 50000, 0x12)), 40, false, 10123, true)
        val out = ByteArrayOutputStream()
        live.writePcapng(out)
        val names = mapOf(10123 to io.github.cinnamon415.packetwall.engine.AppInfo(10123, "com.a", "A", false))
        val r = read(out.toByteArray()) { names[it] }
        val c = r.conns.single()
        assertEquals("A", c.app.name)
        assertEquals(1, c.blockedPkts)
        assertTrue(c.blocked)
    }

    @Test fun nonIpAndGarbage() {
        val arp = ByteArray(42).also {
            it[12] = 0x08
            it[13] = 0x06
        }
        val r = read(pcap(1, listOf(arp)))
        assertEquals(1, r.skipped)
        assertEquals(0, r.conns.size)
        assertTrue(runCatching { read(ByteArray(100)) }.isFailure)
        assertNull(CaptureFile.ipPayload(147, arp, 0, arp.size))
    }

    @Test fun packetsComeFromDiskAndExportWhole() {
        val frames = (0 until 50).map { i ->
            if (i % 2 == 0) {
                eth(ip4(6, phone, server, tcp(50000, 443, 0x18, ByteArray(100) { i.toByte() })))
            } else {
                eth(ip4(6, server, phone, tcp(443, 50000, 0x18, ByteArray(200) { i.toByte() })))
            }
        } + eth(ip4(17, phone, dns, udp(40000, 53, dnsQuery("a.example"))))
        val r = read(pcap(1, frames))
        assertEquals(51, r.store.count())
        val web = r.conns.single { it.dstPort == 443 }
        assertEquals(25, web.sentPkts)
        assertEquals(25, web.rcvdPkts)
        // packets of a connection in capture order, with their direction and data
        val pk = r.store.packetsOf(web)
        assertEquals(50, pk.size)
        assertTrue(pk[0].tx && !pk[1].tx)
        assertEquals(7.toByte(), pk[7].block[PacketStore.DATA_OFF + 40])
        assertEquals(10, r.store.packetsOf(web, 10).size)
        // the global list and lookups by seq agree
        assertEquals(web.id, r.store.flowOf(3))
        assertEquals(pk[3].seq, r.store.bySeq(pk[3].seq)!!.seq)
        // export of one connection is a valid capture with all of its packets
        val out = ByteArrayOutputStream()
        r.store.writeConn(out, web)
        val again = read(out.toByteArray())
        assertEquals(50, again.packets)
        assertEquals(1, again.conns.size)
    }

    @Test fun stopsAtTheSizeLimit() {
        val frames = (0 until 100).map { eth(ip4(6, phone, server, tcp(50000, 443, 0x18, ByteArray(500)))) }
        val r = read(pcap(1, frames), maxBytes = 10_000)
        assertTrue(r.summary.truncated)
        assertTrue(r.loaded.truncated)
        assertTrue(r.packets in 1..19)
        assertEquals(r.packets, r.store.count())
    }
}
