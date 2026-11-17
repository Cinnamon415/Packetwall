package io.github.cinnamon415.packetwall.engine

import java.math.BigInteger
import java.net.InetAddress

/** IPv4 route arithmetic for "local network bypasses the VPN". */
object Routes {
    data class Cidr(val addr: Long, val prefix: Int) {
        val size get() = 1L shl (32 - prefix)
        val last get() = addr + size - 1
        override fun toString() = "${(addr shr 24) and 255}.${(addr shr 16) and 255}.${(addr shr 8) and 255}.${addr and 255}/$prefix"
        fun contains(o: Cidr) = o.addr >= addr && o.last <= last
        fun overlaps(o: Cidr) = o.addr <= last && o.last >= addr
    }

    fun parse(s: String): Cidr {
        val (ip, p) = s.split('/')
        val a = ip.split('.').fold(0L) { acc, x -> (acc shl 8) or x.toLong() }
        return Cidr(a, p.toInt())
    }

    /** [whole] minus [excluded], as the smallest list of CIDRs. */
    fun subtract(whole: Cidr, excluded: List<Cidr>): List<Cidr> {
        if (excluded.any { it.contains(whole) }) return emptyList()
        if (excluded.none { it.overlaps(whole) }) return listOf(whole)
        val half = whole.prefix + 1
        return subtract(Cidr(whole.addr, half), excluded) + subtract(Cidr(whole.addr + (whole.size / 2), half), excluded)
    }

    /** RFC 1918, link-local and multicast: traffic that stays on the local network. */
    val LOCAL_V4 = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4").map(::parse)
}

/** The same route arithmetic for IPv6 (128-bit addresses as BigInteger). */
object Routes6 {
    private val ONE = BigInteger.ONE

    data class Cidr(val addr: BigInteger, val prefix: Int) {
        val size: BigInteger get() = ONE.shiftLeft(128 - prefix)
        val last: BigInteger get() = addr + size - ONE

        fun contains(o: Cidr) = o.addr >= addr && o.last <= last

        fun overlaps(o: Cidr) = o.addr <= last && o.last >= addr

        /** Text form of the address, without the prefix (compressed on Android, full on the JVM). */
        fun address(): String {
            val raw = addr.toByteArray()
            val bytes = ByteArray(16)
            val n = minOf(raw.size, 16)
            System.arraycopy(raw, raw.size - n, bytes, 16 - n, n)
            return InetAddress.getByAddress(bytes).hostAddress!!.substringBefore('%')
        }

        override fun toString() = "${address()}/$prefix"
    }

    fun parse(s: String): Cidr {
        val (ip, p) = s.split('/')
        return Cidr(BigInteger(1, InetAddress.getByName(ip).address), p.toInt())
    }

    fun subtract(whole: Cidr, excluded: List<Cidr>): List<Cidr> {
        if (excluded.any { it.contains(whole) }) return emptyList()
        if (excluded.none { it.overlaps(whole) }) return listOf(whole)
        val half = whole.prefix + 1
        return subtract(Cidr(whole.addr, half), excluded) + subtract(Cidr(whole.addr + whole.size.shiftRight(1), half), excluded)
    }

    /** Link-local, unique local (home routers, LAN devices) and multicast. */
    val LOCAL_V6 = listOf("fe80::/10", "fc00::/7", "ff00::/8").map(::parse)
}
