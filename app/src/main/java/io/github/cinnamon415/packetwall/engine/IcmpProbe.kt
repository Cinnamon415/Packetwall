package io.github.cinnamon415.packetwall.engine

import android.util.Base64
import android.util.Log
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Ping for destinations that go through the upstream proxy. SOCKS5 and HTTP CONNECT carry no ICMP,
 * and sending it directly would show the real address. Instead each echo request becomes a TCP
 * check through the proxy: CONNECT to the destination's port 443 (then 80). When the host answers
 * (connected, or refused it: a refusal also comes from the host) the app gets an echo reply after
 * the time that took; otherwise none, and ping times out as it would for an unreachable host.
 *
 * The time is the proxy's CONNECT round trip: proxy → host and back, plus the way to the proxy,
 * which is what a ping through that proxy would show. It is not ICMP: a host that drops ping but
 * listens on 443 answers here.
 */
class IcmpProbe(
    /** The proxy's current address; null while it is not resolved (then nothing is answered). */
    private val proxy: () -> InetSocketAddress?,
    private val http: Boolean,
    private val user: String,
    private val pass: String,
    /** Writes one IP packet into the VPN interface (towards the app). */
    private val reply: (ByteArray) -> Unit
) {
    // a few checks at a time; when all are busy a ping is dropped, like a lost packet
    private val pool = ThreadPoolExecutor(0, MAX_PARALLEL, 30, TimeUnit.SECONDS, SynchronousQueue()) { r ->
        Thread(r, "IcmpProbe").apply { isDaemon = true }
    }.apply { rejectedExecutionHandler = ThreadPoolExecutor.DiscardPolicy() }

    /** Recent results per destination, so a fast ping (-i 0.2) does not open a connection each time. */
    private val recent = ConcurrentHashMap<String, Pair<Long, Long?>>()

    fun onEcho(packet: ByteArray) {
        val dst = EchoPacket.destination(packet) ?: return
        val answer = EchoPacket.reply(packet) ?: return
        pool.execute {
            val now = System.nanoTime()
            val cached = recent[dst.hostAddress]?.takeIf { now - it.first < CACHE_NS }
            val rtt = if (cached != null) cached.second else check(dst).also { recent[dst.hostAddress!!] = now to it }
            if (rtt != null) {
                try {
                    reply(answer)
                } catch (e: IOException) {
                    Log.d(TAG, "reply not written: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        pool.shutdownNow()
    }

    /** Round trip of a TCP CONNECT through the proxy in ns, or null when the host did not answer. */
    private fun check(dst: InetAddress): Long? {
        val p = proxy() ?: return null
        for ((port, timeout) in listOf(443 to 2_000, 80 to 1_500)) {
            when (val r = connect(p, InetSocketAddress(dst, port), timeout)) {
                is Result.Answered -> return r.ns
                Result.NoAnswer -> return null
                Result.Timeout -> continue
            }
        }
        return null
    }

    private sealed interface Result {
        class Answered(val ns: Long) : Result

        data object NoAnswer : Result

        data object Timeout : Result
    }

    private fun connect(proxy: InetSocketAddress, dst: InetSocketAddress, timeout: Int): Result = try {
        Socket().use { s ->
            s.soTimeout = timeout
            s.connect(proxy, timeout)
            if (http) httpConnect(s, dst) else socksConnect(s, dst)
        }
    } catch (e: SocketTimeoutException) {
        Result.Timeout
    } catch (e: IOException) {
        Result.NoAnswer
    }

    private fun socksConnect(s: Socket, dst: InetSocketAddress): Result {
        val start = System.nanoTime()
        return try {
            Socks5.request(s, user, pass, Socks5.CMD_CONNECT, dst)
            Result.Answered(System.nanoTime() - start)
        } catch (e: Socks5.Refused) {
            // 5 = connection refused: the host itself answered with a reset
            if (e.code == 5) Result.Answered(System.nanoTime() - start) else Result.NoAnswer
        }
    }

    private fun httpConnect(s: Socket, dst: InetSocketAddress): Result {
        val target = (if (dst.address.address.size == 16) "[${dst.address.hostAddress}]" else dst.address.hostAddress) + ":" + dst.port
        val auth = if (user.isEmpty()) {
            ""
        } else {
            "Proxy-Authorization: Basic " + Base64.encodeToString("$user:$pass".toByteArray(), Base64.NO_WRAP) + "\r\n"
        }
        val start = System.nanoTime()
        s.getOutputStream().apply {
            write("CONNECT $target HTTP/1.1\r\nHost: $target\r\n$auth\r\n".toByteArray(Charsets.ISO_8859_1))
            flush()
        }
        // the status line is enough: "HTTP/1.1 200 ..."
        val line = StringBuilder()
        val inp = s.getInputStream()
        while (line.length < 64) {
            val c = inp.read()
            if (c < 0 || c == '\n'.code) break
            line.append(c.toChar())
        }
        val code = line.split(' ').getOrNull(1)?.toIntOrNull()
        return if (code == 200) Result.Answered(System.nanoTime() - start) else Result.NoAnswer
    }

    private companion object {
        const val TAG = "IcmpProbe"
        const val MAX_PARALLEL = 8
        const val CACHE_NS = 1_000_000_000L
    }
}

/** Echo request → echo reply, as raw IP packets (IPv4 ICMP and IPv6 ICMPv6). Pure, tested. */
object EchoPacket {
    fun destination(p: ByteArray): InetAddress? = when (version(p)) {
        4 -> if (p.size >= 20) InetAddress.getByAddress(p.copyOfRange(16, 20)) else null
        6 -> if (p.size >= 40) InetAddress.getByAddress(p.copyOfRange(24, 40)) else null
        else -> null
    }

    /** The reply to an echo request, or null when [req] is not one. */
    fun reply(req: ByteArray): ByteArray? = when (version(req)) {
        4 -> reply4(req)
        6 -> reply6(req)
        else -> null
    }

    private fun version(p: ByteArray) = if (p.isEmpty()) 0 else (p[0].toInt() shr 4) and 0xf

    private fun reply4(req: ByteArray): ByteArray? {
        if (req.size < 28) return null
        val ihl = (req[0].toInt() and 0xf) * 4
        val total = minOf(u16(req, 2), req.size)
        if (ihl < 20 || total < ihl + 8 || (req[9].toInt() and 0xff) != 1 || req[ihl].toInt() != 8) return null
        val r = req.copyOf(total)
        System.arraycopy(req, 16, r, 12, 4)
        System.arraycopy(req, 12, r, 16, 4)
        r[8] = 64 // TTL
        r[10] = 0
        r[11] = 0
        put16(r, 10, checksum(r, 0, ihl, 0))
        r[ihl] = 0 // echo reply
        r[ihl + 1] = 0
        r[ihl + 2] = 0
        r[ihl + 3] = 0
        put16(r, ihl + 2, checksum(r, ihl, total - ihl, 0))
        return r
    }

    private fun reply6(req: ByteArray): ByteArray? {
        if (req.size < 48) return null
        val len = minOf(u16(req, 4), req.size - 40)
        if ((req[6].toInt() and 0xff) != 58 || len < 8 || (req[40].toInt() and 0xff) != 128) return null
        val r = req.copyOf(40 + len)
        System.arraycopy(req, 24, r, 8, 16)
        System.arraycopy(req, 8, r, 24, 16)
        r[7] = 64 // hop limit
        r[40] = 129.toByte() // echo reply
        r[41] = 0
        r[42] = 0
        r[43] = 0
        // pseudo-header: source, destination, upper-layer length, next header
        var sum = 0L
        for (i in 8 until 40 step 2) sum += u16(r, i)
        sum += len.toLong() + 58
        put16(r, 42, checksum(r, 40, len, sum))
        return r
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)

    private fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v shr 8).toByte()
        b[o + 1] = v.toByte()
    }

    /** Internet checksum of [len] bytes at [off], starting from [initial]. */
    fun checksum(b: ByteArray, off: Int, len: Int, initial: Long): Int {
        var sum = initial
        var i = off
        while (i + 1 < off + len) {
            sum += u16(b, i)
            i += 2
        }
        if (i < off + len) sum += (b[i].toInt() and 0xff) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xffff) + (sum shr 16)
        return sum.inv().toInt() and 0xffff
    }
}
