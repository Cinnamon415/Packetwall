package io.github.cinnamon415.packetwall.engine

import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Proxy
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Local DNS-over-HTTPS proxy. The native engine sends the VPN's DNS queries (after the firewall
 * had its say) to 127.0.0.1:[port]; every query is POSTed to the DoH server (RFC 8484).
 *
 * Packetwall itself is excluded from its VPN, so these HTTPS requests go straight to the network.
 */
class DnsProxy(private val url: String, upstream: Proxy? = null, proxyAuth: Pair<String, String>? = null) {
    private val http = baseClient.newBuilder().proxy(upstream).apply {
        // HTTP CONNECT proxies with a login (Basic auth)
        if (proxyAuth != null) {
            proxyAuthenticator { _, resp ->
                if (resp.request.header("Proxy-Authorization") != null) {
                    null
                } else {
                    resp.request.newBuilder().header("Proxy-Authorization", Credentials.basic(proxyAuth.first, proxyAuth.second)).build()
                }
            }
        }
    }.build()
    data class Stats(val queries: Long = 0, val failures: Long = 0, val avgMs: Long = 0, val lastError: String? = null)

    private var sock: DatagramSocket? = null
    private var thread: Thread? = null
    private val pool = ThreadPoolExecutor(2, 8, 30, TimeUnit.SECONDS, LinkedBlockingQueue(256))

    @Volatile private var running = false
    private var totalMs = 0L

    val port: Int get() = sock?.localPort ?: 0

    fun start(): Int {
        val s = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        sock = s
        running = true
        thread = Thread({ loop(s) }, "DnsProxy").also { it.start() }
        Log.i(TAG, "DoH proxy on 127.0.0.1:${s.localPort} -> $url")
        return s.localPort
    }

    fun stop() {
        running = false
        sock?.close()
        sock = null
        pool.shutdownNow()
    }

    private fun loop(s: DatagramSocket) {
        val buf = ByteArray(4096)
        while (running) {
            val p = DatagramPacket(buf, buf.size)
            try {
                s.receive(p)
            } catch (e: Exception) {
                if (running) Log.w(TAG, "receive", e)
                break
            }
            val query = p.data.copyOfRange(p.offset, p.offset + p.length)
            val addr = p.address
            val port = p.port
            try {
                pool.execute {
                    val reply = resolve(query) ?: servfail(query)
                    try {
                        s.send(DatagramPacket(reply, reply.size, addr, port))
                    } catch (_: Exception) {}
                }
            } catch (e: RejectedExecutionException) {
                val r = servfail(query)
                try {
                    s.send(DatagramPacket(r, r.size, addr, port))
                } catch (_: Exception) {}
            }
        }
    }

    private fun resolve(q: ByteArray): ByteArray? {
        if (q.size < 12) return null
        val t0 = System.nanoTime()
        return try {
            // OkHttp: HTTP/2 (required by some servers, e.g. Quad9) and one multiplexed connection
            val req = Request.Builder().url(url)
                .header("Accept", "application/dns-message")
                .post(q.toRequestBody(DNS_MESSAGE))
                .build()
            val body = http.newCall(req).execute().use { r ->
                if (r.code != 200) throw IllegalStateException("HTTP ${r.code}")
                r.body?.bytes() ?: ByteArray(0)
            }
            if (body.size < 12) throw IllegalStateException("short reply")
            // keep the transaction id of the client (DoH servers may zero it)
            body[0] = q[0]
            body[1] = q[1]
            val ms = (System.nanoTime() - t0) / 1_000_000
            synchronized(this) {
                totalMs += ms
                val s = _stats.value
                _stats.value = s.copy(queries = s.queries + 1, avgMs = totalMs / (s.queries + 1))
            }
            body
        } catch (e: Exception) {
            synchronized(this) {
                val s = _stats.value
                _stats.value = s.copy(queries = s.queries + 1, failures = s.failures + 1, lastError = e.message ?: e.javaClass.simpleName)
            }
            Log.w(TAG, "DoH query failed: ${e.message}")
            null
        }
    }

    /** SERVFAIL with the question echoed back, so the client fails fast instead of timing out. */
    private fun servfail(q: ByteArray): ByteArray {
        val r = q.copyOf()
        if (r.size >= 4) {
            r[2] = (0x80 or (q[2].toInt() and 0x79)).toByte() // QR=1, keep opcode + RD
            r[3] = 0x82.toByte() // RA=1, RCODE=2
        }
        if (r.size >= 12) {
            r[6] = 0
            r[7] = 0
            r[8] = 0
            r[9] = 0
            r[10] = 0
            r[11] = 0
        }
        return r
    }

    companion object {
        private const val TAG = "DnsProxy"
        private val DNS_MESSAGE = "application/dns-message".toMediaType()
        private val baseClient = OkHttpClient.Builder()
            .connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS)
            .callTimeout(6, TimeUnit.SECONDS)
            .build()
        private val _stats = MutableStateFlow(Stats())
        val stats: StateFlow<Stats> = _stats
        fun resetStats() {
            _stats.value = Stats()
        }

        data class Preset(val name: String, val url: String)
        val PRESETS = listOf(
            Preset("Cloudflare", "https://1.1.1.1/dns-query"),
            Preset("Quad9", "https://9.9.9.9/dns-query"),
            Preset("Google", "https://8.8.8.8/dns-query"),
            Preset("AdGuard", "https://94.140.14.14/dns-query")
        )
    }
}
