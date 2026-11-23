package io.github.cinnamon415.packetwall.engine

import java.io.IOException
import java.net.InetAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import okhttp3.Credentials
import okhttp3.Dns
import okhttp3.OkHttpClient

/**
 * OkHttp clients that go where a [DnsRoute] says: straight to the network, or through the upstream
 * proxy. Through the proxy, host names are resolved by the proxy: no DNS query leaves around it.
 */
object UpstreamHttp {
    /**
     * Names are not looked up here: each gets the placeholder 0.0.0.0 carrying the name, and the
     * SOCKS5 tunnel sends the name to the proxy (see [Socks5.request]).
     */
    private val remoteDns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> = listOf(InetAddress.getByAddress(hostname, ByteArray(4)))
    }

    fun client(base: OkHttpClient, r: DnsRoute): OkHttpClient = when (r) {
        DnsRoute.Direct, DnsRoute.Blocked -> base
        // CONNECT carries the name
        is DnsRoute.ViaHttp -> base.newBuilder().proxy(Proxy(Proxy.Type.HTTP, r.proxy)).apply {
            if (r.user.isNotEmpty()) {
                proxyAuthenticator { _, resp ->
                    if (resp.request.header("Proxy-Authorization") != null) {
                        null
                    } else {
                        resp.request.newBuilder().header("Proxy-Authorization", Credentials.basic(r.user, r.pass)).build()
                    }
                }
            }
        }.build()
        // OkHttp hands java.net's SOCKS an unresolved address: the name goes to the proxy
        is DnsRoute.ViaSocks -> if (r.user.isEmpty()) {
            base.newBuilder().proxy(Proxy(Proxy.Type.SOCKS, r.proxy)).build()
        } else {
            // java.net's SOCKS cannot log in on Android: our own tunnel, names resolved by the proxy
            base.newBuilder().proxy(
                Proxy.NO_PROXY
            ).socketFactory(Socks5.TunnelSocketFactory(r.proxy, r.user, r.pass)).dns(remoteDns).build()
        }
    }
}

/**
 * Packetwall's own downloads: block lists, the GeoIP and trackers databases. The app is excluded
 * from its own VPN, so while protection sends all traffic through the upstream these follow [route]
 * too; otherwise they would leave from the real address. With the upstream down and the kill
 * switch on they fail instead of going direct.
 */
object OwnTraffic {
    /** Where a download from this host goes; set by the capture service while it runs with all traffic through the upstream. */
    @Volatile var route: (host: String) -> DnsRoute = { DnsRoute.Direct }

    private val base = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    @Volatile private var cached: Pair<DnsRoute, OkHttpClient>? = null

    /** A client for [host] right now. Throws while the upstream is down with the kill switch on. */
    @Throws(IOException::class)
    fun client(host: String): OkHttpClient {
        val r = route(host)
        if (r == DnsRoute.Blocked) throw UpstreamDown()
        cached?.let { (cr, c) -> if (cr == r) return c }
        return UpstreamHttp.client(base, r).also { cached = r to it }
    }

    class UpstreamDown : IOException("the upstream proxy is down (kill switch)")
}

/**
 * Loopback, or with [lanBypass] an address of the local network (as excluded from the VPN routes):
 * reached directly, not through the upstream. Names count as remote.
 */
fun isLocalHost(host: String, lanBypass: Boolean): Boolean {
    val h = host.removePrefix("[").removeSuffix("]")
    if (h.equals("localhost", true)) return true
    val ip =
        runCatching {
            if (h.contains(':') ||
                h.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
            ) {
                InetAddress.getByName(h)
            } else {
                null
            }
        }.getOrNull()
            ?: return false
    if (ip.isLoopbackAddress) return true
    if (!lanBypass) return false
    return if (ip.address.size == 4) {
        Routes.LOCAL_V4.any { it.contains(Routes.parse("${ip.hostAddress}/32")) }
    } else {
        Routes6.LOCAL_V6.any { it.contains(Routes6.parse("${ip.hostAddress}/128")) }
    }
}
