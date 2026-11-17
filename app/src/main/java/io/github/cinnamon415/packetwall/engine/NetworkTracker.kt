package io.github.cinnamon415.packetwall.engine

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.net.Inet4Address

/**
 * Follows the non-VPN networks and reports the link properties of the preferred one (Wi-Fi, then
 * Ethernet, then cellular) whenever any of them changes. [onChange] runs on the main thread.
 */
class NetworkTracker(private val cm: ConnectivityManager, private val onChange: (LinkProperties?) -> Unit) {
    private val handler = Handler(Looper.getMainLooper())
    private val networks = HashMap<Network, Pair<LinkProperties?, NetworkCapabilities?>>()
    private var callback: ConnectivityManager.NetworkCallback? = null

    fun start() {
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = changed {
                networks[network] = networks[network]?.first to caps
            }

            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = changed {
                networks[network] = lp to networks[network]?.second
            }

            override fun onLost(network: Network) = changed { networks.remove(network) }
        }
        try {
            cm.registerNetworkCallback(req, cb)
            callback = cb
        } catch (e: Exception) {
            Log.w(TAG, "registerNetworkCallback failed", e)
        }
    }

    fun stop() {
        callback?.let { cb ->
            try {
                cm.unregisterNetworkCallback(cb)
            } catch (e: Exception) {
                Log.w(TAG, "unregisterNetworkCallback failed", e)
            }
        }
        callback = null
        handler.removeCallbacksAndMessages(null)
        networks.clear()
    }

    private fun changed(update: () -> Unit) {
        handler.post {
            if (callback == null) return@post
            update()
            onChange(preferred())
        }
    }

    private fun preferred(): LinkProperties? {
        fun rank(c: NetworkCapabilities?) = when {
            c == null -> 9
            c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
            c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
            c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
            else -> 3
        }
        return networks.values.filter { it.first != null }.minByOrNull { rank(it.second) }?.first
    }

    companion object {
        private const val TAG = "NetworkTracker"

        fun activeLinkProperties(cm: ConnectivityManager): LinkProperties? = cm.activeNetwork?.let { cm.getLinkProperties(it) }

        fun firstIpv4Dns(lp: LinkProperties?): String? = lp?.dnsServers?.firstOrNull { it is Inet4Address }?.hostAddress
    }
}
