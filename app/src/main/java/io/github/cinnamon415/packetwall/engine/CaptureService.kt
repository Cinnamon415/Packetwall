/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * VPN setup and native callbacks adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda.
 */
package io.github.cinnamon415.packetwall.engine

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import android.widget.Toast
import androidx.core.content.ContextCompat
import io.github.cinnamon415.packetwall.BuildConfig
import io.github.cinnamon415.packetwall.MainActivity
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.model.BlacklistDescriptor
import io.github.cinnamon415.packetwall.engine.model.CaptureStats
import io.github.cinnamon415.packetwall.engine.model.ConnectionDescriptor
import io.github.cinnamon415.packetwall.engine.model.ConnectionUpdate
import java.net.Inet4Address
import java.net.InetSocketAddress

/**
 * The VPN service hosting the native packet loop (zdtun + nDPI).
 *
 * Every public method below whose name matches a key in the native code (jni_impl.c,
 * capture_vpn.c, uid_resolver.c) is invoked from the capture thread via JNI: keep names and
 * signatures stable.
 */
class CaptureService : VpnService() {

    private var pfd: ParcelFileDescriptor? = null
    private var loopThread: Thread? = null
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var apps: AppsResolver
    private lateinit var register: ConnectionsRegister
    private var dnsServer = FALLBACK_DNS4
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    /** Non-VPN networks: link properties and transports, to follow DNS and Private DNS changes. */
    private val networks = HashMap<Network, Pair<LinkProperties?, NetworkCapabilities?>>()

    override fun onCreate() {
        super.onCreate()
        val app = application as PacketwallApp
        apps = app.apps
        register = app.connections
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopCapture()
            return START_NOT_STICKY
        }
        startForegroundCompat()
        if (loopThread?.isAlive != true)
            startCapture()
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked the permission
        stopCapture()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    private fun startCapture() {
        (application as io.github.cinnamon415.packetwall.PacketwallApp).firewall.compileNow()
        dnsServer = detectSystemDns() ?: FALLBACK_DNS4
        getSystemService(ConnectivityManager::class.java)?.let { cm ->
            cm.activeNetwork?.let { handleLinkProperties(cm.getLinkProperties(it), initial = true) }
        }
        Log.i(TAG, "Starting capture, upstream DNS $dnsServer")

        val builder = Builder()
            .setMtu(VPN_MTU)
            .setSession(getString(R.string.app_name))
            .addAddress(VPN_IP4, 30)
            .addRoute("0.0.0.0", 1)
            .addRoute("128.0.0.0", 1)
            .addDnsServer(VPN_DNS4)
            .addAddress(VPN_IP6, 128)
            .addRoute("2000::", 3)
            .addRoute("fc00::", 7)
        builder.setMetered(false)
        builder.setConfigureIntent(mainActivityIntent())
        try {
            builder.addDnsServer(FALLBACK_DNS6)
        } catch (e: IllegalArgumentException) {
            Log.w(TAG, "IPv6 DNS not set: $e")
        }

        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "VPN establish failed", e)
            null
        }
        if (fd == null) {
            reportError(getString(R.string.err_vpn_setup))
            stopSelfCompat()
            return
        }
        pfd = fd
        register.reset()
        state.value = CaptureState.Running(System.currentTimeMillis())

        startNetworkTracking()
        loopThread = Thread({
            try {
                runPacketLoop(fd.fd, this, Build.VERSION.SDK_INT)
            } catch (e: Throwable) {
                Log.e(TAG, "Packet loop crashed", e)
            }
            Log.i(TAG, "Packet loop exited")
            handler.post { onLoopExited() }
        }, "PacketLoop").also { it.start() }
    }

    /**
     * Private DNS in "automatic" mode is blocked, so Android falls back to plain DNS that the
     * firewall can see (as PCAPdroid does). In strict mode names stay hidden: the UI shows a notice.
     */
    private fun handleLinkProperties(lp: LinkProperties?, initial: Boolean = false) {
        if (lp == null) return
        val strict = lp.privateDnsServerName != null
        // Off or automatic: DoT to our DNS addresses is dropped so Android uses plain DNS.
        // Checking isPrivateDnsActive is not enough: it is per network and the VPN network
        // may enable it while the underlying one did not.
        setPrivateDnsBlocked(!strict)
        privateDnsStrict.value = strict
        val dns = lp.dnsServers.firstOrNull { it is Inet4Address }?.hostAddress ?: return
        if (dns != dnsServer) {
            Log.i(TAG, "DNS server changed: $dnsServer -> $dns")
            dnsServer = dns
            if (!initial) setDnsServer(dns)
        }
    }

    private fun pickUnderlying(): LinkProperties? {
        fun rank(c: NetworkCapabilities?) = when {
            c == null -> 9
            c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
            c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
            c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
            else -> 3
        }
        return networks.values.filter { it.first != null }.minByOrNull { rank(it.second) }?.first
    }

    private fun startNetworkTracking() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                handler.post { networks[network] = networks[network]?.first to caps; handleLinkProperties(pickUnderlying()) }
            }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                handler.post { networks[network] = lp to networks[network]?.second; handleLinkProperties(pickUnderlying()) }
            }
            override fun onLost(network: Network) {
                handler.post { networks.remove(network); handleLinkProperties(pickUnderlying()) }
            }
        }
        try {
            cm.registerNetworkCallback(req, cb)
            netCallback = cb
        } catch (e: Exception) {
            Log.w(TAG, "registerNetworkCallback failed", e)
        }
    }

    private fun stopNetworkTracking() {
        netCallback?.let { cb -> try { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) } catch (_: Exception) {} }
        netCallback = null
        networks.clear()
        setPrivateDnsBlocked(false)
    }

    private fun onLoopExited() {
        stopNetworkTracking()
        try { pfd?.close() } catch (_: Exception) {}
        pfd = null
        loopThread = null
        state.value = CaptureState.Stopped
        stopSelfCompat()
    }

    private fun stopCapture() {
        if (loopThread?.isAlive == true)
            stopPacketLoop()
        else if (state.value is CaptureState.Running)
            onLoopExited()
    }

    private fun stopSelfCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun detectSystemDns(): String? {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return null
        val net = cm.activeNetwork ?: return null
        val lp = cm.getLinkProperties(net) ?: return null
        return lp.dnsServers.firstOrNull { it is Inet4Address }?.hostAddress
    }

    /* ---------------- notification ---------------- */

    private fun startForegroundCompat() {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null)
            nm.createNotificationChannel(NotificationChannel(CHANNEL_ID,
                getString(R.string.notif_channel_status), NotificationManager.IMPORTANCE_LOW))

        val stop = PendingIntent.getService(this, 1,
            Intent(this, CaptureService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        val n: Notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_wall)
            .setContentTitle(getString(R.string.notif_running))
            .setContentIntent(mainActivityIntent())
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, getString(R.string.action_stop), stop).build())
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            startForeground(NOTIFY_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else
            startForeground(NOTIFY_ID, n)
    }

    private fun mainActivityIntent(): PendingIntent = PendingIntent.getActivity(this, 0,
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE)

    /* ============ Called from native code ============ */

    fun reportError(msg: String) {
        Log.e(TAG, "native error: $msg")
        handler.post { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
    }

    fun getApplicationByUid(uid: Int): String = apps.get(uid).name
    fun getPackageNameByUid(uid: Int): String = apps.get(uid).packageName
    fun loadUidMapping(uid: Int, packageName: String, appName: String) {}
    fun getCountryCode(host: String): String = ""
    fun dumpPcapData(data: ByteArray) {}
    fun stopPcapDump() {}
    fun startConnectionsUpdate() {}

    fun updateConnections(newConns: Array<ConnectionDescriptor?>?, updates: Array<ConnectionUpdate?>?) {
        register.onUpdate(newConns, updates)
    }

    fun sendStatsDump(stats: CaptureStats) { register.onStats(stats) }

    fun sendServiceStatus(status: String) {
        Log.i(TAG, "service status: $status")
    }

    fun getLibprogPath(prog: String): String = applicationInfo.nativeLibraryDir + "/lib" + prog + ".so"
    fun notifyBlacklistsLoaded(loaded: Array<Blacklists.NativeBlacklistStatus>) {}
    fun getBlacklistsInfo(): Array<BlacklistDescriptor> = emptyArray()
    fun checkAvailableHeap() {}

    fun getUidQ(protocol: Int, saddr: String, sport: Int, daddr: String, dport: Int): Int {
        if (protocol != 6 && protocol != 17) return UID_UNKNOWN
        val cm = getSystemService(ConnectivityManager::class.java) ?: return UID_UNKNOWN
        return try {
            cm.getConnectionOwnerUid(protocol, InetSocketAddress(saddr, sport), InetSocketAddress(daddr, dport))
        } catch (e: Exception) {
            UID_UNKNOWN
        }
    }

    // --- configuration read by the native code at startup ---
    fun getMitmAddonUid(): Int = -1
    fun isVpnCapture(): Int = 1
    fun isRootCapture(): Int = 0
    fun isPcapFileCapture(): Int = 0
    fun getPayloadMode(): Int = 0           // NONE (M2 enables payload)
    fun pcapDumpEnabled(): Int = 0
    fun dumpExtensionsEnabled(): Int = 0
    fun isPcapngEnabled(): Int = 1
    fun getSnaplen(): Int = 0
    fun getMaxPktsPerFlow(): Int = 0
    fun getMaxDumpSize(): Int = 0
    fun getSocks5Enabled(): Int = 0
    fun getSocks5ProxyAddress(): String = ""
    fun getSocks5ProxyPort(): Int = 0
    fun getSocks5ProxyAuth(): String = ""
    fun malwareDetectionEnabled(): Int = 0
    fun firewallEnabled(): Int = 0          // M1: rule engine
    fun isTlsDecryptionEnabled(): Int = 0
    fun getWorkingDir(): String = cacheDir.absolutePath
    fun getPersistentDir(): String = filesDir.absolutePath
    fun getPcapdLogPath(): String = cacheDir.absolutePath + "/pcapd.log"
    fun getAppFilterUids(): IntArray = IntArray(0)
    fun getCaptureInterface(): String = ""
    fun getPcapDumperBpf(): String = ""
    fun getBlockQuickMode(): Int = 0
    fun getIPv4Enabled(): Int = 1
    fun getIPv6Enabled(): Int = 1
    fun getVpnMTU(): Int = VPN_MTU
    fun getVpnIPv4(): String = VPN_IP4
    fun getVpnDns(): String = VPN_DNS4
    fun getDnsServer(): String = dnsServer
    fun getIpv6DnsServer(): String = FALLBACK_DNS6

    companion object {
        private const val TAG = "CaptureService"
        const val ACTION_START = "io.github.cinnamon415.packetwall.START"
        const val ACTION_STOP = "io.github.cinnamon415.packetwall.STOP"
        private const val CHANNEL_ID = "status"
        private const val NOTIFY_ID = 1

        const val VPN_IP4 = "10.215.173.1"
        const val VPN_DNS4 = "10.215.173.2"
        const val VPN_IP6 = "fd00:2:fd00:1:fd00:1:fd00:1"
        const val VPN_MTU = 10000
        const val FALLBACK_DNS4 = "9.9.9.10"
        const val FALLBACK_DNS6 = "2620:fe::10"
        const val UID_UNKNOWN = -1

        val state = kotlinx.coroutines.flow.MutableStateFlow<CaptureState>(CaptureState.Stopped)

        init {
            System.loadLibrary("capture")
            initPlatformInfo(BuildConfig.VERSION_NAME, "${Build.MANUFACTURER} ${Build.MODEL}", "Android ${Build.VERSION.RELEASE}")
        }

        fun start(ctx: Context) {
            ContextCompat.startForegroundService(ctx, Intent(ctx, CaptureService::class.java).setAction(ACTION_START))
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, CaptureService::class.java).setAction(ACTION_STOP))
        }

        @JvmStatic external fun initPlatformInfo(appver: String, device: String, os: String)
        @JvmStatic external fun runPacketLoop(fd: Int, vpn: CaptureService, sdk: Int)
        @JvmStatic external fun stopPacketLoop()
        @JvmStatic external fun askStatsDump()
        @JvmStatic external fun setDnsServer(server: String)
        @JvmStatic external fun setPrivateDnsBlocked(block: Boolean)
        /** Private DNS is in strict mode: queries are encrypted, rules by name only see SNI. */
        val privateDnsStrict = kotlinx.coroutines.flow.MutableStateFlow(false)
        /** Loads a compiled rules file into the native engine; works while stopped too. */
        @JvmStatic external fun loadRules(path: String): Int
    }
}

sealed interface CaptureState {
    data object Stopped : CaptureState
    data class Running(val since: Long) : CaptureState
}
