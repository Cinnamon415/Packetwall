/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * Native callbacks adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda.
 */
package io.github.cinnamon415.packetwall.engine

import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.util.Log
import io.github.cinnamon415.packetwall.BuildConfig
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.engine.model.BlacklistDescriptor
import io.github.cinnamon415.packetwall.engine.model.CaptureStats
import io.github.cinnamon415.packetwall.engine.model.ConnectionDescriptor
import io.github.cinnamon415.packetwall.engine.model.ConnectionUpdate
import java.net.InetSocketAddress

/**
 * The JNI surface of the native engine (jni_impl.c, capture_vpn.c, uid_resolver.c, pw_rules.c).
 *
 * The native code finds this class by name and calls the instance methods below by name and
 * signature from the capture thread: keep both stable (see docs/NATIVE_CHANGES.md). The external
 * functions control the engine while it runs; [loadRules] also works while it is stopped.
 */
class NativeBridge(private val vpn: VpnService, private val app: PacketwallApp, private val onError: (String) -> Unit) {
    /** Plain DNS server the engine forwards queries to. */
    @Volatile var forwardDns: String = VpnSetup.FALLBACK_DNS4

    /** Resolved address of the upstream proxy, null when it is not used. */
    @Volatile var upstreamIp: String? = null

    private val settings get() = app.settings.current
    private val connectivity by lazy { vpn.getSystemService(ConnectivityManager::class.java) }

    /** Blocks until [stopPacketLoop]. */
    fun run(tunFd: Int) = runPacketLoop(tunFd, this, Build.VERSION.SDK_INT)

    // ---------------- callbacks ----------------

    fun reportError(msg: String) {
        Log.e(TAG, "native error: $msg")
        onError(msg)
    }

    fun protect(socket: Int): Boolean = vpn.protect(socket)

    fun getApplicationByUid(uid: Int): String = app.apps.get(uid).name

    fun getPackageNameByUid(uid: Int): String = app.apps.get(uid).packageName

    fun loadUidMapping(uid: Int, packageName: String, appName: String) {}

    fun getCountryCode(host: String): String = app.geo.country(host)

    fun dumpPcapData(data: ByteArray) = app.packets.feed(data)

    fun stopPcapDump() {}

    fun startConnectionsUpdate() {}

    fun updateConnections(newConns: Array<ConnectionDescriptor?>?, updates: Array<ConnectionUpdate?>?) {
        app.connections.onUpdate(newConns, updates)
    }

    fun sendStatsDump(stats: CaptureStats) {
        app.connections.onStats(stats)
    }

    fun sendServiceStatus(status: String) {
        Log.i(TAG, "service status: $status")
    }

    fun getLibprogPath(prog: String): String = vpn.applicationInfo.nativeLibraryDir + "/lib" + prog + ".so"

    fun notifyBlacklistsLoaded(loaded: Array<Blacklists.NativeBlacklistStatus>) {}

    fun getBlacklistsInfo(): Array<BlacklistDescriptor> = emptyArray()

    fun checkAvailableHeap() {}

    /** Owner of a connection (uid_resolver.c). */
    fun getUidQ(protocol: Int, saddr: String, sport: Int, daddr: String, dport: Int): Int {
        if (protocol != 6 && protocol != 17) return UID_UNKNOWN
        val cm = connectivity ?: return UID_UNKNOWN
        return try {
            cm.getConnectionOwnerUid(protocol, InetSocketAddress(saddr, sport), InetSocketAddress(daddr, dport))
        } catch (e: Exception) {
            UID_UNKNOWN
        }
    }

    // ---------------- configuration read by the native code at startup ----------------

    fun getMitmAddonUid(): Int = -1

    fun isVpnCapture(): Int = 1

    fun isRootCapture(): Int = 0

    fun isPcapFileCapture(): Int = 0

    fun getPayloadMode(): Int = 0

    fun pcapDumpEnabled(): Int = if (settings.capturePackets) 1 else 0

    fun dumpExtensionsEnabled(): Int = 1

    fun isPcapngEnabled(): Int = 1

    fun getSnaplen(): Int = settings.snaplen

    fun getMaxPktsPerFlow(): Int = 0

    fun getMaxDumpSize(): Int = 0

    // configured but not resolved: an unroutable address, so the kill switch holds (UpstreamMonitor)
    fun getSocks5Enabled(): Int = if (settings.upstream) 1 else 0

    fun getSocks5ProxyAddress(): String = upstreamIp ?: UpstreamMonitor.UNROUTABLE

    fun getSocks5ProxyPort(): Int = settings.upPort

    fun getSocks5ProxyUser(): String = settings.upUser

    fun getSocks5ProxyPass(): String = settings.upPass

    fun malwareDetectionEnabled(): Int = 0

    /** PCAPdroid's own firewall; Packetwall's rules run in pw_rules.c instead. */
    fun firewallEnabled(): Int = 0

    fun isTlsDecryptionEnabled(): Int = 0

    fun getWorkingDir(): String = vpn.cacheDir.absolutePath

    fun getPersistentDir(): String = vpn.filesDir.absolutePath

    fun getPcapdLogPath(): String = vpn.cacheDir.absolutePath + "/pcapd.log"

    fun getAppFilterUids(): IntArray = IntArray(0)

    fun getCaptureInterface(): String = ""

    fun getPcapDumperBpf(): String = ""

    fun getBlockQuickMode(): Int = 0

    fun getIPv4Enabled(): Int = 1

    fun getIPv6Enabled(): Int = 1

    fun getVpnMTU(): Int = VpnSetup.MTU

    fun getVpnIPv4(): String = VpnSetup.IP4

    fun getVpnDns(): String = VpnSetup.DNS4

    fun getDnsServer(): String = forwardDns

    fun getIpv6DnsServer(): String = VpnSetup.FALLBACK_DNS6

    companion object {
        private const val TAG = "NativeBridge"
        const val UID_UNKNOWN = -1

        init {
            System.loadLibrary("capture")
            // the native debug log names every host: release builds log warnings and errors only
            setLogLevel(if (BuildConfig.DEBUG) Log.DEBUG else Log.WARN)
            initPlatformInfo(BuildConfig.VERSION_NAME, "${Build.MANUFACTURER} ${Build.MODEL}", "Android ${Build.VERSION.RELEASE}")
        }

        @JvmStatic external fun setLogLevel(level: Int)

        @JvmStatic external fun initPlatformInfo(appver: String, device: String, os: String)

        @JvmStatic private external fun runPacketLoop(fd: Int, bridge: NativeBridge, sdk: Int)

        @JvmStatic external fun stopPacketLoop()

        @JvmStatic external fun askStatsDump()

        @JvmStatic external fun setDnsServer(server: String)

        /** Drops DoT (port 853) to the known DNS servers so Android falls back to plain DNS. */
        @JvmStatic external fun setPrivateDnsBlocked(block: Boolean)

        /** Port the VPN DNS address is redirected to (53, or the DoH proxy's local port). */
        @JvmStatic external fun setDnsServerPort(port: Int)

        /** [active]: send through the upstream proxy; [blockUdp]: drop UDP that would go through it. */
        @JvmStatic external fun setUpstreamState(active: Boolean, blockUdp: Boolean)

        /** The upstream is an HTTP CONNECT proxy (else SOCKS5). */
        @JvmStatic external fun setUpstreamHttp(http: Boolean)

        /** All traffic goes through the upstream (else only allow rules with route "upstream"). */
        @JvmStatic external fun setUpstreamScope(all: Boolean)

        /** New address of the upstream proxy (re-resolved while running); new connections use it. */
        @JvmStatic external fun setUpstreamAddress(ip: String, port: Int)

        /** SOCKS5 UDP relay address; empty = none. */
        @JvmStatic external fun setUdpRelay(ip: String, port: Int)

        /** Loads a compiled rules file (RulesCompiler) into the native engine; works while stopped too. */
        @JvmStatic external fun loadRules(path: String): Int
    }
}
