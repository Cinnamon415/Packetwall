/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * VPN setup adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda.
 */
package io.github.cinnamon415.packetwall.engine

import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import android.widget.Toast
import androidx.core.content.ContextCompat
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.Settings
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * The VPN service: starts and stops the native packet loop ([NativeBridge]) together with the
 * pieces around it — DNS (system server or the DoH [DnsProxy]), the [UpstreamMonitor] and the
 * [NetworkTracker] — and publishes its state in [CaptureStatus].
 */
class CaptureService : VpnService() {
    private val app get() = application as PacketwallApp
    private val handler = Handler(Looper.getMainLooper())

    // Start and stop run one after another on this thread (compiling, resolving the proxy and
    // establishing the VPN take time and must not block the main thread or race each other).
    private val control = Executors.newSingleThreadExecutor { Thread(it, "CaptureControl") }
    private val pendingStarts = AtomicInteger()

    @Volatile private var lastStartId = 0

    @Volatile private var session = 0

    @Volatile private var pfd: ParcelFileDescriptor? = null

    @Volatile private var loopThread: Thread? = null

    @Volatile private var bridge: NativeBridge? = null

    @Volatile private var dohProxy: DnsProxy? = null
    @Volatile private var dohDirect: DnsProxy? = null

    @Volatile private var upstream: UpstreamMonitor? = null

    @Volatile private var networks: NetworkTracker? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        if (intent?.action == ACTION_PAUSE || intent?.action == ACTION_RESUME) {
            val pause = intent.action == ACTION_PAUSE && CaptureStatus.packetsKept.value
            CaptureStatus.pausedSince.value = if (pause) System.currentTimeMillis() else null
            if (CaptureStatus.running) startForegroundCompat() // the notification shows the new state
            return START_STICKY
        }
        if (intent?.action == ACTION_STOP) {
            control.execute { stopCapture() }
            return START_NOT_STICKY
        }
        // the notification offers Pause only when packets are kept (read again at start below)
        CaptureStatus.packetsKept.value = app.settings.current.capturePackets
        // within 5 s of startForegroundService(): here, not on the control thread, which may be busy
        startForegroundCompat()
        pendingStarts.incrementAndGet()
        control.execute {
            pendingStarts.decrementAndGet()
            if (loopThread?.isAlive != true) startCapture()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // another VPN took over, or the user revoked the permission
        control.execute { stopCapture() }
        super.onRevoke()
    }

    override fun onDestroy() {
        control.execute { stopCapture() }
        control.shutdown()
        super.onDestroy()
    }

    /** Control thread only. */
    private fun startCapture() {
        // Makes this app the system's current VPN again when the user consented before (the
        // package was updated, or started from the tile or widget); an Intent means no consent.
        if (prepare(this) != null) {
            Log.w(TAG, "no VPN consent")
            showError(getString(R.string.err_vpn_consent))
            cleanup()
            return
        }
        val st = app.settings.current
        val cm = getSystemService(ConnectivityManager::class.java)
        app.firewall.compileNow()
        app.packets.reset(st.bufferMb.toLong() shl 20)

        val b = NativeBridge(this, app, ::showError)
        bridge = b
        b.forwardDns = cm?.let { NetworkTracker.firstIpv4Dns(NetworkTracker.activeLinkProperties(it)) } ?: VpnSetup.FALLBACK_DNS4
        cm?.let { onLinkChanged(NetworkTracker.activeLinkProperties(it), initial = true) }

        b.upstreamIp = if (st.upstream) UpstreamMonitor.resolve(st.upHost) else null
        if (st.upstream && b.upstreamIp == null) showError(getString(R.string.upstream_bad_host, st.upHost))
        NativeBridge.setUpstreamHttp(st.upType == TYPE_HTTP)
        NativeBridge.setUpstreamScope(st.upAll)
        val monitor = if (st.upstream) UpstreamMonitor(st.upHost, b.upstreamIp, st) else null
        upstream = monitor

        startDoh(st, b, monitor, proxyAppUid(st))
        Log.i(TAG, "starting capture, DNS ${b.forwardDns}")

        val builder = Builder().setConfigureIntent(CaptureNotification.openApp(this))
        // Packetwall's own traffic (DoH, list downloads, the upstream connections) goes straight to the network.
        // The local proxy app is NOT excluded: with "Block connections without VPN" Android cuts excluded
        // apps off. Its connections pass through the engine, which sends them out directly (setProxyApp).
        VpnSetup.configure(builder, getString(R.string.app_name), st.lanBypass, listOf(packageName))
        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "VPN establish failed", e)
            null
        }
        if (fd == null) {
            showError(getString(R.string.err_vpn_setup))
            cleanup()
            return
        }
        pfd = fd
        if (monitor != null) {
            // replies to ping go straight into the tun interface, towards the app
            val tun = java.io.FileOutputStream(fd.fileDescriptor)
            b.icmp = IcmpProbe(
                proxy = { (monitor.ip ?: b.upstreamIp)?.let { java.net.InetSocketAddress(it, st.upPort) } },
                http = st.upType == TYPE_HTTP,
                user = st.upUser,
                pass = st.upPass
            ) { packet -> synchronized(tun) { tun.write(packet) } }
        }
        app.connections.reset()
        CaptureStatus.alwaysOn.value = isAlwaysOn to isLockdownEnabled
        val startedAt = System.currentTimeMillis()
        CaptureStatus.sessionStart.value = startedAt
        CaptureStatus.packetsKept.value = st.capturePackets
        if (!st.capturePackets) CaptureStatus.pausedSince.value = null
        CaptureStatus.state.value = CaptureState.Running(startedAt)

        networks = cm?.let { NetworkTracker(it) { lp -> onLinkChanged(lp) }.also(NetworkTracker::start) }
        if (monitor != null) {
            monitor.start()
        } else {
            NativeBridge.setUpstreamState(true, false)
            NativeBridge.setUdpRelay("", 0)
        }
        val mySession = ++session
        loopThread = Thread({
            try {
                b.run(fd.fd)
            } catch (e: Throwable) {
                Log.e(TAG, "packet loop crashed", e)
            }
            Log.i(TAG, "packet loop exited")
            // the loop ended by itself (not through stopCapture, which cleans up synchronously)
            control.execute { if (session == mySession && pfd != null) cleanup() }
        }, "PacketLoop").also { it.start() }
    }

    /**
     * The DoH proxy: when DoH is chosen, and always when all traffic goes through the upstream, so
     * that DNS does not leak around it (plain DNS to the network's resolver would). Through the
     * upstream it follows the proxy: blocked while it is down with the kill switch.
     */
    private fun startDoh(st: Settings.Values, b: NativeBridge, monitor: UpstreamMonitor?, proxyUid: Int) {
        dohProxy?.stop()
        dohProxy = null
        dohDirect?.stop()
        dohDirect = null
        val viaUpstream = monitor != null && st.upAll
        if (st.dnsMode == DNS_DOH || viaUpstream) {
            val route: () -> DnsRoute = if (monitor != null && viaUpstream) monitor::dnsRoute else ({ DnsRoute.Direct })
            DnsProxy.resetStats()
            dohProxy = try {
                DnsProxy(st.dohUrl, route).also { it.start() }
            } catch (e: Exception) {
                Log.e(TAG, "DoH proxy", e)
                null
            }
        }
        val p = dohProxy
        if (p != null) {
            b.forwardDns = "127.0.0.1"
            NativeBridge.setDnsServerPort(p.port)
        } else {
            NativeBridge.setDnsServerPort(53)
        }
        CaptureStatus.dohActive.value = p?.let { st.dohUrl }
        // The proxy app may need DNS to reach its server: its queries never go through itself
        if (proxyUid >= 0 && p != null && viaUpstream) {
            dohDirect = try {
                DnsProxy(st.dohUrl).also { it.start() }
            } catch (e: Exception) {
                Log.e(TAG, "direct DoH proxy", e)
                null
            }
        }
        NativeBridge.setProxyApp(proxyUid, dohDirect?.port ?: 0)
    }

    /** UID of the local upstream proxy app, or -1 (none, not installed, or Packetwall itself). */
    private fun proxyAppUid(st: Settings.Values): Int {
        val pkg = st.upApp.takeIf { st.upstream && it.isNotEmpty() && it != packageName } ?: return -1
        return try {
            packageManager.getApplicationInfo(pkg, 0).uid
        } catch (e: Exception) {
            Log.w(TAG, "proxy app $pkg not found")
            -1
        }
    }

    /**
     * Private DNS in "automatic" mode is blocked, so Android falls back to plain DNS the firewall can
     * see (as PCAPdroid does); in strict mode names stay hidden and the UI shows a notice. Checking
     * isPrivateDnsActive is not enough: it is per network, and the VPN network may enable it while
     * the underlying one did not.
     */
    private fun onLinkChanged(lp: LinkProperties?, initial: Boolean = false) {
        if (lp == null) return
        val strict = lp.privateDnsServerName != null
        NativeBridge.setPrivateDnsBlocked(!strict)
        CaptureStatus.privateDnsStrict.value = strict
        val b = bridge ?: return
        val dns = NetworkTracker.firstIpv4Dns(lp) ?: return
        if (dns != b.forwardDns && dohProxy == null) {
            Log.i(TAG, "DNS server changed: ${b.forwardDns} -> $dns")
            b.forwardDns = dns
            if (!initial) NativeBridge.setDnsServer(dns)
        }
    }

    /** Releases everything started by [startCapture]. Control thread only, after the loop exited. */
    private fun cleanup() {
        bridge?.icmp?.stop()
        bridge?.icmp = null
        networks?.stop()
        networks = null
        NativeBridge.setPrivateDnsBlocked(false)
        upstream?.stop()
        upstream = null
        dohProxy?.stop()
        dohProxy = null
        dohDirect?.stop()
        dohDirect = null
        NativeBridge.setProxyApp(-1, 0)
        CaptureStatus.dohActive.value = null
        NativeBridge.setDnsServerPort(53)
        try {
            pfd?.close()
        } catch (e: Exception) {
            Log.w(TAG, "closing the tun fd", e)
        }
        pfd = null
        loopThread = null
        bridge = null
        CaptureStatus.state.value = CaptureState.Stopped
        CaptureStatus.pausedSince.value = null
        // a start that came in meanwhile keeps the service (and its notification) alive
        if (pendingStarts.get() == 0) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelfResult(lastStartId)
        }
    }

    /** Control thread only: waits for the loop to end, so a following start never sees it alive. */
    private fun stopCapture() {
        val t = loopThread
        if (t?.isAlive == true) {
            session++ // the loop's own cleanup callback is now stale
            NativeBridge.stopPacketLoop()
            t.join(LOOP_STOP_TIMEOUT_MS)
            if (t.isAlive) Log.w(TAG, "packet loop did not stop in time")
        }
        if (pfd != null || bridge != null || CaptureStatus.running) {
            cleanup()
        } else if (pendingStarts.get() == 0) {
            stopSelfResult(lastStartId) // nothing was running: do not leave an idle service behind
        }
    }

    private fun showError(msg: String) {
        handler.post { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
    }

    private fun startForegroundCompat() {
        val n = CaptureNotification.build(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(CaptureNotification.ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(CaptureNotification.ID, n)
        }
    }

    companion object {
        private const val TAG = "CaptureService"
        const val ACTION_START = "io.github.cinnamon415.packetwall.START"
        const val ACTION_STOP = "io.github.cinnamon415.packetwall.STOP"
        const val ACTION_PAUSE = "io.github.cinnamon415.packetwall.PAUSE"
        const val ACTION_RESUME = "io.github.cinnamon415.packetwall.RESUME"
        private const val DNS_DOH = 1
        private const val LOOP_STOP_TIMEOUT_MS = 5000L

        fun start(ctx: Context) {
            ContextCompat.startForegroundService(ctx, Intent(ctx, CaptureService::class.java).setAction(ACTION_START))
        }

        /** Pauses or resumes the capture (the rules keep filtering). */
        fun setPaused(ctx: Context, paused: Boolean) {
            ctx.startService(Intent(ctx, CaptureService::class.java).setAction(if (paused) ACTION_PAUSE else ACTION_RESUME))
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, CaptureService::class.java).setAction(ACTION_STOP))
        }
    }
}
