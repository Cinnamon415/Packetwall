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
import java.net.InetSocketAddress
import java.net.Proxy

/**
 * The VPN service: starts and stops the native packet loop ([NativeBridge]) together with the
 * pieces around it — DNS (system server or the DoH [DnsProxy]), the [UpstreamMonitor] and the
 * [NetworkTracker] — and publishes its state in [CaptureStatus].
 */
class CaptureService : VpnService() {
    private val app get() = application as PacketwallApp
    private val handler = Handler(Looper.getMainLooper())
    private var pfd: ParcelFileDescriptor? = null
    private var loopThread: Thread? = null
    private var bridge: NativeBridge? = null
    private var dohProxy: DnsProxy? = null
    private var upstream: UpstreamMonitor? = null
    private var networks: NetworkTracker? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopCapture()
            return START_NOT_STICKY
        }
        startForegroundCompat()
        if (loopThread?.isAlive != true) startCapture()
        return START_STICKY
    }

    override fun onRevoke() {
        // another VPN took over, or the user revoked the permission
        stopCapture()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

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

        startDoh(st, b)
        Log.i(TAG, "starting capture, DNS ${b.forwardDns}")

        val builder = Builder().setConfigureIntent(CaptureNotification.openApp(this))
        // Packetwall's own traffic (DoH, list downloads) and the upstream proxy app go straight to the network
        val excluded = listOfNotNull(packageName, st.upApp.takeIf { b.upstreamIp != null && it.isNotEmpty() && it != packageName })
        VpnSetup.configure(builder, getString(R.string.app_name), st.lanBypass, excluded, dohProxy = dohProxy != null)
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
        app.connections.reset()
        CaptureStatus.state.value = CaptureState.Running(System.currentTimeMillis())

        networks = cm?.let { NetworkTracker(it) { lp -> onLinkChanged(lp) }.also(NetworkTracker::start) }
        val ip = b.upstreamIp
        if (ip != null) {
            upstream = UpstreamMonitor(ip, st).also(UpstreamMonitor::start)
        } else {
            NativeBridge.setUpstreamState(true, false)
            NativeBridge.setUdpRelay("", 0)
        }
        loopThread = Thread({
            try {
                b.run(fd.fd)
            } catch (e: Throwable) {
                Log.e(TAG, "packet loop crashed", e)
            }
            Log.i(TAG, "packet loop exited")
            handler.post { cleanup() }
        }, "PacketLoop").also { it.start() }
    }

    /** The DoH proxy, when enabled; DoH goes through the upstream for HTTP proxies and SOCKS5 without login. */
    private fun startDoh(st: Settings.Values, b: NativeBridge) {
        dohProxy?.stop()
        dohProxy = null
        if (st.dnsMode == DNS_DOH) {
            val viaProxy = b.upstreamIp?.takeIf { st.upType == TYPE_HTTP || st.upUser.isEmpty() }?.let {
                Proxy(if (st.upType == TYPE_HTTP) Proxy.Type.HTTP else Proxy.Type.SOCKS, InetSocketAddress(it, st.upPort))
            }
            val auth = if (st.upType == TYPE_HTTP && st.upUser.isNotEmpty()) st.upUser to st.upPass else null
            DnsProxy.resetStats()
            dohProxy = try {
                DnsProxy(st.dohUrl, viaProxy, auth).also { it.start() }
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

    /** Releases everything started by [startCapture]; runs on the main thread once the loop exited. */
    private fun cleanup() {
        networks?.stop()
        networks = null
        NativeBridge.setPrivateDnsBlocked(false)
        upstream?.stop()
        upstream = null
        dohProxy?.stop()
        dohProxy = null
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
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopCapture() {
        if (loopThread?.isAlive == true) {
            NativeBridge.stopPacketLoop() // cleanup follows when the loop exits
        } else if (CaptureStatus.running || pfd != null) {
            cleanup()
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
        private const val DNS_DOH = 1

        fun start(ctx: Context) {
            ContextCompat.startForegroundService(ctx, Intent(ctx, CaptureService::class.java).setAction(ACTION_START))
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, CaptureService::class.java).setAction(ACTION_STOP))
        }
    }
}
