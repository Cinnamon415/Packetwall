package io.github.cinnamon415.packetwall

import android.app.Application
import android.content.ComponentName
import android.content.res.Configuration
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.service.quicksettings.TileService
import io.github.cinnamon415.packetwall.analysis.ConnFilter
import io.github.cinnamon415.packetwall.analysis.DiskRecorder
import io.github.cinnamon415.packetwall.analysis.GeoIp
import io.github.cinnamon415.packetwall.analysis.PacketStore
import io.github.cinnamon415.packetwall.analysis.PcapServer
import io.github.cinnamon415.packetwall.analysis.Trackers
import io.github.cinnamon415.packetwall.engine.AppsResolver
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.CaptureStatus
import io.github.cinnamon415.packetwall.engine.ConnectionsRegister
import io.github.cinnamon415.packetwall.engine.LogDb
import io.github.cinnamon415.packetwall.engine.NativeBridge
import io.github.cinnamon415.packetwall.fw.FirewallStore
import io.github.cinnamon415.packetwall.system.ProtectionTile
import io.github.cinnamon415.packetwall.system.ProtectionWidget
import io.github.cinnamon415.packetwall.system.Schedules
import io.github.cinnamon415.packetwall.ui.Units
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class PacketwallApp : Application() {
    lateinit var apps: AppsResolver
        private set
    lateinit var connections: ConnectionsRegister
        private set
    lateinit var firewall: FirewallStore
        private set
    lateinit var settings: Settings
        private set
    val packets = PacketStore()
    val pcapServer by lazy { PcapServer(packets, "$packageName.pcap", ::lanAddress) }

    /** The IPv4 address of the Wi-Fi or Ethernet network (not the VPN), for the LAN stream. */
    private fun lanAddress(): InetAddress? {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return null
        @Suppress("DEPRECATION") // allNetworks: the callback API would be overkill for a one-off lookup
        return cm.allNetworks.asSequence()
            .filter { n ->
                val c = cm.getNetworkCapabilities(n) ?: return@filter false
                !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
            }
            .flatMap { cm.getLinkProperties(it)?.linkAddresses.orEmpty().asSequence() }
            .map { it.address }
            .firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
    }
    val recorder by lazy { DiskRecorder(packets, File(filesDir, "captures")) }

    private var streamToken = ""

    /** Starts/stops streaming and recording to match the settings while protection is on. */
    @Synchronized
    fun applySinks(running: Boolean) {
        val s = settings.current
        val wantStream = running && s.capturePackets && s.stream
        val st = pcapServer.state.value
        if (wantStream && s.streamLan && s.streamToken.isEmpty()) {
            settings.update { it.copy(streamToken = PcapServer.newToken()) } // applySinks runs again
            return
        }
        if (wantStream &&
            (!st.running || st.lan != s.streamLan || (s.streamLan && (st.port != s.streamPort || streamToken != s.streamToken)))
        ) {
            streamToken = s.streamToken
            pcapServer.start(s.streamPort, s.streamLan, s.streamToken)
        } else if (!wantStream && st.running) {
            pcapServer.stop()
        }
        val wantRec = running && s.capturePackets && s.record
        val rec = recorder.state.value
        val recChanged = rec.maxMb != s.recordMb || rec.maxMinutes != s.recordMinutes || rec.keep != s.recordKeep
        if (wantRec && (!rec.running || recChanged)) {
            recorder.start(s.recordMb, s.recordMinutes, s.recordKeep)
        } else if (!wantRec && recorder.state.value.running) {
            recorder.stop()
        }
    }
    val logDb by lazy { LogDb(this) }
    lateinit var geo: GeoIp
        private set
    lateinit var trackers: Trackers
        private set

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        Units.load(this)
    }

    override fun onCreate() {
        super.onCreate()
        Units.load(this)
        settings = Settings(this)
        geo = GeoIp(filesDir)
        trackers = Trackers(filesDir)
        ConnFilter.trackerOf = { trackers.trackingOf(it)?.name }
        apps = AppsResolver(this)
        connections = ConnectionsRegister(apps)
        firewall = FirewallStore(
            dir = filesDir,
            uidOf = apps::uidOf,
            loader = NativeBridge::loadRules,
            defaultSetName = getString(R.string.set_default),
            defaultProfileName = getString(R.string.profile_default),
            asnPrefixes = geo::asnPrefixes
        )
        geo.onChanged = { firewall.scheduleCompile() }
        firewall.scheduleCompile(0)
        watchStatus()
        // (re)schedule periodic jobs whenever their settings change
        CoroutineScope(Dispatchers.Default).launch {
            settings.values.collect { s -> Schedules.apply(this@PacketwallApp, s) }
        }
        CoroutineScope(Dispatchers.Default).launch {
            settings.values.map { it.logDays to it.logBlockedOnly }.distinctUntilChanged().collect { (d, b) ->
                connections.blockedOnly = b
                connections.configureLog(logDb, d)
            }
        }
        CoroutineScope(Dispatchers.IO).launch {
            combine(settings.values, CaptureStatus.state) { s, st ->
                Triple(
                    listOf(s.stream, s.streamLan, s.record, s.capturePackets, s.streamToken),
                    listOf(s.streamPort, s.recordMb, s.recordMinutes, s.recordKeep),
                    st is CaptureState.Running
                )
            }.distinctUntilChanged().collect { (_, _, running) -> applySinks(running) }
        }
    }

    /** Keeps the quick settings tile and the widget in sync with the protection state and profile. */
    private fun watchStatus() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
        scope.launch {
            combine(
                CaptureStatus.state,
                firewall.state
            ) { st, fw -> (st is CaptureState.Running) to fw.activeProfile }
                .distinctUntilChanged()
                .collect {
                    TileService.requestListeningState(
                        this@PacketwallApp,
                        ComponentName(this@PacketwallApp, ProtectionTile::class.java)
                    )
                    ProtectionWidget.update(this@PacketwallApp)
                }
        }
    }
}
