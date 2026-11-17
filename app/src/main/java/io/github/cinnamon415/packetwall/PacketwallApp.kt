package io.github.cinnamon415.packetwall

import android.app.Application
import android.content.ComponentName
import android.service.quicksettings.TileService
import io.github.cinnamon415.packetwall.analysis.ConnFilter
import io.github.cinnamon415.packetwall.analysis.DiskRecorder
import io.github.cinnamon415.packetwall.analysis.GeoIp
import io.github.cinnamon415.packetwall.analysis.PacketStore
import io.github.cinnamon415.packetwall.analysis.PcapServer
import io.github.cinnamon415.packetwall.analysis.Trackers
import io.github.cinnamon415.packetwall.engine.AppsResolver
import io.github.cinnamon415.packetwall.engine.CaptureService
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.ConnectionsRegister
import io.github.cinnamon415.packetwall.engine.LogDb
import io.github.cinnamon415.packetwall.fw.FirewallStore
import io.github.cinnamon415.packetwall.system.ProtectionTile
import io.github.cinnamon415.packetwall.system.ProtectionWidget
import io.github.cinnamon415.packetwall.system.Schedules
import java.io.File
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
    val pcapServer by lazy { PcapServer(packets) }
    val recorder by lazy { DiskRecorder(packets, File(filesDir, "captures")) }

    /** Starts/stops streaming and recording to match the settings while protection is on. */
    fun applySinks(running: Boolean) {
        val s = settings.current
        val wantStream = running && s.capturePackets && s.stream
        val st = pcapServer.state.value
        if (wantStream && (!st.running || st.port != s.streamPort || st.lan != s.streamLan)) {
            pcapServer.start(s.streamPort, s.streamLan)
        } else if (!wantStream && st.running) {
            pcapServer.stop()
        }
        val wantRec = running && s.capturePackets && s.record
        if (wantRec && !recorder.state.value.running) {
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

    override fun onCreate() {
        super.onCreate()
        settings = Settings(this)
        geo = GeoIp(filesDir)
        trackers = Trackers(filesDir)
        ConnFilter.trackerOf = { trackers.trackingOf(it)?.name }
        apps = AppsResolver(this)
        connections = ConnectionsRegister(apps)
        firewall = FirewallStore(
            dir = filesDir,
            uidOf = apps::uidOf,
            loader = CaptureService::loadRules,
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
            combine(settings.values, CaptureService.state) { s, st ->
                Triple(
                    listOf(s.stream, s.streamLan, s.record, s.capturePackets),
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
                CaptureService.state,
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
