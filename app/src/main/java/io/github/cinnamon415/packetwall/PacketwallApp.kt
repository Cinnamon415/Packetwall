package io.github.cinnamon415.packetwall

import android.app.Application
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import io.github.cinnamon415.packetwall.engine.AppsResolver
import io.github.cinnamon415.packetwall.engine.ConnectionsRegister
import io.github.cinnamon415.packetwall.fw.FirewallStore
import io.github.cinnamon415.packetwall.analysis.PacketStore

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
    val pcapServer by lazy { io.github.cinnamon415.packetwall.analysis.PcapServer(packets) }
    val recorder by lazy { io.github.cinnamon415.packetwall.analysis.DiskRecorder(packets, java.io.File(filesDir, "captures")) }

    /** Starts/stops streaming and recording to match the settings while protection is on. */
    fun applySinks(running: Boolean) {
        val s = settings.current
        val wantStream = running && s.capturePackets && s.stream
        val st = pcapServer.state.value
        if (wantStream && (!st.running || st.port != s.streamPort || st.lan != s.streamLan)) pcapServer.start(s.streamPort, s.streamLan)
        else if (!wantStream && st.running) pcapServer.stop()
        val wantRec = running && s.capturePackets && s.record
        if (wantRec && !recorder.state.value.running) recorder.start(s.recordMb, s.recordMinutes, s.recordKeep)
        else if (!wantRec && recorder.state.value.running) recorder.stop()
    }
    val logDb by lazy { io.github.cinnamon415.packetwall.engine.LogDb(this) }
    lateinit var geo: io.github.cinnamon415.packetwall.analysis.GeoIp
        private set
    lateinit var trackers: io.github.cinnamon415.packetwall.analysis.Trackers
        private set

    override fun onCreate() {
        super.onCreate()
        settings = Settings(this)
        geo = io.github.cinnamon415.packetwall.analysis.GeoIp(filesDir)
        trackers = io.github.cinnamon415.packetwall.analysis.Trackers(filesDir)
        io.github.cinnamon415.packetwall.analysis.ConnFilter.trackerOf = { trackers.trackingOf(it)?.name }
        apps = AppsResolver(this)
        connections = ConnectionsRegister(apps)
        firewall = FirewallStore(filesDir, apps, getString(R.string.set_default), getString(R.string.profile_default), geo::asnPrefixes)
        geo.onChanged = { firewall.scheduleCompile() }
        firewall.scheduleCompile(0)
        watchStatus()
        // (re)schedule periodic jobs whenever their settings change
        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            settings.values.collect { s -> io.github.cinnamon415.packetwall.system.Schedules.apply(this@PacketwallApp, s) }
        }
        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            settings.values.map { it.logDays to it.logBlockedOnly }.distinctUntilChanged().collect { (d, b) ->
                connections.blockedOnly = b
                connections.configureLog(logDb, d)
            }
        }
        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
            kotlinx.coroutines.flow.combine(settings.values, io.github.cinnamon415.packetwall.engine.CaptureService.state) { s, st ->
                Triple(listOf(s.stream, s.streamLan, s.record, s.capturePackets), listOf(s.streamPort, s.recordMb, s.recordMinutes, s.recordKeep),
                    st is io.github.cinnamon415.packetwall.engine.CaptureState.Running)
            }.distinctUntilChanged().collect { (_, _, running) -> applySinks(running) }
        }
    }

    /** Keeps the quick settings tile and the widget in sync with the protection state and profile. */
    private fun watchStatus() {
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Main)
        scope.launch {
            kotlinx.coroutines.flow.combine(io.github.cinnamon415.packetwall.engine.CaptureService.state,
                firewall.state) { st, fw -> (st is io.github.cinnamon415.packetwall.engine.CaptureState.Running) to fw.activeProfile }
                .distinctUntilChanged()
                .collect {
                    android.service.quicksettings.TileService.requestListeningState(this@PacketwallApp,
                        android.content.ComponentName(this@PacketwallApp, io.github.cinnamon415.packetwall.system.ProtectionTile::class.java))
                    io.github.cinnamon415.packetwall.system.ProtectionWidget.update(this@PacketwallApp)
                }
        }
    }
}
