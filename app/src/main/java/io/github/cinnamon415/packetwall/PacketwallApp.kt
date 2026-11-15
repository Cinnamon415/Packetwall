package io.github.cinnamon415.packetwall

import android.app.Application
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

    override fun onCreate() {
        super.onCreate()
        settings = Settings(this)
        apps = AppsResolver(this)
        connections = ConnectionsRegister(apps)
        firewall = FirewallStore(filesDir, apps, getString(R.string.set_default), getString(R.string.profile_default))
        firewall.scheduleCompile(0)
    }
}
