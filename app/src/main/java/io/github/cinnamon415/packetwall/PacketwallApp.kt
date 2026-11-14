package io.github.cinnamon415.packetwall

import android.app.Application
import io.github.cinnamon415.packetwall.engine.AppsResolver
import io.github.cinnamon415.packetwall.engine.ConnectionsRegister

class PacketwallApp : Application() {
    lateinit var apps: AppsResolver
        private set
    lateinit var connections: ConnectionsRegister
        private set

    override fun onCreate() {
        super.onCreate()
        apps = AppsResolver(this)
        connections = ConnectionsRegister(apps)
    }
}
