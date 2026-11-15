package io.github.cinnamon415.packetwall

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** App settings (SharedPreferences), exposed as flows for the UI. */
class Settings(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)

    data class Values(
        /** Keep packets in memory for the packets/data views and pcapng export. */
        val capturePackets: Boolean = true,
        /** Packet buffer size in MiB (oldest packets are dropped first). */
        val bufferMb: Int = 16,
        /** Max bytes stored per packet, 0 = whole packet. */
        val snaplen: Int = 0,
        /** 0 = system DNS, 1 = built-in DNS-over-HTTPS. */
        val dnsMode: Int = 0,
        val dohUrl: String = "https://1.1.1.1/dns-query",
        // Upstream chain (SOCKS5)
        val upstream: Boolean = false,
        val upHost: String = "127.0.0.1",
        val upPort: Int = 1080,
        val upUser: String = "",
        val upPass: String = "",
        /** Package of the proxy app, excluded from the VPN to avoid a loop. */
        val upApp: String = "",
        /** 0 = UDP goes direct, 1 = UDP is blocked (apps fall back to TCP through the upstream). */
        val upUdp: Int = 1,
        /** 0 = kill switch (block when the upstream is down), 1 = go direct. */
        val upOnDown: Int = 0,
        // Schedules
        val listsAutoUpdate: Boolean = true,
        val listsWifiOnly: Boolean = true,
        /** Tree URI of the backup folder (SAF), empty = no automatic backup. */
        val backupUri: String = "",
        val lastBackup: Long = 0,
        /** Connection log retention in days, 0 = current session only. */
        val logDays: Int = 0,
    )

    private val _values = MutableStateFlow(read())
    val values: StateFlow<Values> = _values
    val current get() = _values.value

    private fun read() = Values(
        capturePackets = prefs.getBoolean("capture_packets", true),
        bufferMb = prefs.getInt("buffer_mb", 16),
        snaplen = prefs.getInt("snaplen", 0),
        dnsMode = prefs.getInt("dns_mode", 0),
        dohUrl = prefs.getString("doh_url", null) ?: "https://1.1.1.1/dns-query",
        upstream = prefs.getBoolean("up", false),
        upHost = prefs.getString("up_host", null) ?: "127.0.0.1",
        upPort = prefs.getInt("up_port", 1080),
        upUser = prefs.getString("up_user", null) ?: "",
        upPass = prefs.getString("up_pass", null) ?: "",
        upApp = prefs.getString("up_app", null) ?: "",
        upUdp = prefs.getInt("up_udp", 1),
        upOnDown = prefs.getInt("up_down", 0),
        listsAutoUpdate = prefs.getBoolean("lists_auto", true),
        listsWifiOnly = prefs.getBoolean("lists_wifi", true),
        backupUri = prefs.getString("backup_uri", null) ?: "",
        lastBackup = prefs.getLong("last_backup", 0),
        logDays = prefs.getInt("log_days", 0),
    )

    fun update(fn: (Values) -> Values) {
        val v = fn(_values.value)
        prefs.edit()
            .putBoolean("capture_packets", v.capturePackets)
            .putInt("buffer_mb", v.bufferMb)
            .putInt("snaplen", v.snaplen)
            .putInt("dns_mode", v.dnsMode)
            .putString("doh_url", v.dohUrl)
            .putBoolean("up", v.upstream).putString("up_host", v.upHost).putInt("up_port", v.upPort)
            .putString("up_user", v.upUser).putString("up_pass", v.upPass).putString("up_app", v.upApp)
            .putInt("up_udp", v.upUdp).putInt("up_down", v.upOnDown)
            .putBoolean("lists_auto", v.listsAutoUpdate).putBoolean("lists_wifi", v.listsWifiOnly)
            .putString("backup_uri", v.backupUri).putLong("last_backup", v.lastBackup)
            .putInt("log_days", v.logDays)
            .apply()
        _values.value = v
    }

    companion object {
        val BUFFER_SIZES = listOf(4, 8, 16, 32, 64, 128)
        val SNAPLENS = listOf(0, 1514, 512, 128)
        val LOG_DAYS = listOf(0, 1, 7, 30)
    }
}
