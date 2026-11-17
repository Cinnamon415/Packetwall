package io.github.cinnamon415.packetwall

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** App settings (SharedPreferences), exposed as flows for the UI. */
class Settings(ctx: Context, private val box: SecretBox = SecretBox.keystore()) {
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
        /** true = all traffic through the upstream, false = only allow rules with route "via upstream". */
        val upAll: Boolean = true,
        /** 0 = SOCKS5, 1 = HTTP CONNECT. */
        val upType: Int = 0,
        /** 0 = UDP goes direct, 1 = UDP is blocked (apps fall back to TCP), 2 = through SOCKS5 UDP ASSOCIATE. */
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
        /** Private networks (LAN, adb over Wi-Fi…) are routed outside the VPN: not filtered, not logged. */
        val lanBypass: Boolean = false,
        /** Persist only blocked connections (spec 6: "statistics and blocks only"). */
        val logBlockedOnly: Boolean = false,
        // Streaming to a PC (pcap-over-IP) and continuous recording to disk
        val stream: Boolean = false,
        val streamPort: Int = 57012,
        val streamLan: Boolean = false,
        val record: Boolean = false,
        val recordMb: Int = 32,
        val recordMinutes: Int = 60,
        val recordKeep: Int = 5
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
        upPass = readPassword(),
        upApp = prefs.getString("up_app", null) ?: "",
        upUdp = prefs.getInt("up_udp", 1),
        upType = prefs.getInt("up_type", 0),
        upAll = prefs.getBoolean("up_all", true),
        upOnDown = prefs.getInt("up_down", 0),
        listsAutoUpdate = prefs.getBoolean("lists_auto", true),
        listsWifiOnly = prefs.getBoolean("lists_wifi", true),
        backupUri = prefs.getString("backup_uri", null) ?: "",
        lastBackup = prefs.getLong("last_backup", 0),
        logDays = prefs.getInt("log_days", 0),
        lanBypass = prefs.getBoolean("lan_bypass", false),
        logBlockedOnly = prefs.getBoolean("log_blocked_only", false),
        stream = prefs.getBoolean("stream", false), streamPort = prefs.getInt("stream_port", 57012),
        streamLan = prefs.getBoolean("stream_lan", false), record = prefs.getBoolean("record", false),
        recordMb = prefs.getInt(
            "record_mb",
            32
        ),
        recordMinutes = prefs.getInt("record_min", 60), recordKeep = prefs.getInt("record_keep", 5)
    )

    /**
     * The proxy password is stored encrypted ([SecretBox]). A plaintext value (older versions, or
     * written by the debug test configuration) is encrypted and removed on the first read.
     */
    private fun readPassword(): String {
        prefs.getString(KEY_PASS_PLAIN, null)?.let { plain ->
            prefs.edit().putString(KEY_PASS, box.seal(plain)).remove(KEY_PASS_PLAIN).apply()
            return plain
        }
        return prefs.getString(KEY_PASS, null)?.let { box.open(it) } ?: ""
    }

    /** Re-reads the preferences (after they were written outside this class, e.g. by tests). */
    fun reload() {
        _values.value = read()
    }

    fun update(fn: (Values) -> Values) {
        val old = _values.value
        val v = fn(old)
        val edit = prefs.edit()
        if (v.upPass != old.upPass) edit.putString(KEY_PASS, box.seal(v.upPass))
        edit
            .putBoolean("capture_packets", v.capturePackets)
            .putInt("buffer_mb", v.bufferMb)
            .putInt("snaplen", v.snaplen)
            .putInt("dns_mode", v.dnsMode)
            .putString("doh_url", v.dohUrl)
            .putBoolean("up", v.upstream).putString("up_host", v.upHost).putInt("up_port", v.upPort)
            .putString("up_user", v.upUser).putString("up_app", v.upApp)
            .putInt("up_udp", v.upUdp).putInt("up_down", v.upOnDown).putInt("up_type", v.upType).putBoolean("up_all", v.upAll)
            .putBoolean("lists_auto", v.listsAutoUpdate).putBoolean("lists_wifi", v.listsWifiOnly)
            .putString("backup_uri", v.backupUri).putLong("last_backup", v.lastBackup)
            .putInt("log_days", v.logDays).putBoolean("lan_bypass", v.lanBypass).putBoolean("log_blocked_only", v.logBlockedOnly)
            .putBoolean("stream", v.stream).putInt("stream_port", v.streamPort).putBoolean("stream_lan", v.streamLan)
            .putBoolean(
                "record",
                v.record
            ).putInt("record_mb", v.recordMb).putInt("record_min", v.recordMinutes).putInt("record_keep", v.recordKeep)
            .apply()
        _values.value = v
    }

    companion object {
        private const val KEY_PASS = "up_pass_enc"
        private const val KEY_PASS_PLAIN = "up_pass"
        val BUFFER_SIZES = listOf(4, 8, 16, 32, 64, 128)
        val SNAPLENS = listOf(0, 1514, 512, 128)
        val LOG_DAYS = listOf(0, 1, 7, 30)
    }
}
