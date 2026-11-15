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
    )

    private val _values = MutableStateFlow(read())
    val values: StateFlow<Values> = _values
    val current get() = _values.value

    private fun read() = Values(
        capturePackets = prefs.getBoolean("capture_packets", true),
        bufferMb = prefs.getInt("buffer_mb", 16),
        snaplen = prefs.getInt("snaplen", 0),
    )

    fun update(fn: (Values) -> Values) {
        val v = fn(_values.value)
        prefs.edit()
            .putBoolean("capture_packets", v.capturePackets)
            .putInt("buffer_mb", v.bufferMb)
            .putInt("snaplen", v.snaplen)
            .apply()
        _values.value = v
    }

    companion object {
        val BUFFER_SIZES = listOf(4, 8, 16, 32, 64, 128)
        val SNAPLENS = listOf(0, 1514, 512, 128)
    }
}
