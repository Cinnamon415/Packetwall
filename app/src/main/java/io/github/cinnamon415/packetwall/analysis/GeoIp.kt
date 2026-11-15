package io.github.cinnamon415.packetwall.analysis

import android.util.Log
import android.util.LruCache
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale
import java.util.zip.GZIPInputStream

/**
 * Country lookup for rules and the connection screen, backed by the free DB-IP "IP to Country
 * Lite" database (CC BY 4.0), downloaded on request into filesDir/geo.
 */
class GeoIp(dir: File) {
    private val geoDir = File(dir, "geo").apply { mkdirs() }
    private val file = File(geoDir, "country.mmdb")
    @Volatile private var reader: MmdbReader? = null
    private val cache = LruCache<String, String>(4096)

    data class Info(val loaded: Boolean = false, val build: String = "", val sizeMb: Float = 0f, val error: String? = null, val busy: Boolean = false)
    private val _info = MutableStateFlow(Info())
    val info: StateFlow<Info> = _info

    init { open() }

    private fun open() {
        reader = try {
            if (file.exists()) MmdbReader(file) else null
        } catch (e: Exception) {
            Log.w(TAG, "bad database", e); null
        }
        cache.evictAll()
        val r = reader
        _info.value = if (r == null) Info() else Info(true,
            (r.metadata["build_epoch"] as? Number)?.let { SimpleDateFormat("yyyy-MM-dd", Locale.US).format(it.toLong() * 1000) } ?: "",
            file.length() / 1048576f)
    }

    /** ISO country code ("" if unknown). Called from the capture thread for every new connection. */
    fun country(ip: String): String {
        val r = reader ?: return ""
        cache.get(ip)?.let { return it }
        val cc = try {
            @Suppress("UNCHECKED_CAST")
            val rec = r.lookup(InetAddress.getByName(ip)) as? Map<String, Any?>
            ((rec?.get("country") as? Map<String, Any?>)?.get("iso_code") as? String) ?: ""
        } catch (e: Exception) { "" }
        cache.put(ip, cc)
        return cc
    }

    /** Downloads the current month's database (falls back to the previous month). Blocking. */
    fun download() {
        _info.value = _info.value.copy(busy = true, error = null)
        val fmt = SimpleDateFormat("yyyy-MM", Locale.US)
        val cal = Calendar.getInstance()
        var last: Exception? = null
        repeat(2) {
            val url = "https://download.db-ip.com/free/dbip-country-lite-${fmt.format(cal.time)}.mmdb.gz"
            try {
                val tmp = File(geoDir, "country.mmdb.tmp")
                okhttp3.OkHttpClient().newCall(okhttp3.Request.Builder().url(url).header("User-Agent", "Packetwall").build()).execute().use { r ->
                    if (r.code != 200) throw IllegalStateException("HTTP ${r.code}")
                    GZIPInputStream(r.body!!.byteStream()).use { input -> tmp.outputStream().use { input.copyTo(it) } }
                }
                MmdbReader(tmp)   // validate
                tmp.renameTo(file)
                open()
                return
            } catch (e: Exception) {
                last = e
                cal.add(Calendar.MONTH, -1)
            }
        }
        _info.value = _info.value.copy(busy = false, error = last?.message ?: "error")
    }

    fun delete() { file.delete(); open() }

    companion object { private const val TAG = "GeoIp" }
}
