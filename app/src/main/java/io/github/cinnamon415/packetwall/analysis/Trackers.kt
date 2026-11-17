package io.github.cinnamon415.packetwall.analysis

import android.util.Log
import android.util.LruCache
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Offline tracker labels: AdGuard companiesdb (https://github.com/AdguardTeam/companiesdb,
 * CC BY-SA 4.0), downloaded on request. Maps a host (and its parent domains) to a tracker name and
 * category.
 */
class Trackers(dir: File) {
    data class Tracker(val name: String, val category: Category)

    enum class Category(val ids: Set<Int>, val tracking: Boolean) {
        ADVERTISING(setOf(3, 4), true),
        ANALYTICS(setOf(6, 101), true),
        TELEMETRY(setOf(15), true),
        SOCIAL(setOf(7), true),
        OTHER(emptySet(), false);

        companion object {
            fun of(id: Int) = entries.firstOrNull { id in it.ids } ?: OTHER
        }
    }

    private val file = File(dir, "trackers.json")

    @Volatile private var domains: Map<String, Tracker> = emptyMap()
    private val cache = LruCache<String, Any>(4096)
    private val none = Any()

    data class Info(
        val loaded: Boolean = false,
        val domains: Int = 0,
        val updated: Long = 0,
        val busy: Boolean = false,
        val error: String? = null
    )
    private val _info = MutableStateFlow(Info())
    val info: StateFlow<Info> = _info

    init {
        load()
    }

    private fun load() {
        domains =
            try {
                if (file.exists()) parse(file.readText()) else emptyMap()
            } catch (e: Exception) {
                Log.w(TAG, "bad file", e)
                emptyMap()
            }
        cache.evictAll()
        _info.value = Info(domains.isNotEmpty(), domains.size, if (domains.isEmpty()) 0 else file.lastModified())
    }

    /** The tracker a host belongs to (also for subdomains of a listed domain), or null. */
    fun of(host: String?): Tracker? {
        if (host.isNullOrEmpty() || domains.isEmpty()) return null
        cache.get(host)?.let { return it as? Tracker }
        var h = host.lowercase()
        var found: Tracker? = null
        while (true) {
            domains[h]?.let { found = it }
            if (found != null) break
            val i = h.indexOf('.')
            if (i < 0) break
            h = h.substring(i + 1)
        }
        cache.put(host, found ?: none)
        return found
    }

    /** Only advertising / analytics / telemetry / social trackers (CDNs, hosting… are not labelled). */
    fun trackingOf(host: String?) = of(host)?.takeIf { it.category.tracking }

    fun download() {
        _info.value = _info.value.copy(busy = true, error = null)
        try {
            val text = OkHttpClient().newCall(Request.Builder().url(URL).header("User-Agent", "Packetwall").build())
                .execute().use { r ->
                    if (r.code != 200) throw IllegalStateException("HTTP ${r.code}")
                    r.body!!.string()
                }
            require(parse(text).isNotEmpty()) { "empty database" }
            val tmp = File(file.path + ".tmp")
            tmp.writeText(text)
            tmp.renameTo(file)
            load()
        } catch (e: Exception) {
            _info.value = _info.value.copy(busy = false, error = e.message ?: e.javaClass.simpleName)
        }
    }

    fun delete() {
        file.delete()
        load()
    }

    companion object {
        private const val TAG = "Trackers"
        const val URL = "https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/dist/trackers.json"

        fun parse(text: String): Map<String, Tracker> {
            val root = Json.parseToJsonElement(text).jsonObject
            val trackers = root["trackers"]!!.jsonObject
            val byId = trackers.mapValues { (_, v) ->
                val o = v.jsonObject
                Tracker(o["name"]?.jsonPrimitive?.contentOrNull ?: "?", Category.of(o["categoryId"]?.jsonPrimitive?.intOrNull ?: -1))
            }
            val out = HashMap<String, Tracker>()
            for ((domain, id) in root["trackerDomains"]!!.jsonObject) {
                byId[id.jsonPrimitive.contentOrNull]?.let { out[domain.lowercase()] = it }
            }
            return out
        }
    }
}
