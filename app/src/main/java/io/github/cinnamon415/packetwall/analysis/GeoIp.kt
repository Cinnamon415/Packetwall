package io.github.cinnamon415.packetwall.analysis

import android.util.Log
import android.util.LruCache
import io.github.cinnamon415.packetwall.HttpStatusException
import io.github.cinnamon415.packetwall.Problem
import java.io.File
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale
import java.util.zip.GZIPInputStream
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Country and AS lookups for rules and the connection screen, backed by the free DB-IP
 * "IP to Country Lite" and "IP to ASN Lite" databases (CC BY 4.0), downloaded on request.
 */
class GeoIp(dir: File) {
    private val geoDir = File(dir, "geo").apply { mkdirs() }
    private val countryFile = File(geoDir, "country.mmdb")
    private val asnFile = File(geoDir, "asn.mmdb")
    private val prefixDir = File(geoDir, "asn-prefixes").apply { mkdirs() }

    @Volatile private var country: MmdbReader? = null

    @Volatile private var asnDb: MmdbReader? = null
    private val countryCache = LruCache<String, String>(4096)
    private val asnCache = LruCache<String, Pair<Long, String>>(4096)

    data class Db(val loaded: Boolean = false, val build: String = "", val sizeMb: Float = 0f)
    data class Info(val country: Db = Db(), val asn: Db = Db(), val error: Problem? = null, val busy: Boolean = false) {
        val loaded get() = country.loaded
    }
    private val _info = MutableStateFlow(Info())
    val info: StateFlow<Info> = _info

    /** Called after a database changes (rules with ASN targets must be recompiled). */
    var onChanged: (() -> Unit)? = null

    init {
        open()
    }

    private fun load(f: File): MmdbReader? = try {
        if (f.exists()) MmdbReader(f) else null
    } catch (e: Exception) {
        Log.w(TAG, "bad db ${f.name}", e)
        null
    }

    private fun dbInfo(r: MmdbReader?, f: File) = if (r == null) {
        Db()
    } else {
        Db(
            true,
            (r.metadata["build_epoch"] as? Number)?.let { SimpleDateFormat("yyyy-MM-dd", Locale.US).format(it.toLong() * 1000) } ?: "",
            f.length() / 1048576f
        )
    }

    private fun open() {
        country = load(countryFile)
        asnDb = load(asnFile)
        countryCache.evictAll()
        asnCache.evictAll()
        _info.value = Info(dbInfo(country, countryFile), dbInfo(asnDb, asnFile))
    }

    /** ISO country code ("" if unknown). Called from the capture thread for every new connection. */
    fun country(ip: String): String {
        val r = country ?: return ""
        countryCache.get(ip)?.let { return it }
        val cc = try {
            @Suppress("UNCHECKED_CAST")
            val rec = r.lookup(InetAddress.getByName(ip)) as? Map<String, Any?>
            ((rec?.get("country") as? Map<String, Any?>)?.get("iso_code") as? String) ?: ""
        } catch (e: Exception) {
            ""
        }
        countryCache.put(ip, cc)
        return cc
    }

    /** AS number and organization of an address, or null. */
    fun asn(ip: String): Pair<Long, String>? {
        val r = asnDb ?: return null
        asnCache.get(ip)?.let { return it.takeIf { it.first > 0 } }
        val v = try {
            @Suppress("UNCHECKED_CAST")
            val rec = r.lookup(InetAddress.getByName(ip)) as? Map<String, Any?>
            val n = (rec?.get("autonomous_system_number") as? Number)?.toLong() ?: 0L
            n to ((rec?.get("autonomous_system_organization") as? String) ?: "")
        } catch (e: Exception) {
            0L to ""
        }
        asnCache.put(ip, v)
        return v.takeIf { it.first > 0 }
    }

    /**
     * All prefixes announced by the given ASes, from one walk of the database tree. Results are cached
     * per database build in files, so recompiling rules is cheap.
     */
    @Synchronized
    fun asnPrefixes(asns: Set<Long>): Map<Long, List<String>> {
        val r = asnDb ?: return emptyMap()
        val build = _info.value.asn.build
        val out = HashMap<Long, List<String>>()
        val missing = HashSet<Long>()
        for (a in asns) {
            val f = File(prefixDir, "$build-$a.txt")
            if (f.exists()) out[a] = f.readLines().filter { it.isNotBlank() } else missing.add(a)
        }
        if (missing.isNotEmpty()) {
            val t0 = System.currentTimeMillis()
            val byOffset = HashMap<Int, Long>()
            val found = HashMap<Long, MutableList<String>>()
            missing.forEach { found[it] = ArrayList() }
            // one walk; the record of each network is decoded once per distinct data offset
            r.networks { off ->
                byOffset.getOrPut(off) {
                    @Suppress("UNCHECKED_CAST")
                    ((r.decodeAt(off) as? Map<String, Any?>)?.get("autonomous_system_number") as? Number)?.toLong() ?: 0L
                } in missing
            }.let { nets ->
                // networks() does not say which AS matched: redo the mapping by lookup (cheap, few prefixes)
                for (net in nets) {
                    val addr = net.substringBefore('/')
                    val n = asn(addr)?.first ?: continue
                    found[n]?.add(net)
                }
            }
            for ((a, l) in found) {
                File(prefixDir, "$build-$a.txt").writeText(l.joinToString("\n"))
                out[a] = l
            }
            Log.i(TAG, "expanded ASNs $missing in ${System.currentTimeMillis() - t0} ms: ${found.mapValues { it.value.size }}")
        }
        return out
    }

    /** Downloads both databases for the current month (falls back to the previous month). Blocking. */
    fun download() {
        _info.value = _info.value.copy(busy = true, error = null)
        var err: Problem? = null
        for ((kind, file) in listOf("country" to countryFile, "asn" to asnFile)) {
            err = fetch(kind, file) ?: err
        }
        prefixDir.listFiles()?.forEach { it.delete() }
        open()
        _info.value = _info.value.copy(error = err)
        onChanged?.invoke()
    }

    /** Returns the problem of the last attempt, null when the database was downloaded. */
    private fun fetch(kind: String, file: File): Problem? {
        val fmt = SimpleDateFormat("yyyy-MM", Locale.US)
        val cal = Calendar.getInstance()
        var last: Problem? = null
        repeat(2) {
            val url = "https://download.db-ip.com/free/dbip-$kind-lite-${fmt.format(cal.time)}.mmdb.gz"
            try {
                val tmp = File(geoDir, "${file.name}.tmp")
                OkHttpClient().newCall(Request.Builder().url(url).header("User-Agent", "Packetwall").build()).execute().use { r ->
                    if (r.code != 200) throw HttpStatusException(r.code)
                    GZIPInputStream(r.body!!.byteStream()).use { input -> tmp.outputStream().use { input.copyTo(it) } }
                }
                MmdbReader(tmp) // validate
                tmp.renameTo(file)
                return null
            } catch (e: Exception) {
                Log.w(TAG, "GeoIP $kind download", e)
                last = Problem.of(e)
                cal.add(Calendar.MONTH, -1)
            }
        }
        return last
    }

    fun delete() {
        countryFile.delete()
        asnFile.delete()
        prefixDir.listFiles()?.forEach { it.delete() }
        open()
        onChanged?.invoke()
    }

    companion object {
        private const val TAG = "GeoIp"
    }
}
