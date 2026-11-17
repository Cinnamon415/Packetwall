package io.github.cinnamon415.packetwall.fw

import io.github.cinnamon415.packetwall.HttpStatusException
import java.io.BufferedReader
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** HTTP validators of a downloaded list. */
data class Validators(val etag: String?, val lastModified: String?)

/** A downloaded list and its validators. */
class Fetched(val reader: BufferedReader, val validators: Validators?)

/** Opens the text of a list subscription. */
fun interface ListSource {
    @Throws(IOException::class)
    fun open(url: String): BufferedReader

    /** Like [open], but null when the server says nothing changed since [known] (HTTP 304). */
    @Throws(IOException::class)
    fun openIfChanged(url: String, known: Validators?): Fetched? = Fetched(open(url), null)
}

/** Plain HTTP(S) download with up to 5 redirects (also across http/https, which URLConnection refuses). */
class HttpListSource : ListSource {
    override fun open(url: String): BufferedReader = openIfChanged(url, null)!!.reader

    override fun openIfChanged(url: String, known: Validators?): Fetched? {
        var u = URL(url)
        repeat(MAX_REDIRECTS) {
            val c = u.openConnection() as HttpURLConnection
            c.connectTimeout = 15_000
            c.readTimeout = 30_000
            c.instanceFollowRedirects = false
            c.setRequestProperty("User-Agent", "Packetwall")
            known?.etag?.let { c.setRequestProperty("If-None-Match", it) }
            known?.lastModified?.let { c.setRequestProperty("If-Modified-Since", it) }
            val code = c.responseCode
            if (code == 304 && known != null) {
                c.disconnect()
                return null
            }
            if (code in 300..399) {
                val location = c.getHeaderField("Location") ?: throw IOException("HTTP $code without Location")
                c.disconnect()
                u = URL(u, location)
                return@repeat
            }
            if (code != 200) throw HttpStatusException(code)
            val v = Validators(c.getHeaderField("ETag"), c.getHeaderField("Last-Modified"))
            return Fetched(c.inputStream.bufferedReader(), v.takeIf { it.etag != null || it.lastModified != null })
        }
        throw IOException("too many redirects")
    }

    private companion object {
        const val MAX_REDIRECTS = 5
    }
}
