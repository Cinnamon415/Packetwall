package io.github.cinnamon415.packetwall.fw

import io.github.cinnamon415.packetwall.HttpStatusException
import io.github.cinnamon415.packetwall.engine.OwnTraffic
import java.io.BufferedReader
import java.io.IOException
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Request
import okhttp3.Response

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

/**
 * HTTP(S) download (redirects followed, also across http/https). Goes the way of Packetwall's own
 * traffic ([OwnTraffic]): through the upstream while protection sends everything there.
 */
class HttpListSource : ListSource {
    override fun open(url: String): BufferedReader = openIfChanged(url, null)!!.reader

    override fun openIfChanged(url: String, known: Validators?): Fetched? {
        val u = url.toHttpUrlOrNull() ?: throw IOException("not an http(s) URL: $url")
        val req = Request.Builder().url(u).header("User-Agent", "Packetwall").apply {
            known?.etag?.let { header("If-None-Match", it) }
            known?.lastModified?.let { header("If-Modified-Since", it) }
        }.build()
        val client = OwnTraffic.client(u.host).newBuilder().followRedirects(true).followSslRedirects(true).build()
        val r = client.newCall(req).execute()
        if (priorRedirects(r) > MAX_REDIRECTS) {
            r.close()
            throw IOException("too many redirects")
        }
        if (r.code == 304 && known != null) {
            r.close()
            return null
        }
        if (r.code != 200) {
            r.close()
            throw HttpStatusException(r.code)
        }
        val v = Validators(r.header("ETag"), r.header("Last-Modified"))
        return Fetched(r.body!!.charStream().buffered(), v.takeIf { it.etag != null || it.lastModified != null })
    }

    private fun priorRedirects(r: Response): Int {
        var n = 0
        var p = r.priorResponse
        while (p != null) {
            n++
            p = p.priorResponse
        }
        return n
    }

    private companion object {
        const val MAX_REDIRECTS = 5
    }
}
