package io.github.cinnamon415.packetwall.fw

import io.github.cinnamon415.packetwall.HttpStatusException
import java.io.BufferedReader
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Opens the text of a list subscription. */
fun interface ListSource {
    @Throws(IOException::class)
    fun open(url: String): BufferedReader
}

/** Plain HTTP(S) download with up to 5 redirects (also across http/https, which URLConnection refuses). */
class HttpListSource : ListSource {
    override fun open(url: String): BufferedReader {
        var u = URL(url)
        repeat(MAX_REDIRECTS) {
            val c = u.openConnection() as HttpURLConnection
            c.connectTimeout = 15_000
            c.readTimeout = 30_000
            c.instanceFollowRedirects = false
            c.setRequestProperty("User-Agent", "Packetwall")
            val code = c.responseCode
            if (code in 300..399) {
                val location = c.getHeaderField("Location") ?: throw IOException("HTTP $code without Location")
                c.disconnect()
                u = URL(u, location)
                return@repeat
            }
            if (code != 200) throw HttpStatusException(code)
            return c.inputStream.bufferedReader()
        }
        throw IOException("too many redirects")
    }

    private companion object {
        const val MAX_REDIRECTS = 5
    }
}
