package io.github.cinnamon415.packetwall

import android.content.Context
import io.github.cinnamon415.packetwall.analysis.PcapServer
import io.github.cinnamon415.packetwall.fw.ForeignImport
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InterruptedIOException
import java.net.BindException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.zip.ZipException
import javax.net.ssl.SSLException
import kotlinx.serialization.SerializationException

/** A server answered with a status other than 200. */
class HttpStatusException(val code: Int) : IOException("HTTP $code")

/** Downloaded or imported data is not what was expected (empty, wrong format, corrupt). */
open class BadDataException(msg: String) : IOException(msg)

/**
 * A failure as the user sees it. Code turns exceptions into a [Problem] with [of]; the UI shows
 * [message], in the user's language. [encode]/[decode] keep it in saved state as a short code;
 * strings that are not a known code (older saved messages) decode to [Other].
 */
sealed interface Problem {
    data object Offline : Problem

    data object Timeout : Problem

    /** The TLS connection to the server failed (certificate, protocol). */
    data object Secure : Problem

    data class Http(val code: Int) : Problem

    data object BadData : Problem

    /** Over the size limits (see Limits), or out of memory reading it. */
    data object TooLarge : Problem

    data class PortInUse(val port: Int) : Problem

    data object FileAccess : Problem

    /** No Wi-Fi or Ethernet network to listen on. */
    data object NoLan : Problem

    data class Unsupported(val reason: ForeignImport.Unsupported.Reason) : Problem

    /** Anything else, with the technical detail (English, for bug reports). */
    data class Other(val detail: String) : Problem

    fun encode(): String = when (this) {
        Offline -> "offline"
        Timeout -> "timeout"
        Secure -> "tls"
        is Http -> "http:$code"
        BadData -> "bad-data"
        TooLarge -> "too-large"
        is PortInUse -> "port:$port"
        FileAccess -> "file"
        NoLan -> "no-lan"
        is Unsupported -> "unsupported:${reason.name}"
        is Other -> detail
    }

    fun message(ctx: Context): String = when (this) {
        Offline -> ctx.getString(R.string.problem_offline)
        Timeout -> ctx.getString(R.string.problem_timeout)
        Secure -> ctx.getString(R.string.problem_tls)
        is Http -> ctx.getString(if (code == 404) R.string.problem_http_404 else R.string.problem_http, code)
        BadData -> ctx.getString(R.string.problem_bad_data)
        TooLarge -> ctx.getString(R.string.problem_too_large)
        is PortInUse -> ctx.getString(R.string.problem_port, port)
        FileAccess -> ctx.getString(R.string.problem_file)
        NoLan -> ctx.getString(R.string.problem_no_lan)
        is Unsupported -> ctx.getString(
            when (reason) {
                ForeignImport.Unsupported.Reason.SINGBOX_BINARY -> R.string.problem_srs_binary
                ForeignImport.Unsupported.Reason.RETHINK_NO_DB -> R.string.problem_rethink_no_db
            }
        )
        is Other -> ctx.getString(R.string.problem_other, detail)
    }

    companion object {
        fun of(e: Throwable, port: Int = 0): Problem = when (e) {
            is HttpStatusException -> Http(e.code)
            is TooLargeException, is OutOfMemoryError -> TooLarge
            is PcapServer.NoLanException -> NoLan
            is BadDataException, is SerializationException, is ZipException -> BadData
            is ForeignImport.Unsupported -> Unsupported(e.reason)
            is BindException -> PortInUse(port)
            is UnknownHostException, is ConnectException, is NoRouteToHostException -> Offline
            is SocketTimeoutException -> Timeout
            is SSLException -> Secure
            is FileNotFoundException, is SecurityException -> FileAccess
            // OkHttp reports a call timeout as an InterruptedIOException("timeout")
            is InterruptedIOException -> Timeout
            is IllegalArgumentException -> BadData
            else -> Other(e.message ?: e.javaClass.simpleName)
        }

        fun decode(s: String): Problem = when {
            s == "offline" -> Offline
            s == "timeout" -> Timeout
            s == "tls" -> Secure
            s == "bad-data" -> BadData
            s == "too-large" -> TooLarge
            s == "file" -> FileAccess
            s == "no-lan" -> NoLan
            s.startsWith("http:") -> s.substring(5).toIntOrNull()?.let(::Http) ?: Other(s)
            s.startsWith("port:") -> s.substring(5).toIntOrNull()?.let(::PortInUse) ?: Other(s)
            s.startsWith("unsupported:") ->
                ForeignImport.Unsupported.Reason.entries.firstOrNull { it.name == s.substring(12) }?.let(::Unsupported) ?: Other(s)
            else -> Other(s)
        }
    }
}
