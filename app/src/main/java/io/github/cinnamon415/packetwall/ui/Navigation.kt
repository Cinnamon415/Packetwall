package io.github.cinnamon415.packetwall.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/** Navigation destinations. Top-level ones are reachable from the drawer. */
@Serializable
sealed interface Dest {
    @Serializable data object Home : Dest

    @Serializable data object Logs : Dest

    @Serializable data object Stats : Dest

    @Serializable data object Apps : Dest

    @Serializable data object Global : Dest

    @Serializable data object Blocklists : Dest

    @Serializable data object Sets : Dest

    @Serializable data object Settings : Dest

    @Serializable data object About : Dest

    @Serializable data object Files : Dest

    /** The capture file open in [OpenedFile]. */
    @Serializable data object FileView : Dest

    /** [file]: a connection of the opened capture file, not of the live capture. */
    @Serializable data class Connection(val id: Int, val tab: Int = 0, val file: Boolean = false) : Dest

    @Serializable data class AppRules(val pkg: String) : Dest

    @Serializable data class Packet(val connId: Int, val seq: Long, val file: Boolean = false) : Dest

    @Serializable data class GroupRules(val id: Int) : Dest
}

/** The back stack. Survives configuration changes and process death (see [rememberNavigator]). */
class Navigator(initial: List<Dest> = listOf(Dest.Home)) {
    val stack = mutableStateListOf<Dest>().apply { addAll(initial.ifEmpty { listOf(Dest.Home) }) }
    val current: Dest get() = stack.last()

    /** Opens a top-level screen: the stack becomes Home (+ that screen). */
    fun root(d: Dest) {
        stack.clear()
        if (d != Dest.Home) stack.add(Dest.Home)
        stack.add(d)
    }

    fun push(d: Dest) {
        stack.add(d)
    }

    fun replace(d: Dest) {
        stack[stack.lastIndex] = d
    }

    fun pop(): Boolean {
        if (stack.size <= 1) return false
        stack.removeAt(stack.lastIndex)
        return true
    }

    companion object {
        private val serializer = ListSerializer(Dest.serializer())

        val saver: Saver<Navigator, String> = Saver(
            save = { Json.encodeToString(serializer, it.stack.toList()) },
            restore = { Navigator(runCatching { Json.decodeFromString(serializer, it) }.getOrDefault(emptyList())) }
        )
    }
}

@Composable
fun rememberNavigator(): Navigator = rememberSaveable(saver = Navigator.saver) { Navigator() }
