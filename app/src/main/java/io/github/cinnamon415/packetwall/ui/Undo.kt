package io.github.cinnamon415.packetwall.ui

import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.staticCompositionLocalOf
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/** Shows "Deleted · Undo" at the bottom of the screen; [onUndo] runs when the user taps Undo. */
class UndoController(private val scope: CoroutineScope, val host: SnackbarHostState, private val undoLabel: String) {
    fun offer(message: String, onUndo: () -> Unit) {
        scope.launch {
            host.currentSnackbarData?.dismiss()
            val r = host.showSnackbar(message, actionLabel = undoLabel, withDismissAction = true, duration = SnackbarDuration.Long)
            if (r == SnackbarResult.ActionPerformed) onUndo()
        }
    }
}

val LocalUndo = staticCompositionLocalOf<UndoController?> { null }
