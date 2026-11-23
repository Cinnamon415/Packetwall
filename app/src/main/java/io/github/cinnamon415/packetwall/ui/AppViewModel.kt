package io.github.cinnamon415.packetwall.ui

import androidx.compose.runtime.Composable
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import io.github.cinnamon415.packetwall.PacketwallApp
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn

/**
 * A screen ViewModel built from the app's services. Scoped to the activity: the screens are not
 * separate navigation destinations, so state like the log filter outlives leaving and reopening a screen.
 */
@Composable
inline fun <reified VM : ViewModel> appViewModel(
    app: PacketwallApp,
    key: String? = null,
    crossinline create: (PacketwallApp, SavedStateHandle) -> VM
): VM = viewModel(key = key, factory = viewModelFactory { initializer { create(app, createSavedStateHandle()) } })

abstract class ScreenViewModel : ViewModel() {
    /** Computed while the screen collects it, and five more seconds (so a rotation does not restart it). */
    // onEach keeps stateIn from fusing with a flowOn upstream: fused, the sharing coroutine runs on that
    // dispatcher and the screen (seen in the log's filter) kept showing an older value. The work itself
    // still runs where flowOn puts it.
    protected fun <T> Flow<T>.whileShown(initial: T): StateFlow<T> =
        onEach { }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), initial)
}
