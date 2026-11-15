package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.Settings

@Composable
fun SettingsScreen(app: PacketwallApp, openDrawer: () -> Unit) {
    val s by app.settings.values.collectAsState()
    ScreenScaffold(title = stringResource(R.string.nav_settings), onMenu = openDrawer) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
            ListSubheader(stringResource(R.string.settings_analysis))
            RoundedGroup {
                Row(Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(capturePackets = !it.capturePackets) } }
                    .padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.capture_packets))
                        Text(stringResource(R.string.capture_packets_hint), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(s.capturePackets, { v -> app.settings.update { it.copy(capturePackets = v) } })
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                ChoiceRow(stringResource(R.string.buffer_size), Settings.BUFFER_SIZES, s.bufferMb, { "$it MB" }) { v ->
                    app.settings.update { it.copy(bufferMb = v) }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                ChoiceRow(stringResource(R.string.snaplen), Settings.SNAPLENS, s.snaplen,
                    { if (it == 0) stringResource(R.string.snaplen_full) else "$it B" }) { v -> app.settings.update { it.copy(snaplen = v) } }
            }
            Text(stringResource(R.string.settings_apply_hint), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 4.dp, top = 6.dp))
            ListSubheader(stringResource(R.string.settings_storage))
            RoundedGroup {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                    Text(stringResource(R.string.storage_session))
                    Text(stringResource(R.string.storage_session_hint), style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun <T> ChoiceRow(title: String, options: List<T>, value: T, label: @Composable (T) -> String, onPick: (T) -> Unit) {
    Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
        Text(title)
        Row(Modifier.horizontalScroll(rememberScrollState()).padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            options.forEach { o -> FilterChip(o == value, { onPick(o) }, { Text(label(o)) }) }
        }
    }
}
