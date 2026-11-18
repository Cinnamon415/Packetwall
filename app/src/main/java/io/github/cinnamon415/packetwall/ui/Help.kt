package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.R

/** Explanations behind the ⓘ next to settings that are not obvious. Paragraphs are separated by a blank line. */
enum class Help(val title: Int, val body: Int) {
    BUFFER(R.string.help_buffer_t, R.string.help_buffer),
    SNAPLEN(R.string.help_snaplen_t, R.string.help_snaplen),
    RECORD(R.string.help_record_t, R.string.help_record),
    LAN_BYPASS(R.string.help_lan_t, R.string.help_lan),
    UPSTREAM(R.string.help_upstream_t, R.string.help_upstream),
    UDP(R.string.help_udp_t, R.string.help_udp),
    KILL_SWITCH(R.string.help_kill_t, R.string.help_kill),
    DNS(R.string.help_dns_t, R.string.help_dns),
    REJECT(R.string.help_reject_t, R.string.help_reject),
    SET_PRIORITY(R.string.help_sets_t, R.string.help_sets),
    PROFILES(R.string.help_profiles_t, R.string.help_profiles),
    LOG_STORAGE(R.string.help_log_t, R.string.help_log),
    ALWAYS_ON(R.string.help_always_on_t, R.string.help_always_on)
}

/** A small ⓘ that opens the explanation of [topic]. */
@Composable
fun InfoButton(topic: Help) {
    var open by rememberSaveable { mutableStateOf(false) }
    IconButton({ open = true }, Modifier.size(36.dp)) {
        Icon(
            Icons.Outlined.Info,
            stringResource(R.string.help_about, stringResource(topic.title)),
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(20.dp)
        )
    }
    if (open) HelpSheet(topic) { open = false }
}

/** Title text followed by its ⓘ. */
@Composable
fun TitleWithInfo(text: String, topic: Help?, modifier: Modifier = Modifier, content: @Composable (String) -> Unit = { Text(it) }) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        content(text)
        if (topic != null) InfoButton(topic)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HelpSheet(topic: Help, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(stringResource(topic.title), style = MaterialTheme.typography.titleLarge)
            stringResource(topic.body).split("\n\n").forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
            Spacer(Modifier.height(4.dp))
            Button(onDismiss, Modifier.fillMaxWidth()) { Text(stringResource(R.string.help_ok)) }
        }
    }
}

/** "?" at the end of a filter field: opens [FilterHelpSheet]; an example replaces the filter. */
@Composable
fun FilterHelpButton(onInsert: (String) -> Unit) {
    var open by rememberSaveable { mutableStateOf(false) }
    val desc = stringResource(R.string.filter_help)
    IconButton({ open = true }, Modifier.semantics { contentDescription = desc }) {
        Text("?", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
    }
    if (open) {
        FilterHelpSheet({
            onInsert(it)
            open = false
        }) { open = false }
    }
}

/** Examples in the filter help (a test checks that they parse). */
val FILTER_EXAMPLES = listOf(
    "host ~ ads && !blocked",
    "app == \"Chrome\" && port == 443",
    "proto == DNS && blocked",
    "bytes > 1000000",
    "tracker && allowed",
    "!(proto == TLS) && port != 53"
)

/** The log filter: fields, operators and examples; tapping an example puts it into the filter. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilterHelpSheet(onInsert: (String) -> Unit, onDismiss: () -> Unit) {
    val fields = listOf(
        "app" to R.string.fh_app,
        "pkg" to R.string.fh_pkg,
        "host" to R.string.fh_host,
        "ip · port" to R.string.fh_ip,
        "proto" to R.string.fh_proto,
        "uid" to R.string.fh_uid,
        "bytes · sent · rcvd" to R.string.fh_bytes,
        "tracker" to R.string.fh_tracker,
        "blocked · allowed · active" to R.string.fh_flags
    )
    val examples = FILTER_EXAMPLES
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(stringResource(R.string.fh_title), style = MaterialTheme.typography.titleLarge)
            Text(stringResource(R.string.fh_intro), style = MaterialTheme.typography.bodyMedium)
            fields.forEach { (f, d) ->
                val desc = stringResource(d)
                val muted = MaterialTheme.colorScheme.onSurfaceVariant
                Text(
                    buildAnnotatedString {
                        withStyle(SpanStyle(fontFamily = FontFamily.Monospace)) { append(f) }
                        withStyle(SpanStyle(color = muted)) { append("  —  $desc") }
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
            }
            Text(
                stringResource(R.string.fh_ops_title),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(top = 6.dp)
            )
            Text("==  !=  ~  !~  <  <=  >  >=", fontFamily = FontFamily.Monospace)
            Text(stringResource(R.string.fh_ops), style = MaterialTheme.typography.bodyMedium)
            Text("&&  ||  !  ( )", fontFamily = FontFamily.Monospace)
            Text(stringResource(R.string.fh_logic), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(R.string.fh_examples), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
            examples.forEach { e ->
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    modifier = Modifier.fillMaxWidth().clickable { onInsert(e) }
                ) {
                    Text(e, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp))
                }
            }
        }
    }
}
