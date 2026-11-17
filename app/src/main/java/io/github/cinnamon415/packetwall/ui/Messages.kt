package io.github.cinnamon415.packetwall.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import io.github.cinnamon415.packetwall.Problem
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.analysis.ConnFilter
import io.github.cinnamon415.packetwall.fw.ForeignImport

/** Localized texts for the typed results of the non-UI code. */
@Composable
fun problemText(p: Problem): String = p.message(LocalContext.current)

@Composable
fun noteText(n: ForeignImport.Note): String = when (n.kind) {
    ForeignImport.NoteKind.PCAPDROID_WHITELIST -> stringResource(R.string.note_pcapdroid_whitelist)
    ForeignImport.NoteKind.PARTIAL_NETWORK -> stringResource(R.string.note_partial_network, n.count)
    ForeignImport.NoteKind.NETGUARD_DEFAULT_BLOCK -> stringResource(R.string.note_netguard_default_block)
    ForeignImport.NoteKind.NETGUARD_PORT_FORWARDING -> stringResource(R.string.note_netguard_ports)
    ForeignImport.NoteKind.AFWALL_ALLOWLIST -> stringResource(R.string.note_afwall_allowlist)
    ForeignImport.NoteKind.AFWALL_COLUMNS -> stringResource(R.string.note_afwall_columns)
    ForeignImport.NoteKind.SINGBOX_NO_EQUIVALENT -> stringResource(R.string.note_singbox_no_equivalent)
    ForeignImport.NoteKind.LIST_IMPORTANT -> stringResource(R.string.note_list_important)
    ForeignImport.NoteKind.LIST_APP_RULES -> stringResource(R.string.note_list_app_rules)
    ForeignImport.NoteKind.RETHINK_BYPASS -> stringResource(R.string.note_rethink_bypass)
    ForeignImport.NoteKind.RETHINK_EXCLUDED -> stringResource(R.string.note_rethink_excluded)
    ForeignImport.NoteKind.RETHINK_ISOLATED -> stringResource(R.string.note_rethink_isolated)
}

@Composable
fun parseErrorText(e: ConnFilter.ParseError): String = when (e.kind) {
    ConnFilter.ParseError.Kind.UNEXPECTED -> stringResource(R.string.filter_unexpected, e.token)
    ConnFilter.ParseError.Kind.UNTERMINATED_STRING -> stringResource(R.string.filter_unterminated)
    ConnFilter.ParseError.Kind.UNEXPECTED_END -> stringResource(R.string.filter_unexpected_end)
    ConnFilter.ParseError.Kind.MISSING_PAREN -> stringResource(R.string.filter_missing_paren)
    ConnFilter.ParseError.Kind.UNKNOWN_FIELD -> stringResource(R.string.filter_unknown_field, e.token)
    ConnFilter.ParseError.Kind.EXPECTED_OPERATOR -> stringResource(R.string.filter_expected_operator, e.token)
}
