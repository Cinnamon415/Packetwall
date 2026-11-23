package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull

/** What the rule editor should be filled with. */
data class RuleSpec(
    val value: String = "",
    val kind: TargetKind = TargetKind.DOMAIN,
    val action: Action = Action.BLOCK,
    val subdomains: Boolean = true,
    val proto: String? = null,
    val port: Int? = null,
    val reject: Boolean = false,
    val set: String? = null,
    val route: Int? = null
)

private val kindLabel = mapOf(
    TargetKind.ALL to R.string.target_all,
    TargetKind.DOMAIN to R.string.target_domain,
    TargetKind.IP to R.string.target_ip,
    TargetKind.ASN to R.string.kind_asn,
    TargetKind.COUNTRY to R.string.target_country
)

private val placeholder = mapOf(
    TargetKind.DOMAIN to "ads.example.com",
    TargetKind.IP to "203.0.113.0/24",
    TargetKind.ASN to "AS13335",
    TargetKind.COUNTRY to "US"
)

/** Fills the open rule editor dialog (new or existing rule) and saves it. */
fun E2eTest.fillRuleEditor(s: RuleSpec, save: Boolean = true) {
    waitText(str(R.string.rule_set))
    tap(str(if (s.action == Action.BLOCK) R.string.action_block else R.string.action_allow))
    dialogChip(str(kindLabel.getValue(s.kind)))
    if (s.kind != TargetKind.ALL) {
        val inDialog = hasSetTextAction() and androidx.compose.ui.test.hasAnyAncestor(androidx.compose.ui.test.isDialog())
        val fields = ui.onAllNodes(inDialog)
        // the target field is the first text field of the dialog
        val idx = visible(inDialog).first()
        fields[idx].performTextClearance()
        fields[idx].performTextInput(s.value)
        ui.waitForIdle()
    }
    if (s.kind == TargetKind.DOMAIN) setCheck(str(R.string.prop_subdomains), s.subdomains)
    s.proto?.let { tap(it) }
    s.port?.let { type(it.toString(), label = str(R.string.port)) }
    if (s.action == Action.BLOCK) setCheck(str(R.string.reject_label), s.reject)
    s.route?.let { tap(str(it)) }
    s.set?.let { pickSet(it) }
    if (save) {
        tap(str(R.string.save))
        waitNoText(str(R.string.rule_set))
    }
}

/** A chip in a dialog (chip rows scroll sideways: brought into view first). */
fun E2eTest.dialogChip(label: String) {
    val m = hasText(label) and androidx.compose.ui.test.hasAnyAncestor(androidx.compose.ui.test.isDialog())
    ui.waitUntil("chip $label", 5000) { ui.onAllNodes(m).fetchSemanticsNodes().isNotEmpty() }
    val n = ui.onAllNodes(m).onFirst()
    n.performScrollToCompat()
    n.performClick()
    ui.waitForIdle()
}

/** The set dropdown of a dialog or sheet. */
fun E2eTest.pickSet(name: String) {
    tap(str(R.string.rule_set), substring = false)
    tap(name)
}

/** A checkbox row: taps it until it shows [on]. The Checkbox is a child of the clickable row with the label. */
fun E2eTest.setCheck(label: String, on: Boolean) {
    val m = androidx.compose.ui.test.isToggleable() and androidx.compose.ui.test.hasParent(hasText(label, substring = true))
    ui.waitUntil("checkbox $label", 5000) { count(m) > 0 }
    val node = ui.onAllNodes(m)[visible(m).last()]
    val state = node.fetchSemanticsNode().config.getOrNull(androidx.compose.ui.semantics.SemanticsProperties.ToggleableState)
    if ((state == androidx.compose.ui.state.ToggleableState.On) != on) {
        node.performScrollToCompat()
        node.performClick()
        ui.waitForIdle()
    }
}

/** Global rules → Add rule → editor. Returns the new rule (read back from the store the screen uses). */
fun E2eTest.addGlobalRule(s: RuleSpec): Rule {
    val before = app.firewall.state.value.rules.map { it.id }.toSet()
    drawer(R.string.nav_global)
    tap(str(R.string.rule_add))
    fillRuleEditor(s)
    val r = waitForValue("new global rule") { app.firewall.state.value.rules.firstOrNull { it.id !in before } }
    assertEquals(Who.Global, r.who)
    assertEquals(s.action, r.action)
    return r
}

/** Apps → search → the app's rules screen. */
fun E2eTest.openAppRules(appName: String) {
    drawer(R.string.nav_apps)
    type(appName)
    // a row, not the search field that holds the same text
    val row = hasText(appName) and androidx.compose.ui.test.hasClickAction() and !hasSetTextAction()
    // the shell is a system app: listed only with "Show system apps" (or once it has rules)
    if (runCatching { ui.waitUntil(2000) { count(row) > 0 } }.isFailure) {
        tapDesc(str(R.string.more))
        tap(str(R.string.show_system))
        back()
    }
    ui.waitUntil("app row $appName", 8000) { count(row) > 0 }
    ui.onAllNodes(row)[visible(row).first()].performClick()
    waitText(str(R.string.rule_add))
}

/** The rules screen of an app → Add rule → editor. */
fun E2eTest.addAppRule(appName: String, s: RuleSpec): Rule {
    val before = app.firewall.state.value.rules.map { it.id }.toSet()
    openAppRules(appName)
    tap(str(R.string.rule_add))
    fillRuleEditor(s)
    val r = waitForValue("new app rule") { app.firewall.state.value.rules.firstOrNull { it.id !in before } }
    assertNotNull(r.who as? Who.App)
    return r
}

/** Sets & profiles → New set. Returns its id. */
fun E2eTest.addSet(name: String): Int {
    drawer(R.string.nav_sets)
    tap(str(R.string.set_new))
    type(name)
    tap(str(R.string.ok))
    return waitForValue("set $name") { app.firewall.state.value.sets.firstOrNull { it.name == name }?.id }
}

/** The rules of the shell: the test traffic comes from it. */
val shellName: String get() = app.apps.get(SHELL_UID).name

fun E2eTest.openLogs() {
    drawer(R.string.nav_logs)
    runCatching { waitText(str(R.string.chip_all)) }.onFailure {
        dumpTree("logs: no All chip")
        throw it
    }
}

/** The log row (Connections tab) of [c]: its title (host or IP) is the unique text. */
fun E2eTest.logRowText(c: io.github.cinnamon415.packetwall.engine.Conn) = c.title

/** The visible texts of everything matching [text] in the merged tree. */
fun E2eTest.textsOf(sub: String): List<String> = ui.onAllNodes(hasText(sub, substring = true)).fetchSemanticsNodes().flatMap { n ->
    n.config.getOrElse(androidx.compose.ui.semantics.SemanticsProperties.Text) { emptyList() }.map { it.text }
}

/** The switch on the row that shows [rowText] (sets, lists). */
fun E2eTest.setSwitch(rowText: String, on: Boolean) {
    val m = androidx.compose.ui.test.isToggleable() and androidx.compose.ui.test.hasParent(hasText(rowText, substring = true))
    ui.waitUntil("switch of $rowText", 8000) { count(m) > 0 }
    val node = ui.onAllNodes(m)[visible(m).last()]
    val state = node.fetchSemanticsNode().config.getOrNull(androidx.compose.ui.semantics.SemanticsProperties.ToggleableState)
    if ((state == androidx.compose.ui.state.ToggleableState.On) != on) {
        node.performScrollToCompat()
        node.performClickCompat()
    }
    ui.waitForIdle()
}

fun androidx.compose.ui.test.SemanticsNodeInteraction.performClickCompat() = performClick()

fun androidx.compose.ui.test.SemanticsNodeInteraction.performScrollToCompat() = runCatching { performScrollTo() }

/**
 * Brings the first node matching [m] into view through every scrolling container around it:
 * performScrollTo only moves the closest one (a sideways row of chips, not the screen).
 */
fun E2eTest.scrollIntoView(m: androidx.compose.ui.test.SemanticsMatcher) {
    val outer = androidx.compose.ui.test.hasScrollAction() and androidx.compose.ui.test.hasAnyDescendant(m)
    val nodes = ui.onAllNodes(outer).fetchSemanticsNodes()
    nodes.indices.sortedByDescending { nodes[it].size.height }.forEach { i ->
        runCatching { ui.onAllNodes(outer)[i].performScrollToNode(m) }
    }
    ui.onAllNodes(m).fetchSemanticsNodes().indices.firstOrNull()?.let { ui.onAllNodes(m)[it].performScrollToCompat() }
    ui.waitForIdle()
}

/** Sets & profiles: moves the set [name] one step with its accessibility action ("Move up" / "Move down"), as TalkBack would. */
fun E2eTest.moveSet(name: String, up: Boolean) {
    drawer(R.string.nav_sets)
    val label = str(if (up) R.string.move_up else R.string.move_down)
    val m = hasText(name) and androidx.compose.ui.test.SemanticsMatcher("has $label") { n ->
        n.config.getOrElse(androidx.compose.ui.semantics.SemanticsActions.CustomActions) { emptyList() }.any { it.label == label }
    }
    ui.waitUntil("set $name can $label", 8000) { count(m) > 0 }
    val action = ui.onAllNodes(m)[visible(m).first()].fetchSemanticsNode()
        .config[androidx.compose.ui.semantics.SemanticsActions.CustomActions].first { it.label == label }
    ui.runOnUiThread { action.action() }
    ui.waitForIdle()
}

/** The id of the set named [name]. */
fun E2eTest.setId(name: String) = app.firewall.state.value.sets.first { it.name == name }.id

/** Its place in the priority order (0 = first). */
fun E2eTest.setPos(name: String) = app.firewall.state.value.order.indexOfFirst { it.id == setId(name) }
