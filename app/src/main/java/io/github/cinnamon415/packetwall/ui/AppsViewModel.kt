package io.github.cinnamon415.packetwall.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.Who
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class AppSort { RULES, NAME, TRAFFIC }

data class AppQuery(
    val text: String = "",
    val showSystem: Boolean = false,
    val onlyWithRules: Boolean = false,
    /** Only count rules of this set; null = all sets. */
    val setId: Int? = null,
    val sort: AppSort = AppSort.RULES
)

data class AppList(
    /** null while the installed apps are loading. */
    val apps: List<AppInfo>? = null,
    val ruleCounts: Map<String, Int> = emptyMap(),
    val groupRuleCounts: Map<Int, Int> = emptyMap(),
    val traffic: Map<String, Long> = emptyMap()
)

/** The apps list for [q]: system apps only when asked for or when they have rules. Pure. */
fun buildAppList(installed: List<AppInfo>?, rules: List<Rule>, traffic: Map<String, Long>, q: AppQuery): AppList {
    val scoped = rules.filter { q.setId == null || it.setId == q.setId }
    val counts = scoped.mapNotNull { (it.who as? Who.App)?.pkg }.groupingBy { it }.eachCount()
    val groupCounts = scoped.mapNotNull { (it.who as? Who.Group)?.id }.groupingBy { it }.eachCount()
    val needle = q.text.trim().lowercase()
    val byName = compareBy<AppInfo> { it.name.lowercase() }
    val apps = installed?.filter { a ->
        (q.showSystem || !a.isSystem || a.packageName in counts) &&
            (!q.onlyWithRules || a.packageName in counts) &&
            (needle.isEmpty() || a.name.lowercase().contains(needle) || a.packageName.contains(needle))
    }?.sortedWith(
        when (q.sort) {
            AppSort.NAME -> byName
            AppSort.TRAFFIC -> compareByDescending<AppInfo> { traffic[it.packageName] ?: 0L }.then(byName)
            AppSort.RULES -> compareByDescending<AppInfo> { counts[it.packageName] ?: 0 }.then(byName)
        }
    )
    return AppList(apps, counts, groupCounts, traffic)
}

class AppsViewModel(app: PacketwallApp, private val saved: SavedStateHandle) : ScreenViewModel() {
    private val installed = MutableStateFlow<List<AppInfo>?>(null)

    /** The search text. Compose state, so the text field updates synchronously while typing. */
    var search by mutableStateOf(saved[K_TEXT] ?: "")
        private set

    fun updateSearch(v: String) {
        search = v
        saved[K_TEXT] = v
    }

    val query: StateFlow<AppQuery> = combine(
        snapshotFlow { search },
        saved.getStateFlow(K_SYSTEM, false),
        saved.getStateFlow(K_WITH_RULES, false),
        saved.getStateFlow(K_SET, NO_SET),
        saved.getStateFlow(K_SORT, AppSort.RULES)
    ) { text, system, withRules, set, sort -> AppQuery(text, system, withRules, set.takeIf { it != NO_SET }, sort) }
        .whileShown(current())

    /** Reads the saved state directly, so it is right even while nobody collects [query]. */
    private fun current() = AppQuery(
        search,
        saved[K_SYSTEM] ?: false,
        saved[K_WITH_RULES] ?: false,
        saved.get<Int>(K_SET)?.takeIf { it != NO_SET },
        saved[K_SORT] ?: AppSort.RULES
    )

    fun setQuery(change: (AppQuery) -> AppQuery) {
        val q = change(current())
        updateSearch(q.text)
        saved[K_SYSTEM] = q.showSystem
        saved[K_WITH_RULES] = q.onlyWithRules
        saved[K_SET] = q.setId ?: NO_SET
        saved[K_SORT] = q.sort
    }

    private val traffic = app.connections.conns
        .map { l -> l.groupBy { it.app.packageName }.mapValues { (_, c) -> c.sumOf { it.bytes } } }
        .distinctUntilChanged()

    val list: StateFlow<AppList> = combine(installed, app.firewall.state, traffic, query) { all, st, tr, q ->
        buildAppList(all, st.rules, tr, q)
    }.flowOn(Dispatchers.Default).whileShown(AppList())

    init {
        // reload on every install / update / removal
        viewModelScope.launch {
            app.apps.changes.collect { installed.value = withContext(Dispatchers.IO) { app.apps.installed() } }
        }
    }

    private companion object {
        const val K_TEXT = "apps.text"
        const val K_SYSTEM = "apps.system"
        const val K_WITH_RULES = "apps.withRules"
        const val K_SET = "apps.set"
        const val K_SORT = "apps.sort"
        const val NO_SET = Int.MIN_VALUE
    }
}
