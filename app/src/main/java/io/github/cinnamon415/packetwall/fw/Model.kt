package io.github.cinnamon415.packetwall.fw

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/*
 * Firewall model. See docs/SPEC.md, section 2.
 *
 * Persisted as JSON (filesDir/firewall.json); the same format, wrapped in [ExportFile], is used
 * for export/import. Blocklist entries are kept apart in filesDir/lists/<setId>.txt.
 */

@Serializable
enum class Action { BLOCK, ALLOW }

@Serializable
enum class TargetKind { ALL, DOMAIN, IP, COUNTRY, ASN }

@Serializable
enum class Proto(val ipproto: Int) { ANY(0), TCP(6), UDP(17) }

/** Where allowed traffic goes (spec 2.8 "route as a rule action"). */
@Serializable
enum class Route(val code: Int) { DEFAULT(0), DIRECT(1), UPSTREAM(2) }

@Serializable
data class Target(
    val kind: TargetKind,
    val value: String = "",
    /** For [TargetKind.DOMAIN]: also match every subdomain. */
    val subdomains: Boolean = false
)

@Serializable
sealed interface Who {
    @Serializable
    @SerialName("global")
    data object Global : Who

    /** An app by package name; system uids use the pseudo-packages of AppsResolver (netd, root, …). */
    @Serializable
    @SerialName("app")
    data class App(val pkg: String) : Who

    @Serializable
    @SerialName("group")
    data class Group(val id: Int) : Who
}

@Serializable
data class Rule(
    val id: Int,
    val setId: Int,
    val who: Who,
    val target: Target,
    val action: Action,
    val reject: Boolean = false,
    val proto: Proto = Proto.ANY,
    /** 0 = any port. */
    val port: Int = 0,
    val created: Long = 0,
    /** For allow rules: send the matching traffic directly or through the upstream proxy. */
    val route: Route = Route.DEFAULT
)

@Serializable
enum class SetKind { USER, BLOCKLIST }

@Serializable
data class RuleSet(
    val id: Int,
    val name: String,
    val kind: SetKind = SetKind.USER,
    // Blocklist subscription (kind == BLOCKLIST). url == null: imported from a file.
    val url: String? = null,
    /** What the list entries do (entries prefixed with "@@" / "!" do the opposite). */
    val action: Action = Action.BLOCK,
    val reject: Boolean = false,
    val updated: Long = 0,
    val entries: Int = 0,
    val skipped: Int = 0,
    val error: String? = null,
    /** HTTP validators of the last download, for conditional requests (304 = unchanged). */
    val etag: String? = null,
    val lastModified: String? = null,
    /** Hash of the normalized entries: an unchanged download does not rewrite the file. */
    val contentHash: Int = 0
)

@Serializable
data class SetState(val id: Int, val enabled: Boolean)

/** A snapshot of the enabled sets and their order. */
@Serializable
data class Profile(val id: Int, val name: String, val sets: List<SetState>)

@Serializable
data class AppGroup(val id: Int, val name: String, val packages: List<String> = emptyList())

@Serializable
data class FwState(
    val version: Int = 1,
    val sets: List<RuleSet> = emptyList(),
    /** The live configuration: sets in priority order (first = highest) with their switch. */
    val order: List<SetState> = emptyList(),
    val rules: List<Rule> = emptyList(),
    val groups: List<AppGroup> = emptyList(),
    val profiles: List<Profile> = emptyList(),
    val activeProfile: Int? = null,
    val nextId: Int = 100
) {
    fun set(id: Int) = sets.firstOrNull { it.id == id }
    fun rule(id: Int) = rules.firstOrNull { it.id == id }
    fun group(id: Int) = groups.firstOrNull { it.id == id }
    fun isEnabled(setId: Int) = order.firstOrNull { it.id == setId }?.enabled == true
    val orderedSets get() = order.mapNotNull { s -> set(s.id) }
    val userSets get() = orderedSets.filter { it.kind == SetKind.USER }
    val blocklists get() = orderedSets.filter { it.kind == SetKind.BLOCKLIST }
    val profile get() = activeProfile?.let { id -> profiles.firstOrNull { it.id == id } }

    /** The active profile no longer matches the live configuration. */
    val profileModified get() = profile?.let { it.sets != order } ?: false

    companion object {
        const val DEFAULT_SET = 1

        fun initial(defaultSetName: String, defaultProfileName: String): FwState {
            val order = listOf(SetState(DEFAULT_SET, true))
            return FwState(
                sets = listOf(RuleSet(DEFAULT_SET, defaultSetName)),
                order = order,
                profiles = listOf(Profile(2, defaultProfileName, order)),
                activeProfile = 2,
                nextId = 100
            )
        }
    }
}

/** Export file: the whole configuration or a part of it, plus inlined blocklist entries. */
@Serializable
data class ExportFile(
    val format: String = FORMAT,
    val formatVersion: Int = 1,
    val app: String = "Packetwall",
    val exported: Long = 0,
    val state: FwState,
    /** setId -> normalized list lines, for blocklists imported from files (no URL). */
    val lists: Map<Int, List<String>> = emptyMap()
) {
    companion object {
        const val FORMAT = "packetwall-rules"
    }
}
