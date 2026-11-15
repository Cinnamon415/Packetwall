package io.github.cinnamon415.packetwall.fw

import java.io.File

/**
 * Writes the enabled part of the configuration in the format read by pw_rules.c:
 *
 *   R <ref> <set> <who> <uid> <block> <reject> <kind> <value> <subs> <proto> <port>
 *   L <set> <ref> <block> <reject> <path>
 *
 * <set> is the priority position among enabled sets (0 = highest).
 */
object RulesCompiler {
    fun compile(st: FwState, uidOf: (String) -> Int?, listFile: (Int) -> File, out: File): Int {
        var lines = 0
        val tmp = File(out.parentFile, out.name + ".tmp")
        tmp.bufferedWriter().use { w ->
            w.write("# Packetwall compiled rules\n")
            val enabled = st.order.filter { it.enabled }
            enabled.forEachIndexed { prio, s ->
                val set = st.set(s.id) ?: return@forEachIndexed
                for (r in st.rules) {
                    if (r.setId != set.id) continue
                    val value = if (r.target.kind == TargetKind.ALL) "-" else sanitize(r.target.value)
                    if (value.isEmpty()) continue
                    val kind = when (r.target.kind) {
                        TargetKind.ALL -> 'A'; TargetKind.DOMAIN -> 'D'; TargetKind.IP -> 'I'; TargetKind.COUNTRY -> 'C'
                    }
                    val (who, uids) = when (val wh = r.who) {
                        Who.Global -> 0 to listOf(-1)
                        is Who.App -> 2 to listOfNotNull(uidOf(wh.pkg))
                        is Who.Group -> 1 to (st.group(wh.id)?.packages?.mapNotNull(uidOf)?.distinct() ?: emptyList())
                    }
                    val block = if (r.action == Action.BLOCK) 1 else 0
                    val reject = if (r.action == Action.BLOCK && r.reject) 1 else 0
                    val subs = if (r.target.kind == TargetKind.DOMAIN && r.target.subdomains) 1 else 0
                    for (uid in uids) {
                        w.write("R\t${r.id}\t$prio\t$who\t$uid\t$block\t$reject\t$kind\t$value\t$subs\t${r.proto.ipproto}\t${r.port}\n")
                        lines++
                    }
                }
                if (set.kind == SetKind.BLOCKLIST) {
                    val f = listFile(set.id)
                    if (f.exists()) {
                        val block = if (set.action == Action.BLOCK) 1 else 0
                        val reject = if (set.action == Action.BLOCK && set.reject) 1 else 0
                        w.write("L\t$prio\t${-set.id}\t$block\t$reject\t${f.absolutePath}\n")
                        lines++
                    }
                }
            }
        }
        tmp.renameTo(out)
        return lines
    }

    private fun sanitize(v: String) = v.trim().lowercase().filterNot { it == '\t' || it == '\n' || it == '\r' || it == ' ' }
}
