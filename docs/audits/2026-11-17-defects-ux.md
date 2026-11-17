Packetwall audit: correctness bugs and usability defects (read-only; nothing in the repo was changed or built)

Scope: I read docs/SPEC.md, the whole UI layer, FirewallStore, RulesCompiler, Model, AppsResolver, ConnectionsRegister, LogDb, CaptureService, Settings, the tile and widget, and the native engine jni/core/pw_rules.c. I compared every values-ru string with EN. I only skimmed ForeignImport.kt, ListParser.kt, analysis/PacketStore and Dissector, so import-converter edge cases are not covered. Items the owner already reported are left out. Paths are relative to app/src/main/java/io/github/cinnamon415/packetwall/ unless they start with app/ or docs/.

============================================================
PART A. BUGS, BY SEVERITY
============================================================

A1. [High, confirmed] Stale blocklist files are reused by sets with the same id, so the wrong entries get enforced.
- Code: fw/FirewallStore.kt:465-489. The "replace" import writes only `f.lists` and never clears `files/lists/`. fw/RulesCompiler.kt:71-74 emits an `L` line for any existing `lists/<id>.txt`.
- Why it collides so easily: ids come from one counter starting at 100 on every install, so two devices (or two configs) use the same ids. A replace import can also lower `nextId` (line 467: max(src.nextId, …)), so later allocations reuse ids of old files.
- Repro:
  1. Device A has a file-imported list with id 105.
  2. Import, with "Replace the whole configuration", a JSON from device B whose id 105 is an OISD subscription. Do it offline, or let the download fail.
  3. The "OISD" set enforces A's old 105.txt. Its count and error come from B's metadata, so nothing on screen reveals it.
  4. The same happens after a replace, when a newly added subscription gets an id that had an orphan file and its download fails.
- Fix: on replace, delete every `lists/*.txt` not in `f.lists`. In `addBlocklist` and `importJson`, delete `listFile(id)` before scheduling the download. Never lower `nextId` below the current value.

A2. [High, confirmed] Rules for apps installed or reinstalled while protection is on are not enforced.
- Code: fw/RulesCompiler.kt:52-53 turns packages into uids only when it compiles. Nothing listens for PACKAGE_ADDED, REMOVED or REPLACED: a grep finds no BroadcastReceiver, and compiles happen only on rule edits, on GeoIP changes and at service start (engine/CaptureService.kt:73).
- Repro:
  1. Apps → app X → add rule Everything / Block.
  2. Uninstall X and install it again; the uid changes.
  3. X is fully unblocked until some unrelated rule edit or a protection restart.
- Same problem: rules imported for apps not yet installed (NetGuard, AFWall+, `$app=`) stay dead after the app is installed.
- Fix: register a receiver for ACTION_PACKAGE_ADDED/REMOVED/REPLACED (data scheme "package") in PacketwallApp and call `firewall.scheduleCompile()`. Also refresh the Apps list (A13).

A3. [High, confirmed] Deleting the active profile silently overwrites another profile.
- Code: fw/FirewallStore.kt:199-206 switches `activeProfile` to `left.first()` but keeps the live `order` of the deleted profile. On the next set toggle, `syncProfiles` (101-102) writes that order into the new active profile.
- Repro:
  1. Profiles A (set X on) and B (X off). B is active.
  2. Sets & profiles → B ⋮ → Delete.
  3. Home shows A, but X is still off.
  4. Toggle any set: A's saved snapshot is now B's.
- Fix: in `deleteProfile`, when the deleted profile is active, apply the new active profile's order the way `activateProfile` does.

A4. [High, likely] Two compiles can run at once and corrupt `rules.compiled`; compiling also blocks the main thread.
- Code:
  - fw/FirewallStore.kt:530-549: `scheduleCompile` cancels the job, but `compileNow()` has no suspension point, so a running compile keeps going.
  - engine/CaptureService.kt:73 calls `compileNow()` on the main thread.
  - PacketwallApp.kt:92 calls `scheduleCompile(0)` on IO.
  - Both write the same `rules.compiled.tmp` (RulesCompiler.kt:29).
- Repro: with the process cold, tap the tile (App.onCreate schedules a compile and the service starts at once), or edit rules while ASN expansion is slow. Two writers truncate and interleave the same tmp file. The engine then loads a mix (lines it cannot parse are only logged), and `_loaded` can end up with the older count.
- Main-thread cost: the ASN tree walk after a GeoIP update (GeoIp.kt:118-140) and the native load of large lists both run on the main thread, which risks an ANR.
- Fix: serialize compiles with a Mutex or a single-thread dispatcher, use a unique tmp name per run, and have CaptureService wait for the compile off the main thread before `establish()`.

A5. [High, confirmed] An "Allow" added from a log entry can silently have no effect, and the app still says "Rule added".
- Code:
  - ui/FwComponents.kt:450 picks the blocking rule's own set by default; 462 picks "base domain + subdomains" by default.
  - The warning (535-541) only checks set order.
  - Engine scores (app/src/main/jni/core/pw_rules.c:246-275, `better()` at 600-607): within one set and one "who" level, the narrowest target wins and a tie blocks. An exact host scores 1037; "example.com + subdomains" scores 1022.
- Repro:
  1. Long-press a connection → Block → "Exact host" `t.example.com` for the app.
  2. Later, long-press the now-blocked connection → Allow, keeping the defaults.
  3. The new allow is broader and in the same set, so it loses. The connection stays blocked.
- Fix: when the deciding rule is a user rule, offer "Delete the blocking rule" as the first action. Otherwise preselect the deciding rule's exact target, and warn when the chosen target is broader than the deciding rule in the same set (compute the score in Kotlin).

A6. [Medium, confirmed] Merge-importing a single-set export duplicates every app group; unmapped group references point at the wrong local group.
- Code: fw/FirewallStore.kt:374-381. `exportJson(onlySet)` keeps `groups = st.groups` (all of them). The merge at 498 copies every group under a new id.
- Repro: Sets → a set → Export JSON → Import Packetwall JSON → Add as new sets. Every group appears twice; it gets worse with each import.
- Related: line 502 keeps the original `Who.Group(id)` when the id is not in `groupMap`. That id can match an unrelated local group, so the rule applies to the wrong apps.
- Fix: filter groups to those referenced by the exported rules, as `exportRules` does at 392. On merge, drop or report rules whose group is not in the file.

A7. [Medium, confirmed] "Replace" import accepts partial files and wipes profiles and groups, without a warning.
- Code: fw/FirewallStore.kt:465-489 and ui/SetsScreens.kt:728-755.
- Repro: Import a file made with Sets → set → Export JSON, or with the multi-select rules export, and choose Replace.
  - The result is `profiles = []`, `activeProfile = null`, and only groups that were in the file.
  - Group rules whose group is missing compile to nothing (RulesCompiler.kt:55).
  - Nothing confirms or allows undo.
- Fix: offer Replace only for full exports (profiles present). Show a confirmation listing what will be lost. Keep `firewall.json` as a `.bak` for undo.

A8. [Medium, likely] Protection toggles by itself when the activity is recreated after process death.
- Code: MainActivity.kt:45 and 54-65. `handleIntent(intent)` runs on every `onCreate`, including recreation with `savedInstanceState != null`. Setting `intent.action = null` changes only the in-process object; after process death the system redelivers the original TOGGLE_ON/OFF intent.
- Repro:
  1. Enable "Don't keep activities".
  2. Open the app from the tile while VPN consent is needed (TOGGLE_ON). Grant, then turn protection off in the app.
  3. Leave and return. The activity is recreated with TOGGLE_ON, and protection turns on again (or the consent dialog reappears).
- Fix: `if (savedInstanceState == null) handleIntent(intent)`, and `setIntent(Intent(intent).setAction(null))` in `onNewIntent`.

A9. [Medium, confirmed] Exports are lost silently if the activity is recreated while the system "Save as" picker is open.
- Code: ui/FileExport.kt:40-49. `PendingWrite` is in plain `remember`; the activity has no `configChanges`. After rotation or dark-mode toggle, `pending.take()` returns null: nothing is written and no toast appears. This affects every export (CSV, pcapng, JSON, profile, set, rules).
- Fix: keep the pending export kind and arguments in `rememberSaveable` or a ViewModel. At minimum, show "export_failed" when `uri != null && write == null`.

A10. [Medium, confirmed] Counters on Home and Stats mix scopes, so the numbers contradict each other.
- Code:
  - "Requests" and "Received" come from the native session counters (HomeScreen.kt:161, 180; StatsScreen.kt:67-75).
  - "Blocked", Top apps, hosts, trackers and blocks come from `conns`, which include up to 5000 rows of DB history from earlier days when log retention is on (ConnectionsRegister.kt:198; ConnStats.kt:236-253).
- Repro: set Keep log to 7 days, restart protection. Home shows "Requests 3, Blocked 812", and Stats "Top apps" bytes exceed "Received".
- A second mismatch: the Logs "Blocked" chip counts `c.blocked` (ui/LogsViewModel.kt:24), which includes internal Private-DNS drops. Home excludes them (`fwRule != 0`), so tapping the Blocked tile shows a different number.
- Fix: compute all session tiles from one source and filter `firstSeen >= session start`, or label the scope ("today" / "since start"). Use the same blocked predicate everywhere.

A11. [Medium, confirmed] Upstream port field can't be cleared and accepts invalid ports.
- Code: ui/SettingsScreen.kt:303-309. It writes only when `toIntOrNull()` is non-null, so deleting the last digit is ignored. 0 and 65536-99999 are stored.
- Repro: Settings → Upstream → port 1080 → backspace four times: the field keeps "1". Typing "99999" saves an invalid port.
- Fix: keep a local text state, validate 1..65535, show isError, and commit only valid values.

A12. [Medium, confirmed] Changing recording size, age or file count while recording does nothing.
- Code: PacketwallApp.kt:56-61 starts the recorder only if it is not running and never restarts it on parameter changes. The collector at 105-111 fires, but `applySinks` ignores it.
- Repro: Logs → Captures → Continuous recording on → change File size from 32 MB to 8 MB → files keep rotating at 32 MB until protection restarts.
- Fix: restart the recorder when (mb, minutes, keep) differ from the running values, or show the "applies on restart" hint.

A13. [Medium, confirmed] The Apps list never picks up new apps.
- Code: ui/AppsViewModel.kt:110-112 loads `installed()` once; the ViewModel lives as long as the activity. GroupMembersDialog and the proxy-app picker reload, but the Apps screen does not.
- Repro: open Apps, install an app, return: it is missing and search can't find it until the activity is recreated.
- Fix: reload on resume or on the package broadcast from A2.

A14. [Medium, confirmed] Deleting the GeoIP/ASN databases silently disables Country and ASN rules.
- Code: ui/SettingsScreen.kt:588 deletes with no confirmation. GeoIp.kt:110 then returns no ASN prefixes; the compiler emits nothing for ASN rules and countries no longer resolve.
- Repro: Settings → GeoIP → Delete. Every "Country RU" and "AS13335" rule stops matching, and the rule lists give no sign of it.
- Fix: confirm, naming the number of affected rules. Mark Country/ASN rules "inactive: database missing" in the rule rows.

A15. [Low-Med, confirmed] Country validation accepts Cyrillic letters, producing a rule that never matches.
- Code: ui/FwComponents.kt:231 uses `isLetter()`.
- Repro: with the Russian keyboard, type "РУ" → Save is enabled → the rule never matches.
- Fix: require `[A-Za-z]{2}`; better, a country picker.

A16. [Low-Med, confirmed] Log entries from earlier days show only the time.
- Code: ui/Common.kt:183-186 formats `HH:mm:ss`. It is used for log rows (LogsScreen.kt:255, 373, 662), Home recent blocks (HomeScreen.kt:232) and the connection's first/last seen (ConnectionScreen.kt:140-141).
- Repro: with 7- or 30-day retention, rows from yesterday look like today's.
- Fix: show a date when the day differs from today, plus day separators in the Logs list.

A17. [Low-Med, likely] Large imports and file saves can crash or freeze the app.
- ui/SetsScreens.kt:327 reads the whole import into memory with `readBytes()`. OutOfMemoryError is an Error, so `catch (e: Exception)` misses it and a multi-hundred-MB hosts file or RethinkDNS backup crashes the app.
- ui/SetsScreens.kt:749 runs `importJson` (JSON decode plus `writeList` of inlined lists) on the main thread.
- ui/LogsScreen.kt:417-426: an IOException from Save (disk full) escapes the `rememberCoroutineScope` launch and crashes the app.
- Fix: stream line by line where the format allows and catch Throwable for OOM; move `importJson` to IO; wrap the save in runCatching and show `export_failed`.

A18. [Low, likely] Data and HTTP tabs redo their work on the main thread every 0.8 s.
- Code: ui/AnalysisScreens.kt:75-79 builds a new rows list every 800 ms. `remember(rows)` then reruns `payloadBlocks` (up to 256 KB copied, line 391), `TlsInfo` parsing and a Regex (478-486) on the main thread, even for closed connections.
- Fix: stop polling once the connection is closed; emit only when the packet count changes (distinctUntilChanged on size or last seq); compute blocks in the producer on Default.

A19. [Low, likely] Dragging on the packet timeline is interrupted while packets arrive.
- Code: ui/AnalysisScreens.kt:157 keys `pointerInput(rows.size)`. Each new packet restarts the gesture detector.
- Fix: key on Unit and read rows through `rememberUpdatedState`.

A20. [Low, likely] Settings changes can be lost when two writers race.
- Code: Settings.kt:112-136 reads, modifies and writes without a lock. The backup worker writes `lastBackup` (not verified in system/Schedules.kt) while the UI writes on every keystroke, so one change can be lost.
- Fix: synchronize, or use `MutableStateFlow.update {}` before writing prefs.

A21. [Low, likely] Navigation state grows without limit.
- Code: ui/AppRoot.kt:90 keys `SaveableStateProvider("${stack.size}:$d0")` and never calls `removeState`. Every connection or packet screen opened keeps its saved state in the activity bundle, which risks TransactionTooLargeException in long sessions.
- Fix: call `saveable.removeState(key)` when a destination is popped or replaced.

A22. [Low, confirmed] A help text says the opposite of what the app does.
- Code: app/src/main/res/values/strings.xml `storage_session_hint`: "…A persistent database comes later" (RU: «Постоянная база появится позже»).
- Why wrong: the database exists; it is the 1/7/30-day option right next to this text.
- Fix: replace the text, e.g. "The log is kept in memory and cleared when protection restarts."

============================================================
PART B. USABILITY, BY HOW MUCH IT HURTS DAILY USE
============================================================

B1. [Confirmed] Destructive actions have no confirmation and no undo. Each item below is an immediate, irreversible action:
- Group → ⋮ → Delete removes the group and all its rules: ui/RulesScreens.kt:314-319.
- Multi-select → Delete rules: ui/RulesScreens.kt:615-618.
- Rule editor → Delete: ui/FwComponents.kt:377-379.
- Profile → ⋮ → Delete (and A3): ui/SetsScreens.kt:522-529.
- Captures → trash icon on a file: ui/LogsScreen.kt:471-474.
- "Clear the saved log": ui/SettingsScreen.kt:164-169.
- GeoIP / Trackers Delete: ui/SettingsScreen.kt:588 and 624.
- Replace-config import: ui/SetsScreens.kt:732-743.
- Shrinking log retention purges history right away: ConnectionsRegister.kt:103.
Fix: a Snackbar with Undo for rule, group and profile deletes (keep the removed objects for a few seconds); ConfirmDialog for files, the log DB, the databases and Replace.

B2. [Confirmed] Home tiles and links don't filter what they open.
- Code: ui/HomeScreen.kt:157-191 and 203.
- "Blocked", "Active" and "Recent blocks → All" all open Logs with the previous filter.
- The spec's "recent blocks with quick allow" (SPEC §4) is missing: rows only open the connection (215-218), and there is no long-press QuickRuleSheet there.
- Fix: navigate to Logs with StatusFilter.BLOCKED or an `active` filter; add long-press and a trailing "Allow" button to recent blocks.

B3. [Confirmed] Blocked connections without a rule show no reason.
- Code: ui/FwComponents.kt:115 returns null when `fwRule == 0`. Status says "Blocked", but there is no Rule row.
- Repro: a DoT-to-853 drop (Private DNS) or a kill-switch drop.
- Fix: map these cases to explicit reasons ("Private DNS (DoT) dropped so Android falls back to plain DNS", "Upstream down, kill switch") and link to the related setting.

B4. [Confirmed] Rules in disabled sets look exactly like active ones.
- Code: ui/FwComponents.kt:101 prints only the set name; RulesScreens.kt:332 and 537. Only the SetChips text is greyed (FwComponents.kt:209).
- Effect: a user edits a rule that has no effect.
- Fix: dim the row and add "(set off)" to the props line; ideally also mark rules overridden by a higher set.

B5. [Confirmed] Connection arrows ignore the Logs filter.
- Code: ui/ConnectionScreen.kt:55-77 steps through the unfiltered `conns`.
- Repro: Logs filtered to Blocked → open one → › opens an allowed DNS connection.
- Fix: pass the filtered id list (from LogsViewModel.shown) to the connection screen.

B6. [Confirmed] Statistics is a dead end.
- Code: ui/StatsScreen.kt:85-191. Rows for apps, hosts, protocols, trackers and blocked-by-app are not clickable.
- Fix: app row → app rules page or Logs `app == "X"`; host → Logs `host ~ "h"`; blocked-by-app → Logs blocked + app.

B7. [Confirmed] Hard-coded English text in the RU UI.
- ui/LogsScreen.kt:569-583: "$it MB", "$it min", "${it/60} h".
- ui/SettingsScreen.kt:100 and 108: "$it MB", "$it B". `Units.mb`, `Units.m` and `Units.h` already exist in ui/Common.kt:156-174.
- ui/StatsScreen.kt:236: "max".
- engine/AppsResolver.kt:201-209: "Unknown (−1)", "Android System", "Phone (radio)", "uid N". These show in Logs, Apps and rule titles.
- values-ru: `set_default` is "Default"; `upstream`, `kill_switch` and "Reject … вместо drop" are untranslated.
- Fix: string resources for all of these. Suggested RU: «Основной» (set), «Аварийная блокировка (kill switch)», «Отклонять (RST, быстрый отказ) вместо тихого сброса».

B8. [Confirmed] Russian wording that reads unnaturally or is inconsistent:
- `tile_requests` is "Requests" in EN but «Соединений» in RU. The screens show connections, so EN should be "Connections" (StatsScreen.kt:71 reuses it as well).
- `rule_add`: the FAB says only «Правило», and `rule_edit` is also «Правило», so the edit dialog has the same title as the button. Use «Добавить правило» / «Изменить правило».
- `kv_package` «Пакет» sits next to `kv_packets` «Пакеты» on the same Overview screen, which is ambiguous. Use «Имя пакета» or «Пакет приложения».
- Log vs journal: the drawer and title say «Логи», but settings say «Хранение журнала» and «Очистить сохранённый журнал». Pick one; «Журнал» reads better.
- Blocklists vs lists: «Блок-листы» in the drawer, but «Добавить список» and «списков» in the dialogs.
- «Захваты» is a calque. «Записи трафика» or «Дампы» reads better.
- `chip_blocked` «Заблок.» and `chip_allowed` «Разреш.» are cut-off abbreviations that would fit in full; `st_blocked` «Заблок.» likewise. Use «Заблокированные» / «Разрешённые».
- `import_done_sets` «Импортировано в новых наборов: %d» is ungrammatical. Use a plural: «Создано новых наборов: %d».
- `record_keep` «Хранить файлов» is clumsy. Use «Сколько файлов хранить».
- `tls_ciphers` «Шифронаборов» → «Наборы шифров».
- `nav_global` is «Глобальные правила», but rules and props say «Глобально», and EN is just "Global".
- The kind chip «Всё» sits in the same area as the «Все наборы» chip on the Global screen (RulesScreens.kt:526): two "all" chips with different meanings. Rename the kind chip «Весь трафик».
- Count strings use colon forms («записей: %d», «правил: %d», «приложений: %d»). That is grammatical but stiff; <plurals> would read better.

B9. [Confirmed] Accessibility gaps.
- No content description on overflow (⋮) buttons: LogsScreen.kt:180, RulesScreens.kt:122/304/491, SetsScreens.kt:116/467/511.
- The compact-density chip is icon-only with no description: LogsScreen.kt:209.
- Connection neighbour arrows are text "‹" / "›" with no label: ConnectionScreen.kt:69-77.
- `Chevron()` "›" is announced as text: RulesScreens.kt:238.
- Block vs allow is shown by color only, with a null icon description: FwComponents.kt:139-141.
- Set reordering works only by long-press drag, with no TalkBack alternative: SetsScreens.kt:595-621.
- Fix: add descriptions; add "Move up / Move down" custom accessibility actions on set rows.

B10. [Confirmed] Missing explanations of rule behaviour.
- A global "Everything / Block" is offered without any warning (FwComponents.kt:279-285; Global FAB at RulesScreens.kt:564) and cuts the whole device off. Warn, or hide "Everything" for global rules.
- Country and ASN rules show no "database missing" state (see A14).

B11. [Confirmed] Small dead ends.
- Logs → Captures still shows the filter field, the status chips and the "N / M" subtitle, which do nothing there: LogsScreen.kt:177, 195-221.
- The import name defaults to the SAF path segment, giving names like "msf:1234" or "document:42": SetsScreens.kt:321. Read OpenableColumns.DISPLAY_NAME instead.
- Deleting a blocklist from Sets & profiles says "Delete X and its 0 rules?" because it counts rules, not entries: SetsScreens.kt:705-706.
- A duplicate custom blocklist URL is accepted: SetsScreens.kt:201-205.
- The app rules page doesn't list the groups the app belongs to: RulesScreens.kt:276.

B12. [Confirmed] Spec gaps not covered above.
- SPEC §4: the app page should have "история" (the app's connection history). It is missing (RulesScreens.kt:261-396).
- SPEC §4: quick actions should offer "подсеть" (subnet). The quick sheet offers only host, base domain, IP and everything (FwComponents.kt:453-461).
- SPEC §4: Global rules should have a profile picker in the header. It is missing.
- SPEC §2.3: profiles should switch "с плитки" (from the tile). The tile only shows the profile (system/ProtectionTile.kt).
- SPEC §2.5.6: "why blocked" should show the profile. It does not (FwComponents.kt:114-124).
- SPEC §4: the Home "текущий профиль" is a non-tappable line of small text; tapping it should switch or open profiles (HomeScreen.kt:143-148).

============================================================
TOP 10 MOST VALUABLE
============================================================
1. A2: recompile on package install, uninstall and reinstall. Today a reinstall bypasses "block app".
2. A1: clear stale `lists/*.txt` on replace import and on new ids, so no set enforces another list's entries.
3. A5: make "allow from log" effective (offer to remove the blocking rule, warn when the allow is broader in the same set).
4. A3: fix deleting the active profile, which silently corrupts another profile.
5. A4: serialize compiles, unique tmp file, off the main thread.
6. B1: confirmation and undo for rule, group and profile deletes, file deletes, log clear, database delete and Replace import.
7. A6 and A7: single-set export carries all groups (duplicates on import, wrong group ids); Replace accepts partial files and wipes profiles and groups.
8. A10 with B2: consistent Home and Stats counters, and tiles that open Logs already filtered.
9. A9 and A8: exports lost on activity recreation; protection toggling by itself after process death.
10. B7 and B8: hard-coded English and the inconsistent or awkward Russian terms, the most visible daily annoyance for a Russian-speaking user.
