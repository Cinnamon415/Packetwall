## Packetwall performance audit (read-only)

I read the native hot path (pcapdroid.c, capture_vpn.c, pw_rules.c, jni_impl.c, pcap_dump.c, the zdtun patch), the engine and analysis code in Kotlin, the firewall code, and the ViewModels and screens. I modified nothing, ran no Gradle build and used no network. Every finding below is in the code as quoted. Where a figure is an estimate (CPU cost per operation, file sizes), it is marked as one. Paths are relative to `app/src/main/java/io/github/cinnamon415/packetwall/` (Kotlin) or `app/src/main/jni/` (C).

---

### HIGH

**H1. Wildcard, IP/CIDR and ASN rules are checked by a linear scan of every rule, on the capture thread.**
- **Where:** `core/pw_rules.c:375` (`linear = (r->flags & F_WILD)`); IP, ASN and country rules always go to the linear list (`:356-365`); the scan loop is at `:654`. `ListParser.kt:119` and `:172` turn `*.x` and `||*.x^` into `=**.x`, which has `F_WILD` set, so it goes to the linear list too.
- **What happens:**
  - `pw_engine_eval` runs `pw_match_domain` for every wildcard rule (two `split_labels` calls plus the recursive `**` match) and `ip_in_cidr` for every IP rule.
  - This happens at least twice per connection (when it is created, and when DPI learns the host) and for every DNS query.
  - After every rule reload it runs again for every active connection (`pcapdroid.c:1239-1240`).
- **Scenario (estimate):**
  - A wildcard-format list such as HaGeZi "wildcard", or uBO lists with `||*.` entries, of 200k entries at about 100–200 ns per match costs about 20–40 ms per eval, so 40–80 ms of stalled packet loop per new connection.
  - On a rule toggle with 500 active connections the loop stalls for about 10–20 s.
  - An IP list of 100k entries costs about 1 ms per eval.
  - The built-in catalog (adblock `||x^` and hosts formats) is indexed, so this hits user-added lists, imports and ASN rules.
- **Confidence:** the code path is confirmed; the cost per match is an estimate.
- **Fix:**
  - Index `**.<literal>` (and `*.<literal>`) in the hash table under the literal suffix, with a flag "needs ≥1 (or exactly 1) more label". The parent-domain walk in eval already visits each suffix.
  - For IP/ASN rules, use one hash table per prefix length (usually only a few distinct lengths), or sorted ranges with binary search, split by IP version.
  - Keep only real globs linear.

**H2. `PacketStore.feed` builds a string key with `String.format` for every byte of every packet, on the capture thread and under the store lock. It is on by default.**
- **Where:** `analysis/PacketStore.kt:207-211` (`hex()` calls `String.format("%02x")` per byte), `:214-246` (`keyOf`), `:95-125` and `:160` (called for every EPB inside `synchronized(lock)`). JNI calls it synchronously from the packet loop (`core/jni_impl.c:125`). The defaults are `capture_packets=true` and `snaplen 0` (`Settings.kt:64-66`).
- **Scenario (estimate):** IPv4 needs 8 `String.format` calls per packet and IPv6 needs 32. At about 1 µs each, a 50 Mbit/s download (about 4.5k pps) costs about 40 ms/s on IPv4 and about 150+ ms/s on IPv6 of blocked packet loop. On top of that come a block copy (`copyOfRange`), a key string and a `Pkt` per packet, and a `_version` bump per flush.
- **Confidence:** the code is confirmed; the timings are an estimate.
- **Fix:**
  - Use a precomputed hex lookup table, or a binary key (e.g. two `Long`s plus ports, or a wrapper around the raw address bytes).
  - Better: have the native dumper put the connection `incr_id` into the EPB comment (e.g. `c-<id>`, next to `u-<uid>`) and index by that int. Then `keyOf(Conn)` (`InetAddress.getByName` plus hex) is no longer needed either.

**H3. The connection list is rebuilt in full every second whether or not anyone is watching, while holding the lock the capture thread needs.**
- **Where:** `engine/ConnectionsRegister.kt:121-128`, a `while(true){delay(500)}` loop that starts at construction and never stops. `publish()` at `:187-199` maps all `byId` entries (up to `maxConns` 20,000, `:70`) to new `Conn` objects inside `synchronized(lock)`, then builds `snap.asReversed() + stored` (5,000 rows from the database). `onUpdate`, which the capture thread calls through JNI (`:156-166`), waits for the same lock.
- **Scenario:**
  - The native side sends connection dumps at 1 Hz (`CONNECTION_DUMP_UPDATE_FREQUENCY_MS`), so with any background traffic that is about 1 publish/s, screen off included.
  - 20k × roughly 130 B per `Conn` is about 2.6 MB/s of garbage. The lock is held for about 2–5 ms per tick (estimate), stalling the packet loop.
  - DNS queries count as connections, so 20k is reached within about a day of normal use.
  - When the UI is open, every tick also triggers full recomputes over 25k rows:
    - `LogsViewModel` filter (`ui/LogsViewModel.kt:66-68`);
    - `DashboardViewModel` → `ConnStats.summarize`: 5 `groupBy` passes plus 25k tracker lookups (`ui/DashboardViewModel.kt:12-15`);
    - `AppsViewModel` traffic `groupBy` plus a re-sort (`ui/AppsViewModel.kt:102-108`).
- **Confidence:** confirmed.
- **Fix:**
  - Keep `Conn` snapshots up to date incrementally in `onUpdate`, only for the ids that changed (use `ConnectionDescriptor.version`).
  - Write closed connections to the database from that path.
  - Build and publish the list only while `_conns.subscriptionCount > 0`, outside the lock (copy the changed ids first).
  - Precompute the tracker name once per connection, when its host is set.

**H4. The DoH proxy answers at most two queries at a time.**
- **Where:** `engine/DnsProxy.kt:46`, `ThreadPoolExecutor(2, 8, …, LinkedBlockingQueue(256))`. A `ThreadPoolExecutor` only grows past its core size when the queue is full, so the max of 8 is never used. Each worker blocks in `execute()` for up to `callTimeout` 6 s (`:107`, `:156`).
- **Scenario:** a page load with 40 lookups at 40 ms RTT finishes in about 800 ms instead of about 40 ms. One stalled server response blocks a whole lane for 6 s, and with two lanes all DNS on the device stalls.
- **Confidence:** confirmed (standard `ThreadPoolExecutor` behaviour).
- **Fix:** use OkHttp `enqueue()`, with `dispatcher.maxRequests` and `maxRequestsPerHost` set to about 64 (HTTP/2 multiplexes them), or set core = max = 16 with `allowCoreThreadTimeOut(true)`.

**H5. Starting the VPN does heavy blocking work on the main thread and races the compile started at app launch.**
- **Where:** `engine/CaptureService.kt:62-125` runs from `onStartCommand`, on the main thread:
  - `app.firewall.compileNow()` (`:73`): `RulesCompiler`, plus `pw_engine_load` of every list, plus, on the first compile after a GeoIP update, the full ASN tree walk in `GeoIp.asnPrefixes` (`analysis/GeoIp.kt:108-144`);
  - `UpstreamMonitor.resolve()`, which waits up to 4 s (`:81`; `engine/UpstreamMonitor.kt:97-107`).
- **Race:**
  - On a cold start from the tile or widget, `PacketwallApp.onCreate` also calls `firewall.scheduleCompile(0)` (`PacketwallApp.kt:92`) on IO.
  - Both run `compileNow()` at once (`fw/FirewallStore.kt:540-549`, not synchronized), write the same `rules.compiled.tmp` (`fw/RulesCompiler.kt:27`, `:78`) and each loads all the lists.
- **Scenario (estimate):** about 1M list entries (spec: 300k ≈ 0.1 s) takes about 0.35 s × 2 loads. Add up to 4 s of DNS, and seconds for the ASN walk. That is a frozen UI, and an ANR risk when started from the app. The two compiles writing the same file can also corrupt it.
- **Confidence:** confirmed.
- **Fix:**
  - Move `startCapture` onto a worker thread and keep only `establish()` and the bookkeeping on the main thread.
  - Run compiles one at a time through a single-thread dispatcher or a mutex, and skip a compile when its inputs are unchanged (hash of the state plus list mtimes).
  - Do not compile in `Application.onCreate`; compile when capture starts or when rules change.

---

### MEDIUM

**M1. The packet buffer counts only block bytes, so real memory use can be 2× the setting.**
- **Where:** `analysis/PacketStore.kt:161-173`. `bytes += block.size` leaves out the `Pkt` object (about 56 B), the key string per packet (about 70–100 B, not shared between packets of one connection) and the deque slots.
- **Scenario (estimate):** an ACK-heavy flow has EPBs of about 110 B and about 130 B of overhead each. A 16 MB buffer holds about 150k packets and costs about 20 MB more than counted. At the 128 MB setting that is about 1.2M packets and about +160 MB, with no `largeHeap`, so OOM.
- **Confidence:** confirmed (sizes estimated).
- **Fix:**
  - Count a fixed overhead per packet (e.g. +150 B) against the capacity.
  - Share one key per flow (store it in the `byKey` value) or use an int connection id (H2).
  - Or store packets in one large ring `ByteArray` with offset/length.

**M2. Compile storms and repeated full reloads.**
- **Where:** `fw/FirewallStore.kt:330-361`: every successful `download()` calls `update()` → `scheduleCompile(250)`.
- **Problems:**
  - Downloads take seconds, so `updateAllNow()` (the daily worker, `system/Schedules.kt:100-104`) recompiles and reloads every list once per downloaded list (N lists → N full loads).
  - `compileJob.cancel()` does not stop a compile that is already running (`:530-538`), so compiles overlap.
  - There are no conditional requests (`fw/ListSource.kt:16-36`: no ETag or If-Modified-Since), so unchanged lists are downloaded, parsed, written and recompiled again every day.
  - `pw_fw_load` builds the new engine while the old `g_current` still exists, so native memory peaks at about 2× (`core/pw_rules.c:717-729`).
  - The engine is also loaded on every process start (H5), including WorkManager-only starts, and held as `g_pending` while protection is off.
- **Confidence:** confirmed.
- **Fix:**
  - In `updateAllNow`, download everything first, then compile once.
  - Send ETag / If-Modified-Since, and skip `writeList` and the recompile when the content hash is unchanged.
  - Serialize compiles (see H5).
  - Free the pending engine while stopped, or compile lazily at start.

**M3. List parsing compiles a regex per line and holds the whole list in a hash set.**
- **Where:** `fw/ListParser.kt:104`, `l.split(Regex("\\s+"))`, which compiles a new `Regex` for every non-adblock line (hosts files, plain lists). `:49` collects every entry into a `LinkedHashSet` and copies it to a `List` (`:87`); the cap is 3M lines (`fw/FirewallStore.kt:553`).
- **Scenario (estimate):** StevenBlack hosts (about 150k lines) means about 150k `Pattern` compiles, about 0.3–0.5 s. A 3M-line list needs about 150 B per entry in the set, about 450 MB, so OOM.
- **Confidence:** confirmed (cost estimated).
- **Fix:**
  - Use one precompiled `Regex`, or a manual whitespace split.
  - Stream entries into the output file and deduplicate on hashes (a `LongOpenHashSet` of 64-bit hashes), or let `pw_rules` deduplicate on load.

**M4. Blocking startup work in `Application.onCreate` on the main thread, on every process start (tile, widget, workers).**
- **Where:** `PacketwallApp.kt:77-83`:
  - `Trackers` parses the whole `trackers.json` into a `JsonElement` tree (`analysis/Trackers.kt:55-62`, `:118-130`);
  - `FirewallStore` decodes `firewall.json` (`fw/FirewallStore.kt:56`, `:67-68`);
  - `GeoIp` opens two MMDB files and scans up to 128 KB backwards byte by byte for the metadata marker (`analysis/MmdbReader.kt:31-44`).
- **Scenario:** likely 100–300 ms of cold-start delay when the tracker database and many rules are present (file sizes not checked).
- **Confidence:** the main-thread code is confirmed; the timing is an estimate.
- **Fix:** load trackers and GeoIP lazily on a background thread; decode `firewall.json` off the main thread with a "loading" state.

**M5. Tracker lookups miss their cache on every tick.**
- **Where:** `analysis/ConnStats.kt:31` and `ui/LogsScreen.kt:159` call `trackingOf()` per connection. The cache is `LruCache(4096)` (`analysis/Trackers.kt:42`), which is synchronized. With more than 4,096 distinct hosts in 25k rows it misses every time, and each miss does `lowercase()` plus a `substring()` per label (`:72-86`).
- **Scenario (estimate):** about 25–50 ms of Default-dispatcher CPU per tick while Home is open (Home is the default screen).
- **Confidence:** likely.
- **Fix:** resolve the tracker once per connection (see H3) and store it in `Conn`, or use a larger `HashMap` cache keyed by host.

**M6. The connection's packet view re-dissects every packet every 800 ms, even when nothing changed.**
- **Where:** `ui/AnalysisScreens.kt:73-81`. A `while(true)` loop runs `buildRows(packetsOf(c))`, which does `Dissector.summary` for every packet, every 800 ms, also for closed connections. `remember(rows)` then rebuilds the payload blocks in `DataTab` and `HttpTab` (`:391`, `:478`).
- **Scenario (estimate):** a download connection with 50k buffered packets costs about 50–150 ms of CPU per poll, continuously while the tab is open.
- **Confidence:** confirmed.
- **Fix:** key on `packets.version` and the flow's packet count, add only new packets, and stop polling once the connection is closed.

**M7. The upstream proxy is probed with a TCP connect every 10 s (every 3 s while the relay is missing) for the whole session.**
- **Where:** `engine/UpstreamMonitor.kt:76`, `:86-91`.
- **Scenario:** with a remote proxy on mobile data, each connect wakes the radio and keeps its high-power tail running. At 10 s intervals the radio barely gets to idle while the screen is on or the device is not in Doze.
- **Confidence:** likely (the code is confirmed; the radio effect is the usual one).
- **Fix:**
  - Use exponential backoff to about 60 s while the proxy is up.
  - Probe on network change (`NetworkTracker`) and when connections through the proxy fail.
  - Skip the probes for loopback proxies, or keep them cheap there.

**M8. Imports parse and write on the main thread.**
- **Where:** `ui/SetsScreens.kt:328`: `ForeignImport.detect` parses the whole file as JSON (`fw/ForeignImport.kt:91`) on the main thread. `ui/SetsScreens.kt:749`: `firewall.importJson` decodes the JSON and runs `writeList` for the inlined lists, which can be millions of lines (`fw/FirewallStore.kt:459-526`), on the main thread.
- **Scenario:** a backup with inlined lists of tens of MB freezes the UI for seconds (ANR).
- **Confidence:** confirmed.
- **Fix:** wrap both in `withContext(Dispatchers.Default/IO)`. `detect` only needs the head of the file plus a streaming check of the top-level keys.

**M9. The country lookup for each new connection decodes the whole GeoIP record over JNI.**
- **Where:** `core/pcapdroid.c:607` → `NativeBridge.getCountryCode` → `analysis/GeoIp.kt:74-86` → `MmdbReader.lookup` (`analysis/MmdbReader.kt:94`). On a cache miss this decodes the full record: names in several languages plus the continent, about 30 maps and strings.
- **Scenario (estimate):** about 10–30 µs per new IP on the capture thread, plus pressure on the 4096-entry LRU cache.
- **Confidence:** confirmed (cost estimated).
- **Fix:** cache by the record's data offset (about 250 distinct country records) and decode only `country.iso_code`. Better still, do the MMDB lookup natively and drop the JNI call.

---

### LOW

- **L1. Native debug logs are on in release builds.** `common/utils.c:29` has `int loglevel = 0;` and nothing calls `set_log_level`. Every `log_d` therefore does `vsnprintf` plus a logcat write on the capture thread: per new connection (`core/capture_vpn.c:35-41`, which also always formats the 5-tuple), per nDPI result (`core/pcapdroid.c:772`), and per DNS answer (`:936`). It also leaks host names into logcat. Fix: `set_log_level(ANDROID_LOG_INFO)` in release. (Confirmed.)
- **L2. Unbounded growth.**
  - `ConnectionsRegister.saved` (`engine/ConnectionsRegister.kt:96`, `:193`) is never pruned when `byId` drops entries, so it grows by one boxed `Int` per closed connection for the whole session.
  - `LogDb.purge` only runs in `configureLog` (`:99-109`), at process start or on a settings change, so a VPN process that runs for weeks never purges.
  - Fix: remove ids when they are evicted, and purge daily.
- **L3. The disk recorder updates its state for every block.** `analysis/Streaming.kt:202`, `_state.value = copy(bytes=…)`, allocates per packet and recomposes the Captures card on every frame while it is visible. Throttle it to about 1 Hz.
- **L4. Small main-thread costs.**
  - `ui/ConnectionScreen.kt:55-57` collects the whole list and runs `indexOfFirst` over 25k rows every tick.
  - `ui/AnalysisScreens.kt:228` falls back to `packets.all()`, copying up to the whole ring under the capture lock, on the main thread.
  - `ui/ConnectionScreen.kt:131` does `geo.asn()`, and `ui/RulesScreens.kt:263` does `apps.byPackage()` (a PackageManager call), both in `remember` on the main thread.
- **L5. The speed history covers about 3 minutes, not about 10.** It holds 600 samples (`ConnectionsRegister.kt:169`, `:203`), but stats arrive every 300 ms (`core/pcapdroid.h:33`), and each sample copies the list. Use a ring buffer, or sample at 1 s.
- **L6. The log filter lowercases per row on every evaluation.** `analysis/ConnFilter.kt:55-56` runs `lowercase()` on both sides for each row; use `equals` / `contains(ignoreCase = true)` and lowercase the value once.

Checked and fine:
- JNI pcap data is batched (512 KB or 1 s, `core/pcap_dump.c:28-29`).
- The zdtun UDP relay patch uses `sendmsg` with an iovec and allocates nothing per packet.
- The rules hash index and the hot swap are lock-free on the capture thread.
- The log `LazyColumn` uses keys.
- Only the top screen in the back stack is composed.

---

### Top 5 fixes, by value

1. **Index `**.x` / `*.x` wildcards and IP/CIDR/ASN prefixes in `pw_rules.c` (H1).** This removes stalls of tens of ms per connection, and of seconds on reload, for wildcard or IP lists.
2. **Make the packet-store key cheap: a hex lookup table, or better a connection id in the EPB comment (H2); share one key per flow and count overhead against the capacity (M1).** This takes the main per-packet CPU cost and the OOM risk off the default capture path.
3. **Make `ConnectionsRegister` incremental: update only changed ids, publish only to subscribers and outside the lock, persist from the update path, precompute the tracker name (H3, M5).** This ends about 2.6 MB/s of garbage and the per-tick lock stalls while the screen is off.
4. **Fix DoH concurrency: async OkHttp, or core = max (H4).** This removes the two-lane DNS bottleneck and the 6 s stalls.
5. **Take capture start and compiles off the main thread and run them one at a time, skipping unchanged inputs, with ETag downloads and one compile per batch (H5, M2).** This fixes the startup freeze, the race on the compiled-rules file, and repeated loads of every list.
