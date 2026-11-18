# Packetwall 0.7: work plan

Sources:
- the owner's 11 points and choices on the mockups page (2026-11-17);
- audits in `docs/audits/`: D = defects/UX (A*, B*), S = security, P = performance.

Ordered by risk: first what lets traffic or data leak or get lost, then speed, then the new interface, then the rest.

## 1. Security and data loss

| # | What | From |
|---|---|---|
| 1.1 | Another app can switch protection off: remove TOGGLE_ON/OFF from the exported MainActivity; the tile, widget and notification use a non-exported trampoline | S-H1 |
| 1.2 | pcap-over-IP without authentication. Local: abstract LocalServerSocket, only adb shell/root (uid check). LAN: one-time token, bind to the Wi-Fi address only, client limit | S-H2 |
| 1.3 | Upstream fails closed: unresolvable proxy + kill switch = block everything; DNS goes through the upstream or is blocked; DoH does not bypass SOCKS5 with a login; Quad9 IPv6 fallback becomes a setting | S-H3, S-H4 |
| 1.4 | IPv6 route `::/0` (LAN bypass subtracts the local v6 prefixes): closes the NAT64 bypass | S-M1 |
| 1.5 | Rule engine: linear `**` matcher and a `**` limit; no candidate cap; DNS cache only from the VPN resolver's replies, with answer name check; seeded hash; strip the trailing dot from host names | S-M2, M3, M4, L2, L4 |
| 1.6 | Native log level WARN in release (hosts no longer go to logcat) | S-M5, P-L1 |
| 1.7 | Recompile on app install, remove and update; refresh the apps list | D-A2, S-M7, D-A13 |
| 1.8 | Compiles run one at a time and off the main thread; unique tmp file | D-A4, P-H5 |
| 1.9 | Stale list files on replace import and on id reuse | D-A1 |
| 1.10 | Deleting the active profile corrupts another one | D-A3 |
| 1.11 | Importing a single set duplicates groups; partial "replace" wipes profiles (now confirmation + backup) | D-A6, D-A7 |
| 1.12 | Protection toggling by itself after process death; exports lost when the screen is recreated | D-A8, D-A9 |
| 1.13 | Confirmation or undo for every deletion and the log clear | D-B1 |
| 1.14 | Size limits for downloads and imports; catch Throwable where a crash would kill the VPN; MMDB pointer depth | S-M6, L9, L10, D-A17 |
| 1.15 | Small items: | S-L1, L5, L7, L8 |
|  | - the DoH proxy accepts only the engine; | |
|  | - proxy login and password are no longer truncated; | |
|  | - URLs are confirmed when a configuration is imported; | |
|  | - dataExtractionRules; | |
|  | - secure_delete for the log. | |

## 2. Performance

| # | What | From |
|---|---|---|
| 2.1 | `**.x` / `*.x` and IP/CIDR/ASN go into an index instead of a linear scan | P-H1 |
| 2.2 | Packet store: connection id in the EPB comment instead of the hex key; one key per connection; overhead counted against the buffer size | P-H2, P-M1 |
| 2.3 | Incremental connection register: only changed ones, nothing built while nobody watches, outside the lock; tracker computed once | P-H3, P-M5 |
| 2.4 | DoH: parallel requests instead of 2 lanes | P-H4 |
| 2.5 | List updates: download all lists, then one compile; ETag / If-Modified-Since; no recompile if nothing changed; no regex per line | P-M2, P-M3 |
| 2.6 | Startup: trackers, GeoIP and firewall.json load lazily or off the main thread | P-M4 |
| 2.7 | Packet and data screens: no re-parsing every 0.8 s; stop when the connection closes; gestures not interrupted | P-M6, D-A18, D-A19 |
| 2.8 | Smaller items: | P-M7, M9, L2-L6 |
|  | - backoff for upstream checks; | |
|  | - country lookup by ISO code only; | |
|  | - pruning of `saved` and the database; | |
|  | - recorder state throttled to 1 Hz; | |
|  | - speed history covers 10 min; | |
|  | - filter without lowercase per row. | |

## 3. Interface (mockups)

| # | What | Choice |
|---|---|---|
| 3.1 | Theme: "System / Light / Dark" segments in Settings | T1 |
| 3.2 | Pause: banner with a "Running / Paused / Off" switch on Home (line "VPN · Main" as now); "Resume" in the notification | variant 3 |
| 3.3 | Separate switches for "Keep packets in memory" and "Write to disk" | point 2 |
| 3.4 | "File analysis" drawer item: open pcap/pcapng, recent files, recordings; connections and packets in the existing screens | B |
| 3.5 | Lists: "Connected" + "Catalog" by category, "Add by URL or file" button | B |
| 3.6 | Edits layer on top of a list: search entries, disable, add your own entries, "outdated" edits, reset | A |
| 3.7 | App groups: "Members" and "Rules" tabs, members with ✕, full-screen picker | B |
| 3.8 | "Search" drawer item: flat list with chips (rules with their location, lists, apps, connections), tap opens the place | B |
| 3.9 | Sets and profiles: "+ New profile" under the profiles; no duplicates (new set only at the bottom, file import only in Lists) | A |
| 3.10 | Stream to PC: card with status and a "How to connect" sheet (USB / Wi-Fi, real IP, copy buttons; with 1.2: token) | A |
| 3.11 | ⓘ with explanations for non-obvious settings; filter help (fields, operators, examples tap to insert); obvious captions removed | A |
| 3.12 | About: version, guide, changelog, diagnostics with "Copy report", licenses | A |

## 4. Other defects

- Rule effectiveness (D-A5):
  - "Allow" from the log has to work: offer to delete the blocking rule;
  - warn when the new rule is broader within the same set.
- Counters and Home (D-A10, B2):
  - one counting scope for Home and Statistics;
  - Home tiles open an already-filtered Log;
  - quick allow from the recent blocks.
- Input and settings (D-A11, A12, A14, A15, A20):
  - proxy port with validation;
  - the recorder restarts when its parameters change;
  - deleting GeoIP asks first and marks country/ASN rules as inactive;
  - country code only in Latin letters;
  - no race between settings writers.
- Dates in the log for older days (D-A16).
- Navigation (D-A21, B5): navigation state is cleaned up; the arrows on a connection follow the log filter.
- Wrong text (D-A22): "the database will come later".
- Block reasons and rule state (D-B3, B4):
  - why something was blocked when no rule did it (Private DNS, kill switch);
  - rules of a disabled set are greyed out.
- Statistics is clickable (D-B6).
- Russian text (D-B7, B8):
  - remaining English in the RU interface;
  - terms made consistent ("Журнал", lists, recordings);
  - no truncated chips;
  - plurals.
- Accessibility (D-B9): content descriptions for icons; set reordering without drag.
- Smaller items (D-B10, B11):
  - warning on a global "block everything";
  - file name on import;
  - correct set deletion text;
  - duplicate list URLs;
  - the app's groups shown on its page.
- Spec gaps (D-B12):
  - app connection history;
  - "subnet" in quick actions;
  - profile picker on Global rules;
  - profile switching from the tile;
  - profile in "why blocked";
  - profile on Home is tappable.

## Not doing (with reasons)

- **VPN in a separate process (S-M6).** All state (rules, connections, settings, the packet buffer) is shared through in-memory singletons; moving the VPN to another process means IPC under almost every screen (the log as deltas within Binder's 1 MB, packets on demand, multi-process settings). Not done in 0.7. What is done, and what it does not cover:
  - size limits and catch Throwable make a crash from hostile input (lists, imports) unlikely; any other crash in the UI still stops the VPN;
  - capture files, the largest risk, are parsed in their own process (":parser") as a stream onto disk; the main process holds only the connection table (a 441 MB file: +8 MB);
  - Settings → Network shows whether Always-on VPN + lockdown is on (with help and a link), and a one-time dialog suggests it after protection first starts; with both on, a crash drops the internet for seconds instead of leaking.
- **ICMP through the proxy (S-L11).** SOCKS5 and HTTP CONNECT do not carry ICMP. **Not fixed yet:** with "everything through upstream" ICMP currently goes out directly (real address). Options are being chosen (block / reject / local reply / direct by choice).

## Testing

- Unit tests for the new logic.
- Host test of the engine, including the `**` and hash attack cases from the audit.
- e2e on the emulator and Waydroid, new scenarios:
  - toggle protection from another app (must fail);
  - stream without a token (must be refused);
  - kill switch with an unresolvable host;
  - IPv6 route.
- Release build. Commits per section.

## Status (2026-11-18)

Done: sections 1–3 and 4, except:
- profile switching from the Quick Settings tile: a tile has one tap, which toggles protection;
  profiles switch from Home and Global rules instead;
- the profile in "why blocked": a connection keeps the rule that decided it, not the profile active
  then, so showing today's profile there would mislead;
- day separators in the log: rows from earlier days show the date instead;
- S-L1 (the local DoH resolver is reachable by other apps on the device): Android hides other apps'
  sockets in /proc/net, so the resolver cannot tell the engine from another app. It only answers
  DNS, the same answers the VPN gives every app.

