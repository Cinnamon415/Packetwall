# Native code: changes to PCAPdroid and zdtun

Packetwall's packet engine is PCAPdroid's native core (`app/src/main/jni`, GPL-3.0, Emanuele Faranda)
with zdtun and nDPI as submodules. This file lists every change made to code that came from
upstream, so it can be re-applied to a newer PCAPdroid or zdtun. Commit `be085d8` holds the code as
imported; `git diff be085d8 -- app/src/main/jni` shows the exact edits.

Code that is entirely Packetwall's is not listed here: the rule engine `core/pw_rules.c` / `pw_rules.h`
and its host test `jni/tests/pw_rules`.

## JNI contract

The Kotlin side of the native engine is `engine/NativeBridge.kt`.

- **Class name.** `jni_impl.c` finds `io/github/cinnamon415/packetwall/engine/NativeBridge` by
  name (`cls.vpn_service`). The exported functions are named `Java_..._engine_NativeBridge_*`.
  Upstream these belong to PCAPdroid's `CaptureService`. Before the 0.6 refactor they belonged to
  Packetwall's `CaptureService`.
- **Callbacks by name.** The capture thread calls the instance methods of `NativeBridge` by name and
  signature. Renaming one in Kotlin breaks the engine at runtime, not at compile time. Among them:
  - `reportError`, `protect`, `getApplicationByUid`, `getPackageNameByUid`, `getCountryCode`,
    `dumpPcapData`, `updateConnections`, `sendStatsDump`, `getUidQ`;
  - the configuration getters `get*` / `is*` / `*Enabled`, read through `getStringPref` /
    `getIntPref` in `jni_impl.c`.
- **`ConnectionUpdate.setStats`.** The signature changed from `(JJJJIIIII)V` to `(JJJJIIIIII)V`:
  the last argument is the matched rule reference `fw_rule`.
- **Status bit `0x4000`.** In the stats word it means "proxied through the upstream".
- **`errors.h`.** Its comment now points to `NativeBridge.reportError`.

New exported functions, all in `jni_impl.c`:

| Function | Purpose |
|---|---|
| `loadRules(path)` | Load a compiled rules file (`RulesCompiler`) into `pw_rules.c`; works while stopped |
| `setDnsServerPort(port)` | Port of the forward DNS server: 53, or the local DoH proxy |
| `setUpstreamState(active, blockUdp)` | Upstream reachable (or kill switch); block UDP that would use it |
| `setUpstreamHttp(http)` | The upstream is an HTTP CONNECT proxy instead of SOCKS5 |
| `setUpstreamScope(all)` | Proxy everything, or only allow rules with route "upstream" |
| `setUdpRelay(ip, port)` | SOCKS5 UDP ASSOCIATE relay address; `""` removes it |
| `setUpstreamAddress(ip, port)` | The proxy's resolved address; `0.0.0.0` = unknown, proxied flows are blocked (0.7) |
| `setLogLevel(level)` | Native log level; release builds use WARN, so host names do not reach logcat (0.7) |

Changed callbacks (0.7): `getSocks5ProxyAuth` is replaced by `getSocks5ProxyUser` and
`getSocks5ProxyPass`, each read into its own 256-byte field, so long logins and passwords are no
longer cut at 64 bytes.

## `core/pcapdroid.c`, `core/pcapdroid.h`

- **Firewall.** PCAPdroid's firewall (blocklist + per-app allowlist, `firewall_app_allowlisted`) is
  replaced by `pw_fw_apply()`, which queries `pw_rules.c`. It is called:
  - when a connection is created;
  - when DPI learns the connection's host name (DNS, SNI, HTTP Host);
  - for every live connection after new rules are loaded (`recompute_conn_block_cb`).
- **Per-connection fields.** `pd_conn_t` gets:
  - `fw_rule` — the matched rule, logged and shown in the UI;
  - `fw_reject` — answer with RST instead of a silent drop;
  - `fw_route` — `PW_ROUTE_*` of the allow rule that matched.
- **New globals**, set over JNI:
  - `dns_server_port`;
  - `upstream_active`, `upstream_block_udp`, `upstream_http`, `upstream_all`;
  - the UDP relay: `udp_relay_ip`, `udp_relay_port`, `udp_relay_ipver`, and `udp_relay_dirty`,
    which the capture thread applies.
- **Stats.** The stats sent to Java carry `fw_rule` and the proxied bit.

- **Upstream address (0.7).** `upstream_lock` (a mutex) guards the proxy ip/port/version that
  `setUpstreamAddress` changes while the capture thread reads them. `upstream_unknown()` is true
  while the address is 0.0.0.0: the capture thread then blocks new proxied flows instead of
  connecting to 0.0.0.0, which would reach localhost (fail closed).
- **DNS cache (0.7).** `process_dns_reply()` takes the connection tuple and fills the IP → name cache
  only from replies of the VPN's own resolver (`internal_dns`), so an app cannot plant names for
  addresses with its own DNS server.

## `core/capture_vpn.c`

- **DNS redirect port.** The redirect of the VPN DNS address uses `dns_server_port` instead of a
  fixed 53, so queries can reach the built-in DoH proxy on 127.0.0.1.
- **Private DNS block.** Only DNS-over-TLS (port 853) to known DNS servers is dropped, which makes
  Android fall back to plain DNS. Upstream drops all traffic to those addresses, which broke HTTPS
  to 1.1.1.1 and apps' own DoH.
- **`send_tcp_rst()`.** A rejected TCP segment gets a RST, so the client fails at once instead of
  timing out. It is also sent when an established flow becomes blocked later, by SNI or HTTP Host;
  a silent drop would leave the client hanging.
- **`wants_upstream()`.** It decides per connection whether to use the upstream, from the rule's
  route and the upstream scope. Upstream only checks `socks5.enabled`.
- **UDP through the upstream.** UDP goes through the SOCKS5 relay (`zdtun_conn_udp_relay`) when one
  is set. Otherwise it is blocked while `upstream_block_udp` is on, so QUIC falls back to TCP through
  the proxy. Queries to the VPN DNS address are excluded from both.
- **Packet dump.** Packets dropped by the firewall are dumped with the new `dropped` flag.

## `core/pcap_dump.c`, `core/pcap_dump.h`, `core/capture_pcap.c`

- `pcap_dump_packet()` / `pd_dump_packet()` take a `dropped` argument; root-mode capture passes
  `false`.
- In pcapng:
  - The direction flag of the EPB is written in VPN mode too; upstream writes it in root mode only.
    The packets view uses it.
  - A packet dropped by the firewall gets an `opt_comment` "dropped".

## `core/CMakeLists.txt`

- Adds `pw_rules.c`.

## zdtun (`submodules/zdtun`)

Local commit `182b237` in the submodule, also kept as `patches/zdtun-http-connect-udp-relay.patch`.
Apply it with `git -C submodules/zdtun am ../../patches/zdtun-http-connect-udp-relay.patch` after
updating the submodule.

- **HTTP CONNECT proxy mode** (`zdtun_set_proxy_http`): instead of the SOCKS5 handshake, the
  connection to the proxy sends `CONNECT host:port`, with `Proxy-Authorization: Basic` when a login
  is set. It waits for a `2xx` reply.
- **SOCKS5 UDP relay**:
  - `zdtun_set_udp_relay` sets the relay address;
  - `zdtun_has_udp_relay` tells whether one is set;
  - `zdtun_conn_udp_relay` marks a UDP connection to go through it.

  Datagrams of a marked connection get the RFC 1928 UDP request header and go to the relay; replies
  are unwrapped. The UDP ASSOCIATE control connection itself is held by the app
  (`engine/UdpAssociation.kt`).

## nDPI

Unchanged.

## `core/pw_rules.c` (0.7 rewrite)

Packetwall's own rule engine (not from PCAPdroid):
- literal hash plus a suffix index for `*.x` and `**.x`; IP/CIDR and ASN prefixes sorted per prefix
  length for binary search; only other globs are scanned linearly, with a linear-time matcher;
- the best rule per (set, who) is kept while scanning, with no cap on matching candidates;
- seeded FNV hash with a murmur finalizer (no hash flooding with chosen names);
- a trailing dot is stripped from host names.
The host test `app/src/main/jni/tests/pw_rules/run.sh` (ASan) covers these, including the `**` and
200k-rule cases.

