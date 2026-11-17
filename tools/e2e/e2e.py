#!/usr/bin/env python3
"""
End-to-end tests of Packetwall on an emulator (rooted adb, x86_64 AOSP image).

Every scenario writes a known configuration (firewall.json + settings), (re)starts protection from
adb and checks real traffic made with toybox nc from the emulator shell (uid 0 = pseudo-app "root").
The upstream scenarios need tools/e2e/proxy.py running on the host (SOCKS5 :1081, HTTP CONNECT :3128).

    python3 tools/e2e/e2e.py [--apk app/build/outputs/apk/debug/app-debug.apk] [scenario ...]
"""
import argparse, json, os, re, subprocess, sys, tempfile, time

ADB = os.environ.get("ADB", os.path.expanduser("~/Android/Sdk/platform-tools/adb"))
PKG = os.environ.get("PW_PKG", "io.github.cinnamon415.packetwall.debug")
SVC = f"{PKG}/io.github.cinnamon415.packetwall.engine.CaptureService"
HOST = os.environ.get("HOST", "10.0.2.2")    # the host as seen from the device (Waydroid: 192.168.240.1)
ROOTED = False                                # adb root available (emulator) or not (Waydroid)
RUN_AS = True                                 # run-as works (not in Waydroid's LXC container)
ACTIVITY = f"{PKG}/io.github.cinnamon415.packetwall.MainActivity"
PROXY_LOG = os.environ.get("PROXY_LOG", "")
results = []


def adb(*args, check=False, timeout=60):
    r = subprocess.run([ADB, *args], capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout


def sh(cmd, timeout=60):
    return adb("shell", cmd, timeout=timeout)


def put_file(rel, content):
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(content)
    adb("push", f.name, "/data/local/tmp/pw-e2e")
    sh(f"run-as {PKG} sh -c 'mkdir -p $(dirname {rel}); cat /data/local/tmp/pw-e2e > {rel}'")
    os.unlink(f.name)


def vpn_up():
    # the tun interface of Packetwall (dumpsys output differs between Android versions)
    return "10.215.173.1" in sh("ip addr show tun0 2>/dev/null")


def stop():
    if ROOTED: sh(f"am startservice -n {SVC} -a io.github.cinnamon415.packetwall.STOP")
    else: sh(f"am start -n {ACTIVITY} -a io.github.cinnamon415.packetwall.TOGGLE_OFF")
    for _ in range(20):
        if not vpn_up():
            return
        time.sleep(0.5)


def start():
    sh(f"appops set {PKG} ACTIVATE_VPN allow")
    if ROOTED: sh(f"am start-foreground-service -n {SVC} -a io.github.cinnamon415.packetwall.START")
    else: sh(f"am start -n {ACTIVITY} -a io.github.cinnamon415.packetwall.TOGGLE_ON")
    for _ in range(30):
        if vpn_up():
            time.sleep(2.5)       # rules compiled + loop started
            return
        time.sleep(0.5)
    raise RuntimeError("VPN did not come up")


SET = lambda i, n, **kw: {"id": i, "name": n, **kw}
G = {"type": "global"}
ROOT = {"type": "app", "pkg": "root"}         # the app that the shell traffic belongs to (set in main)


def rule(i, set_id, who, kind, value="", subs=False, action="BLOCK", **kw):
    return {"id": i, "setId": set_id, "who": who, "target": {"kind": kind, "value": value, "subdomains": subs}, "action": action, **kw}


def configure(rules=(), sets=None, order=None, settings=None, lists=None):
    stop()
    sets = sets or [SET(1, "Default"), SET(2, "Low")]
    order = order or [{"id": s["id"], "enabled": True} for s in sets]
    state = {"sets": sets, "order": order, "rules": list(rules),
             "profiles": [{"id": 3, "name": "Main", "sets": order}], "activeProfile": 3, "nextId": 10000}
    # adb over the network (Waydroid, phones over Wi-Fi) needs the LAN outside the VPN
    base = {"dns_mode": 0, "up": False, "stream": False, "record": False, "capture_packets": True, "log_days": 0,
            "lan_bypass": not ROOTED}
    base.update(settings or {})
    if RUN_AS:
        sh(f"am force-stop {PKG}")
        put_file("files/firewall.json", json.dumps(state))
        for set_id, lines in (lists or {}).items():
            put_file(f"files/lists/{set_id}.txt", "\n".join(lines) + "\n")
        xml = ["<?xml version='1.0' encoding='utf-8' standalone='yes' ?>", "<map>"]
        for k, v in base.items():
            if isinstance(v, bool): xml.append(f'    <boolean name="{k}" value="{str(v).lower()}" />')
            elif isinstance(v, int): xml.append(f'    <int name="{k}" value="{v}" />')
            else: xml.append(f'    <string name="{k}">{v}</string>')
        xml.append("</map>")
        put_file("shared_prefs/settings.xml", "\n".join(xml) + "\n")
    else:
        # debug-only TestConfigActivity: the app applies the configuration itself
        import base64
        export = {"format": "packetwall-rules", "formatVersion": 1, "state": state,
                  "lists": {str(k): v for k, v in (lists or {}).items()}}
        b64 = lambda o: base64.b64encode(json.dumps(o).encode()).decode()
        sh(f"am start -W -n {PKG}/io.github.cinnamon415.packetwall.TestConfigActivity --es settings {b64(base)} --es fw {b64(export)}")
        time.sleep(1.5)
    start()


def http(host, ip=None, port=80, timeout=6):
    """(first line of the reply or error, milliseconds)"""
    target = ip or host
    out = sh(f"s=$(date +%s%N); r=$(printf 'GET / HTTP/1.0\\r\\nHost: {host}\\r\\n\\r\\n' | timeout {timeout} toybox nc {target} {port} 2>&1 | head -1); "
             f"e=$(date +%s%N); echo \"$r|$(( (e-s)/1000000 ))\"", timeout=timeout + 15).strip()
    line, _, ms = out.rpartition("|")
    return line.strip(), int(ms or 0)


def dns_udp(server, name="example.com"):
    """All reply bytes as hex strings ([] = no reply)."""
    q = "\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00" + "".join(
        f"\\x{len(p):02x}{p}" for p in name.split(".")) + "\\x00\\x00\\x01\\x00\\x01"
    return sh(f"printf '{q}' | timeout 4 toybox nc -u -w 3 {server} 53 | od -An -tx1").split()


def dns_spoofed(reply):
    """Packetwall's local answer to a blocked query: an A record 0.0.0.0."""
    return len(reply) > 12 and reply[-4:] == ["00", "00", "00", "00"]


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}", flush=True)


def skip(name, why):
    print(f"SKIP  {name}  {why}", flush=True)


def ok(r): return r[0].startswith("HTTP/1.")


def allowed(host, ip=None, port=80):
    """Allowed traffic: one retry with a longer timeout (cold DNS / HTTP/2 setup on the host)."""
    r = http(host, ip, port, timeout=10)
    if not ok(r):
        time.sleep(1)
        r = http(host, ip, port, timeout=10)
    return ok(r)
def refused(r): return ("refused" in r[0] or "No address" in r[0] or r[0] == "") and r[1] < 3000


def proxy_log_since(n):
    if not PROXY_LOG or not os.path.exists(PROXY_LOG): return []
    return open(PROXY_LOG).read().splitlines()[n:]


def proxy_log_len():
    return len(open(PROXY_LOG).read().splitlines()) if PROXY_LOG and os.path.exists(PROXY_LOG) else 0


# ------------------------------------------------------------------ scenarios

def s_baseline():
    configure()
    check("baseline: example.org allowed", allowed("example.org"))
    check("baseline: wikipedia allowed", allowed("www.wikipedia.org"))


def s_domain_rules():
    configure([rule(10, 1, G, "DOMAIN", "example.org", True), rule(11, 1, G, "DOMAIN", "www.example.org", False, "ALLOW")])
    r = http("example.org")
    check("global block + DNS answered locally (fast)", refused(r), str(r))
    check("narrower exact allow wins", allowed("www.example.org"))
    check("unrelated host allowed", allowed("www.wikipedia.org"))


def s_app_rules():
    configure([rule(10, 1, ROOT, "ALL"), rule(11, 1, ROOT, "DOMAIN", "wikipedia.org", True, "ALLOW")])
    check("app block-all", refused(http("example.org")))
    check("app exception inside block-all", allowed("www.wikipedia.org"))


def s_set_priority():
    # global allow in set 1 does not open an app block in the lower set 2
    configure([rule(10, 1, G, "DOMAIN", "example.org", True, "ALLOW"), rule(11, 2, ROOT, "DOMAIN", "example.org", True)])
    check("global allow does not lift a lower app block", refused(http("example.org")))
    configure([rule(10, 1, G, "DOMAIN", "example.org", True, "BLOCK"), rule(11, 2, ROOT, "DOMAIN", "example.org", True, "ALLOW")])
    check("higher set wins over a lower app allow", refused(http("example.org")))


def s_ip_port_reject():
    configure([rule(10, 1, G, "IP", "1.1.1.1", False, "BLOCK", proto="TCP", port=80, reject=True)])
    r = http("one.one.one.one", "1.1.1.1", 80)
    check("IP+TCP/80 reject: refused by RST", "refused" in r[0] and r[1] < 1500, str(r))
    # plain HTTP to the HTTPS port: Cloudflare answers "400", which proves the connection was allowed
    check("same IP other port allowed", allowed("one.one.one.one", "1.1.1.1", 443))


def s_blocklist():
    configure(sets=[SET(1, "Default"), SET(5, "List", kind="BLOCKLIST", entries=3)],
              lists={5: ["example.org", "!www.example.org", "=exact.example.net"]})
    check("blocklist entry (+subdomains)", refused(http("example.org")))
    check("blocklist exception (!)", allowed("www.example.org"))


def s_disabled_set():
    configure([rule(10, 2, G, "DOMAIN", "example.org", True)], order=[{"id": 1, "enabled": True}, {"id": 2, "enabled": False}])
    check("rules of a disabled set do not apply", allowed("example.org"))


def s_doh():
    configure([rule(10, 1, G, "DOMAIN", "example.org", True)], settings={"dns_mode": 1, "doh_url": "https://9.9.9.9/dns-query"})
    check("DoH (Quad9, HTTP/2) resolves", allowed("www.wikipedia.org"))
    check("DoH: blocked name answered locally", refused(http("example.org")))


def s_upstream_socks():
    n = proxy_log_len()
    configure(settings={"up": True, "up_host": HOST, "up_port": 1081, "up_type": 0, "up_udp": 2, "up_down": 0})
    time.sleep(2)
    check("SOCKS5: TCP through the proxy", allowed("example.org"))
    a = dns_udp("9.9.9.9")
    time.sleep(1)
    log = proxy_log_since(n)
    check("SOCKS5: UDP via UDP ASSOCIATE", a[:2] == ["12", "34"] and not dns_spoofed(a) and any("UDP -> 9.9.9.9 53" in l for l in log), " ".join(a[:4]))
    check("SOCKS5: proxy saw TCP CONNECT", any("SOCKS CONNECT" in l for l in log))


def s_upstream_http():
    n = proxy_log_len()
    configure(settings={"up": True, "up_host": HOST, "up_port": 3128, "up_type": 1, "up_user": "user", "up_pass": "secret",
                        "up_udp": 1, "up_down": 0, "dns_mode": 1, "doh_url": "https://1.1.1.1/dns-query"})
    check("HTTP CONNECT + Basic auth: TCP works", allowed("www.wikipedia.org"))
    log = proxy_log_since(n)
    check("HTTP CONNECT: DoH went through the proxy", any("HTTP CONNECT 1.1.1.1:443" in l for l in log))
    a = dns_udp("9.9.9.9")
    check("HTTP proxy: UDP blocked (DNS answered locally)", a == [] or dns_spoofed(a), " ".join(a[-4:]))


def s_kill_switch():
    configure(settings={"up": True, "up_host": HOST, "up_port": 1, "up_type": 0, "up_udp": 1, "up_down": 0})
    time.sleep(2)
    check("kill switch: proxy down -> refused", refused(http("example.org", "93.184.215.14")))
    configure(settings={"up": True, "up_host": HOST, "up_port": 1, "up_type": 0, "up_udp": 1, "up_down": 1})
    time.sleep(2)
    check("fallback: proxy down -> direct", allowed("www.wikipedia.org"))


def s_route_rule():
    n = proxy_log_len()
    configure([rule(10, 1, G, "DOMAIN", "example.org", True, "ALLOW", route="UPSTREAM")],
              settings={"up": True, "up_host": HOST, "up_port": 1081, "up_type": 0, "up_all": False, "up_udp": 0, "up_down": 0})
    time.sleep(2)
    a, b = allowed("example.org"), allowed("www.wikipedia.org")
    log = [l for l in proxy_log_since(n) if "SOCKS CONNECT" in l]
    check("route rule: matched host via upstream, others direct", a and b and len(log) == 1, f"{len(log)} proxied")


def s_geo():
    has = "country.mmdb" in sh(f"run-as {PKG} ls files/geo")
    if not has:
        skip("country/ASN rules", "GeoIP databases not downloaded on this device (Settings → GeoIP)")
        return
    configure([rule(10, 1, ROOT, "COUNTRY", "ru", reject=True), rule(11, 1, ROOT, "ASN", "AS13335", reject=True)],
              settings={"dns_mode": 1, "doh_url": "https://1.1.1.1/dns-query"})
    check("country rule (yandex.ru, RU)", refused(http("yandex.ru", "77.88.44.55")))
    check("ASN rule (Cloudflare 1.0.0.1)", refused(http("one.one.one.one", "1.0.0.1")))
    check("other country/AS allowed (wikipedia)", allowed("www.wikipedia.org", "185.15.59.224"))


def s_streaming():
    configure(settings={"stream": True, "record": True, "record_mb": 8})
    adb("forward", "tcp:57012", "tcp:57012")
    out = tempfile.mktemp(suffix=".pcapng")
    p = subprocess.Popen(f"timeout 8 nc 127.0.0.1 57012 > {out}", shell=True)
    time.sleep(2)
    http("example.org"); http("www.wikipedia.org")
    p.wait()
    n = subprocess.run(["capinfos", "-c", out], capture_output=True, text=True).stdout
    m = re.search(r"Number of packets:\s+(\d+)", n)
    check("pcap-over-IP stream readable by Wireshark", m and int(m.group(1)) > 5, m.group(0) if m else n[-200:])
    time.sleep(1.5)
    files = sorted(x for x in sh(f"run-as {PKG} ls files/captures").split() if x.startswith("ring-"))
    local = tempfile.mktemp(suffix=".pcapng")
    with open(local, "wb") as f:
        f.write(subprocess.run([ADB, "exec-out", f"run-as {PKG} cat files/captures/{files[-1]}"], capture_output=True).stdout)
    n2 = subprocess.run(["capinfos", "-c", local], capture_output=True, text=True).stdout
    m2 = re.search(r"Number of packets:\s+(\d+)", n2)
    check("ring recording readable while recording", m2 and int(m2.group(1)) > 5, m2.group(0) if m2 else "")


def s_stress():
    configure([rule(10, 1, G, "DOMAIN", "example.org", True)])
    sh("for i in $(seq 1 60); do (printf 'GET / HTTP/1.0\\r\\nHost: www.wikipedia.org\\r\\n\\r\\n' | timeout 8 toybox nc www.wikipedia.org 80 >/dev/null 2>&1 &); "
       "(printf 'x' | timeout 3 toybox nc example.org 80 >/dev/null 2>&1 &); done; sleep 9", timeout=60)
    pid = sh(f"pidof {PKG}").strip()
    check("stress: 120 concurrent flows, app alive", pid != "", f"pid {pid}")
    check("stress: still filtering", refused(http("example.org")) and allowed("www.wikipedia.org"))


SCENARIOS = [s_baseline, s_domain_rules, s_app_rules, s_set_priority, s_ip_port_reject, s_blocklist, s_disabled_set,
             s_doh, s_upstream_socks, s_upstream_http, s_kill_switch, s_route_rule, s_geo, s_streaming, s_stress]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk")
    ap.add_argument("only", nargs="*")
    a = ap.parse_args()
    global ROOTED
    adb("root"); time.sleep(3); adb("wait-for-device")
    uid = sh("id -u").strip()
    ROOTED = uid == "0"
    ROOT["pkg"] = "root" if ROOTED else "com.android.shell"
    if a.apk:
        print(adb("install", "-r", a.apk).strip())
    global RUN_AS
    probe = sh(f"run-as {PKG} id 2>&1")
    RUN_AS = "uid=" in probe
    print(f"device shell uid {uid}, rooted={ROOTED}, run-as={RUN_AS}, host={HOST}", flush=True)
    adb("logcat", "-c")
    for s in SCENARIOS:
        if a.only and s.__name__[2:] not in a.only:
            continue
        try:
            s()
        except Exception as e:
            check(s.__name__, False, f"exception: {e}")
    stop()
    log = adb("logcat", "-d")
    crashes = [l for l in log.splitlines() if ("FATAL EXCEPTION" in l or "JNI DETECTED" in l or "Fatal signal" in l)]
    check("no crashes / JNI errors in logcat", not crashes, "; ".join(crashes[:3]))
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
