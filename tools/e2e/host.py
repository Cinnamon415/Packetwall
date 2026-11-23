#!/usr/bin/env python3
"""
Host side of the instrumented e2e tests (app/src/androidTest): one process with
  - the test proxies of proxy.py: SOCKS5 :1081 (+UDP ASSOCIATE), SOCKS5 with a login :1082 (user/secret),
    HTTP CONNECT :3128 (user/secret); each logs what it connects to ("SOCKS CONNECT host port"…);
  - a control server on :8099, reached by the app (not through the VPN) and by the shell (through it):
      GET /log?since=N    proxy log lines from N on (header X-Total: number of lines)
      GET /lists/<file>   a fixture from tools/e2e/fixtures (ETag + 304 supported)
      GET /status/<code>  an empty reply with that HTTP status
      GET /hello          "hello" (a LAN target for the LAN bypass tests)
      GET /zeros?mb=N     N MB of zeros (fills the packet buffer)
      GET /hits           how many requests each path got (JSON)
      GET /switch?name=A&to=B   /lists/A serves fixture B from now on (a list that changes upstream)
      GET /forward?port=P&remote=localabstract:NAME   `adb forward tcp:P …` on the host, so the emulator
                          reaches the device socket at 10.0.2.2:P the way a PC does (USB stream)
      GET /unforward?port=P   removes it
Run it before ./gradlew connectedDebugAndroidTest (tools/e2e/run-instrumented.sh does both).
"""
import asyncio, hashlib, json, os, re, subprocess, sys, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proxy

LINES = []
HITS = {}
ALIAS = {}
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def log(*a):
    line = " ".join(str(x) for x in a)
    LINES.append(line)
    print(line, flush=True)


proxy.log = log


def reply(w, code, body=b"", headers=None):
    reason = {200: "OK", 304: "Not Modified", 404: "Not Found"}.get(code, "Status")
    h = {"Content-Length": str(len(body)), "Connection": "close", **(headers or {})}
    w.write(f"HTTP/1.1 {code} {reason}\r\n".encode() + "".join(f"{k}: {v}\r\n" for k, v in h.items()).encode() + b"\r\n" + body)


def adb(*args):
    """adb for the emulator under test: $ANDROID_SERIAL, else the first emulator-* device."""
    serial = os.environ.get("ANDROID_SERIAL")
    if not serial:
        out = subprocess.run(["adb", "devices"], capture_output=True, text=True).stdout.split("\n")
        serial = next((l.split()[0] for l in out if l.startswith("emulator-")), None)
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=15)


async def control(r, w):
    try:
        head = (await r.readuntil(b"\r\n\r\n")).decode(errors="replace").split("\r\n")
        method, target, _ = head[0].split(" ", 2)
        hdrs = {k.lower(): v.strip() for k, _, v in (l.partition(":") for l in head[1:] if l)}
        u = urllib.parse.urlparse(target)
        q = urllib.parse.parse_qs(u.query)
        HITS[u.path] = HITS.get(u.path, 0) + 1
        if u.path == "/log":
            since = int(q.get("since", ["0"])[0])
            reply(w, 200, "\n".join(LINES[since:]).encode(), {"X-Total": str(len(LINES))})
        elif u.path.startswith("/lists/"):
            name = os.path.basename(u.path)
            f = os.path.join(FIXTURES, ALIAS.get(name, name))
            if not os.path.isfile(f):
                reply(w, 404)
            else:
                body = open(f, "rb").read()
                tag = '"' + hashlib.sha1(body).hexdigest()[:16] + '"'
                if hdrs.get("if-none-match") == tag:
                    reply(w, 304, headers={"ETag": tag})
                else:
                    reply(w, 200, body, {"ETag": tag, "Content-Type": "text/plain"})
        elif u.path.startswith("/status/"):
            reply(w, int(u.path.rsplit("/", 1)[1]))
        elif u.path == "/switch":
            ALIAS[q["name"][0]] = q["to"][0]
            reply(w, 200, b"ok")
        elif u.path in ("/forward", "/unforward"):
            port = q.get("port", [""])[0]
            remote = q.get("remote", [""])[0]
            if not port.isdigit() or (u.path == "/forward" and not re.fullmatch(r"localabstract:[\w.]+", remote)):
                reply(w, 400)
            else:
                res = adb("forward", "tcp:" + port, remote) if u.path == "/forward" else adb("forward", "--remove", "tcp:" + port)
                log("ADB", u.path[1:], port, remote, "rc", res.returncode)
                reply(w, 200 if res.returncode == 0 else 500, (res.stdout + res.stderr).encode())
        elif u.path == "/hello":
            reply(w, 200, b"hello")
        elif u.path == "/zeros":
            # bulk traffic (fills the packet buffer): mb megabytes, at most 64
            mb = min(64, int(q.get("mb", ["1"])[0]))
            reply(w, 200, bytes(mb << 20), {"Content-Type": "application/octet-stream"})
        elif u.path == "/hits":
            reply(w, 200, json.dumps(HITS).encode(), {"Content-Type": "application/json"})
        else:
            reply(w, 404)
        await w.drain()
    except Exception as e:
        print("control err", e, flush=True)
    finally:
        w.close()


async def main():
    servers = [
        await asyncio.start_server(proxy.socks, "0.0.0.0", 1081),
        await asyncio.start_server(proxy.http, "0.0.0.0", 3128),
        await asyncio.start_server(proxy.socks_auth, "0.0.0.0", 1082),
        await asyncio.start_server(control, "0.0.0.0", 8099),
    ]
    log("listening")
    await asyncio.gather(*(s.serve_forever() for s in servers))


asyncio.run(main())
