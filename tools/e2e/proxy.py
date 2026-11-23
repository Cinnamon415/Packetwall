import asyncio, struct, socket, sys, base64
log=lambda *a: print(*a, flush=True)
async def pipe(r, w):
    try:
        while (d := await r.read(65536)): w.write(d); await w.drain()
    except Exception: pass
    finally:
        try:
            if w.can_write_eof(): w.write_eof()
            else: w.close()
        except Exception: pass
class Relay(asyncio.DatagramProtocol):
    def __init__(s): s.client=None
    def connection_made(s,t): s.t=t
    def datagram_received(s, data, addr):
        if s.client is None or addr==s.client:
            s.client=addr
            at=data[3]
            if at==1: host=socket.inet_ntoa(data[4:8]); off=8
            elif at==4: host=socket.inet_ntop(socket.AF_INET6,data[4:20]); off=20
            else: n=data[4]; host=data[5:5+n].decode(); off=5+n
            port=struct.unpack("!H",data[off:off+2])[0]
            s.t.sendto(data[off+2:], (host,port)); log("UDP ->", host, port, len(data)-off-2)
        else:
            hdr=b"\x00\x00\x00\x01"+socket.inet_aton(addr[0])+struct.pack("!H",addr[1])
            s.t.sendto(hdr+data, s.client); log("UDP <-", addr[0], addr[1], len(data))
async def socks(r, w):
    try:
        try: ver, n = await r.readexactly(2)
        except asyncio.IncompleteReadError: w.close(); return
        await r.readexactly(n); w.write(b"\x05\x00")
        await socks_request(r, w, "SOCKS")
    except Exception as e: w.close()
async def socks_auth(r, w):
    # SOCKS5 with a login (RFC 1929): user / secret
    try:
        try: ver, n = await r.readexactly(2)
        except asyncio.IncompleteReadError: w.close(); return
        methods = await r.readexactly(n)
        if 2 not in methods:
            w.write(b"\x05\xff"); await w.drain(); w.close(); log("SOCKS AUTH no login offered"); return
        w.write(b"\x05\x02"); await w.drain()
        _, ul = await r.readexactly(2); u = await r.readexactly(ul)
        pl = (await r.readexactly(1))[0]; pw = await r.readexactly(pl)
        if u != b"user" or pw != b"secret":
            w.write(b"\x01\x01"); await w.drain(); w.close(); log("SOCKS AUTH bad login"); return
        w.write(b"\x01\x00"); await w.drain()
        await socks_request(r, w, "SOCKS AUTH")
    except Exception as e: w.close()
async def socks_request(r, w, tag):
    if True:
        ver, cmd, _, at = await r.readexactly(4)
        if at == 1: host = socket.inet_ntoa(await r.readexactly(4))
        elif at == 3: host = (await r.readexactly((await r.readexactly(1))[0])).decode()
        else: host = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        port = struct.unpack("!H", await r.readexactly(2))[0]
        if cmd == 3:
            loop=asyncio.get_running_loop()
            t,p = await loop.create_datagram_endpoint(Relay, local_addr=("0.0.0.0",0))
            bport=t.get_extra_info("sockname")[1]
            w.write(b"\x05\x00\x00\x01"+socket.inet_aton("0.0.0.0")+struct.pack("!H",bport)); await w.drain()
            log("ASSOCIATE relay port", bport)
            await r.read()  # association lives while TCP is open
            t.close(); log("ASSOCIATE closed"); return
        rr, ww = await asyncio.open_connection(host, port)
        w.write(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"); await w.drain()
        log(tag + " CONNECT", host, port)
        await asyncio.gather(pipe(r, ww), pipe(rr, w))
async def http(r, w):
    try:
        head=b""
        while b"\r\n\r\n" not in head:
            d = await r.read(4096)
            if not d: w.close(); return
            head += d
        lines=head.split(b"\r\n"); target=lines[0].split()[1].decode()
        auth=[l for l in lines if l.lower().startswith(b"proxy-authorization:")]
        if not auth or base64.b64decode(auth[0].split()[-1])!=b"user:secret":
            w.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"); await w.drain(); w.close(); log("HTTP 407", target); return
        host,port=target.rsplit(":",1); host=host.strip("[]")
        rr,ww=await asyncio.open_connection(host,int(port))
        w.write(b"HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\n"); await w.drain(); log("HTTP CONNECT", target)
        await asyncio.gather(pipe(r, ww), pipe(rr, w))
    except Exception as e: log("http err", e); w.close()
async def main():
    a=await asyncio.start_server(socks,"0.0.0.0",1081); b=await asyncio.start_server(http,"0.0.0.0",3128); c=await asyncio.start_server(socks_auth,"0.0.0.0",1082); log("listening")
    async with a, b: await asyncio.gather(a.serve_forever(), b.serve_forever())
if __name__ == "__main__":
    asyncio.run(main())
