#!/usr/bin/env python3
"""把一个本地端口转发到「经 SOCKS5h 代理」的某个目标。

为什么需要它：uTLS 原版有两条测试硬编码拨 `www.google.com:443` / `yahoo.com:443`，
而 Go 的 `net.Dial` **不认**代理环境变量。于是用一个本机转发器 + /etc/hosts 把
那两个名字指到 127.0.0.x，由转发器替它们走 SOCKS5h（socks5h = 目标名交给代理解析）。
"""
import socket, sys, threading

def socks5_connect(proxy_host, proxy_port, target_host, target_port):
    s = socket.create_connection((proxy_host, proxy_port), timeout=20)
    s.sendall(b"\x05\x01\x00")                      # ver=5, nmethods=1, no-auth
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 代理不接受 no-auth")
    host = target_host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + target_port.to_bytes(2, "big")
    s.sendall(req)
    resp = s.recv(4)
    if len(resp) < 4 or resp[1] != 0:
        raise RuntimeError(f"SOCKS5 CONNECT 失败: {resp!r}")
    atyp = resp[3]
    s.recv(4 if atyp == 1 else 16 if atyp == 4 else s.recv(1)[0] + 0)
    s.recv(2)
    return s

def pump(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for x in (a, b):
            try: x.shutdown(socket.SHUT_RDWR)
            except OSError: pass

def main():
    listen_ip, listen_port, target_host, target_port = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_ip, listen_port)); srv.listen(64)
    print(f"fwd {listen_ip}:{listen_port} -> socks5h-> {target_host}:{target_port}", flush=True)
    while True:
        c, _ = srv.accept()
        def handle(c=c):
            try:
                up = socks5_connect("127.0.0.1", 2080, target_host, target_port)
            except Exception as e:
                print("upstream failed:", e, flush=True); c.close(); return
            threading.Thread(target=pump, args=(c, up), daemon=True).start()
            threading.Thread(target=pump, args=(up, c), daemon=True).start()
        threading.Thread(target=handle, daemon=True).start()

if __name__ == "__main__":
    main()
