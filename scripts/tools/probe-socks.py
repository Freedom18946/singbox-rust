# -*- coding: utf-8 -*-
# 只做 SOCKS5 握手（NO_AUTH），不发 CONNECT，避免依赖外部网络/路由
import socket, sys, time

def main(addr, deadline_ts):
    host, port = addr.split(":")
    port = int(port)
    deadline = float(deadline_ts)
    greet = b"\x05\x01\x00"  # VER=5, NMETHODS=1, NO_AUTH(0x00)

    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            s.sendall(greet)
            resp = b""
            while len(resp) < 2:
                chunk = s.recv(2 - len(resp))
                if not chunk:
                    break
                resp += chunk
            s.close()
            if resp == b"\x05\x00":
                print("[OK] SOCKS5 NO_AUTH accepted")
                return 0
            else:
                print(f"[TRY] greet resp: {resp!r}")
        except Exception as e:
            print(f"[DEBUG] Exception: {e}")
            time.sleep(0.2)
    print("[ERR] SOCKS5 协议就绪探测失败")
    return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))