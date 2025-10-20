# -*- coding: utf-8 -*-
import socket, sys, time
def main(addr, deadline_ts):
    host, port = addr.split(":"); port = int(port)
    deadline = float(deadline_ts)
    req = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            s.sendall(req)
            data = b""
            while b"\r\n" not in data and len(data) < 4096:
                chunk = s.recv(1024)
                if not chunk: break
                data += chunk
            s.close()
            line = data.split(b"\r\n", 1)[0] if b"\r\n" in data else data
            if line.startswith(b"HTTP/1.1 405"):
                print("[OK] HTTP 首行：", line.decode("ascii","replace"))
                return 0
            else:
                print("[TRY] 首行：", line.decode("ascii","replace"))
        except Exception as e:
            print(f"[DEBUG] Exception: {e}")
            time.sleep(0.2)
    print("[ERR] HTTP 协议就绪探测失败")
    return 1
if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
