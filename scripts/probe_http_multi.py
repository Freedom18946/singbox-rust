# -*- coding: utf-8 -*-
import socket, sys, time
def once(host, port, timeout=2.0):
    req = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    s.connect((host, int(port)))
    s.sendall(req)
    data = b""
    while b"\r\n" not in data and len(data) < 4096:
        chunk = s.recv(1024)
        if not chunk: break
        data += chunk
    s.close()
    line = data.split(b"\r\n", 1)[0] if b"\r\n" in data else data
    return line.decode("ascii","replace")

def main(addr, n):
    host, port = addr.split(":"); n = int(n)
    ok = 0
    for i in range(n):
        try:
            line = once(host, port)
            print(f"[{i+1}] {line}")
            if line.startswith("HTTP/1.1 405"): ok += 1
            time.sleep(0.05)
        except Exception as e:
            print(f"[{i+1}] EXC {e}")
            time.sleep(0.1)
    print(f"[SUMMARY] {ok}/{n} got 405")
    return 0 if ok==n else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
