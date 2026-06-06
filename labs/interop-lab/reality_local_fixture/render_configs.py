#!/usr/bin/env python3
"""Render every REALITY-fixture kernel config from the SINGLE manifest.

Outputs (to --out-dir):
  go_server.json             Go VLESS+REALITY inbound, handshake.dest -> local tls-dest
  go_server_dead_dest.json   ditto, but handshake.dest -> dead port (negative: dead_dest)
  go_client.json             Go VLESS+REALITY outbound (base64url pubkey, uTLS chrome)
  rust_client.json           Rust app VLESS+REALITY outbound (64-hex pubkey, v2 schema)
  rust_client_bad_pubkey.json wrong (valid-format) public key   (negative: bad_public_key)
  rust_client_bad_uuid.json   wrong uuid, correct keys          (negative: bad_uuid)

NO parameter is duplicated by hand: Go uses base64url, Rust v2_schema requires 64-hex;
both come from the same manifest key and are cross-checked here. The Rust phase-probe
env is NOT rendered here -- run_fixture.py derives it from rust_client*.json via the
existing scripts/tools/reality_vless_env_from_config.py (single source preserved).
"""
import argparse
import base64
import json
import pathlib


def b64url_to_hex(s: str) -> str:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).hex()


def render(m: dict) -> dict[str, dict]:
    x = m["x25519"]
    neg = m["negative"]
    # integrity: the two encodings must be the same key
    if b64url_to_hex(x["public_key_b64"]) != x["public_key_hex"]:
        raise SystemExit("manifest x25519 public_key b64/hex mismatch")
    if b64url_to_hex(neg["bad_public_key_b64"]) != neg["bad_public_key_hex"]:
        raise SystemExit("manifest bad_public_key b64/hex mismatch")

    p = m["ports"]
    sni, uuid, flow, sid, fp = m["sni"], m["uuid"], m["flow"], m["short_id"], m["fingerprint"]
    priv_b64, pub_b64, pub_hex = x["private_key_b64"], x["public_key_b64"], x["public_key_hex"]

    def go_server(dest_port: int) -> dict:
        return {
            "log": {"level": "info", "timestamp": True},
            "inbounds": [{
                "type": "vless", "tag": "vless-reality-in",
                "listen": "127.0.0.1", "listen_port": p["reality_server"],
                "users": [{"name": "fixture", "uuid": uuid, "flow": flow}],
                "tls": {
                    "enabled": True, "server_name": sni,
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": "127.0.0.1", "server_port": dest_port},
                        "private_key": priv_b64, "short_id": [sid],
                    },
                },
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
        }

    def go_client() -> dict:
        return {
            "log": {"level": "error", "timestamp": True},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": p["go_client_socks"]}],
            "outbounds": [
                {
                    "type": "vless", "tag": "vless-reality-out",
                    "server": "127.0.0.1", "server_port": p["reality_server"],
                    "uuid": uuid, "flow": flow,
                    "tls": {
                        "enabled": True, "server_name": sni,
                        "utls": {"enabled": True, "fingerprint": fp},
                        "reality": {"enabled": True, "public_key": pub_b64, "short_id": sid},
                    },
                },
            ],
            # No 'direct' outbound on purpose: with vless-reality-out as the only
            # outbound, a silent fallback is impossible, so a passing end-to-end
            # token proves the request actually traversed REALITY (not a fallback).
            "route": {"final": "vless-reality-out"},
        }

    def rust_client(public_key_hex: str, the_uuid: str) -> dict:
        return {
            "schema_version": 2,
            "inbounds": [{"type": "socks", "listen": "127.0.0.1:%d" % p["rust_client_socks"]}],
            "outbounds": [
                {
                    "type": "vless", "name": "vless-reality-out",
                    "server": "127.0.0.1", "port": p["reality_server"],
                    "uuid": the_uuid, "flow": flow,
                    "tls": {
                        "enabled": True, "sni": sni,
                        "reality": {
                            "enabled": True, "public_key": public_key_hex,
                            "short_id": sid, "server_name": sni,
                        },
                    },
                },
            ],
            # No 'direct' outbound on purpose (see go_client): vless-reality-out is
            # the only route, so a fallback cannot mask a broken REALITY path.
            "route": {"rules": [], "default": "vless-reality-out"},
        }

    return {
        "go_server.json": go_server(p["tls_dest"]),
        "go_server_dead_dest.json": go_server(neg["dead_dest_port"]),
        "go_client.json": go_client(),
        "rust_client.json": rust_client(pub_hex, uuid),
        "rust_client_bad_pubkey.json": rust_client(neg["bad_public_key_hex"], uuid),
        "rust_client_bad_uuid.json": rust_client(pub_hex, neg["bad_uuid"]),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    m = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))
    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, cfg in render(m).items():
        (out / name).write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        print("rendered", out / name)


if __name__ == "__main__":
    main()
