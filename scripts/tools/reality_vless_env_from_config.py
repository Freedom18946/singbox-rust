#!/usr/bin/env python3
"""Extract VLESS REALITY phase-probe environment from an app config."""

import argparse
import json
import pathlib
import shlex
import sys
from typing import Any


def load_config(path: pathlib.Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on local env
            raise SystemExit("YAML config requires PyYAML; pass JSON or install PyYAML") from exc
        loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise SystemExit("config root must be an object")
    return loaded


def parse_target(target: str) -> tuple[str, int]:
    if ":" not in target:
        raise SystemExit(f"invalid target host:port: {target}")
    host, port = target.rsplit(":", 1)
    if not host:
        raise SystemExit(f"invalid target host:port: {target}")
    try:
        parsed_port = int(port)
    except ValueError as exc:
        raise SystemExit(f"invalid target port: {target}") from exc
    if parsed_port <= 0 or parsed_port > 65535:
        raise SystemExit(f"target port out of range: {target}")
    return host, parsed_port


def outbound_name(outbound: dict[str, Any]) -> str | None:
    value = outbound.get("tag", outbound.get("name"))
    return value if isinstance(value, str) else None


def find_outbound(config: dict[str, Any], name: str) -> dict[str, Any]:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise SystemExit("config has no outbounds list")
    for outbound in outbounds:
        if isinstance(outbound, dict) and outbound_name(outbound) == name:
            return outbound
    raise SystemExit(f"outbound not found: {name}")


def string_value(value: Any, field: str) -> str:
    if isinstance(value, str) and value:
        return value
    raise SystemExit(f"missing or invalid {field}")


def optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def port_value(outbound: dict[str, Any]) -> int:
    value = outbound.get("server_port", outbound.get("port"))
    if not isinstance(value, int) or value <= 0 or value > 65535:
        raise SystemExit("missing or invalid server port")
    return value


def tls_object(outbound: dict[str, Any]) -> dict[str, Any]:
    tls = outbound.get("tls")
    return tls if isinstance(tls, dict) else {}


def reality_object(outbound: dict[str, Any], tls: dict[str, Any]) -> dict[str, Any]:
    reality = tls.get("reality")
    if isinstance(reality, dict):
        return reality
    return {}


def utls_object(tls: dict[str, Any]) -> dict[str, Any]:
    utls = tls.get("utls")
    return utls if isinstance(utls, dict) else {}


def normalize_alpn(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.split(",")
    elif isinstance(value, list):
        parts = value
    else:
        raise SystemExit("invalid TLS ALPN value")
    output = []
    for part in parts:
        if not isinstance(part, str):
            raise SystemExit("invalid TLS ALPN item")
        stripped = part.strip()
        if stripped:
            output.append(stripped)
    return output


def extract_env(
    config: dict[str, Any],
    outbound_name_value: str,
    target: str,
    phase_timeout_ms: int | None,
    probe_io_timeout_ms: int | None,
) -> dict[str, str]:
    outbound = find_outbound(config, outbound_name_value)
    if outbound.get("type") != "vless":
        raise SystemExit(f"outbound is not vless: {outbound_name_value}")
    transport = outbound.get("transport")
    if isinstance(transport, list) and transport:
        raise SystemExit("minimal phase probe only supports plain TCP VLESS outbounds")
    if isinstance(transport, dict) and transport.get("type") not in (None, "tcp"):
        raise SystemExit("minimal phase probe only supports plain TCP VLESS outbounds")

    tls = tls_object(outbound)
    reality = reality_object(outbound, tls)
    utls = utls_object(tls)
    target_host, target_port = parse_target(target)

    server = string_value(outbound.get("server"), "server")
    server_name = (
        optional_string(reality.get("server_name"))
        or optional_string(tls.get("server_name"))
        or optional_string(outbound.get("reality_server_name"))
        or optional_string(outbound.get("tls_sni"))
        or server
    )
    public_key = (
        optional_string(reality.get("public_key"))
        or optional_string(outbound.get("reality_public_key"))
    )
    if not public_key:
        raise SystemExit("missing REALITY public key")
    short_id = (
        optional_string(reality.get("short_id"))
        or optional_string(outbound.get("reality_short_id"))
        or ""
    )
    fingerprint = (
        optional_string(utls.get("fingerprint"))
        or optional_string(outbound.get("utls_fingerprint"))
        or "chrome"
    )
    alpn = normalize_alpn(tls.get("alpn", outbound.get("tls_alpn")))

    env = {
        "SB_VLESS_SERVER": server,
        "SB_VLESS_PORT": str(port_value(outbound)),
        "SB_VLESS_SERVER_NAME": server_name,
        "SB_VLESS_REALITY_PUBLIC_KEY": public_key,
        "SB_VLESS_REALITY_SHORT_ID": short_id,
        "SB_VLESS_FINGERPRINT": fingerprint,
        "SB_VLESS_UUID": string_value(outbound.get("uuid"), "uuid"),
        "SB_VLESS_TARGET_HOST": target_host,
        "SB_VLESS_TARGET_PORT": str(target_port),
        "SB_VLESS_ALPN": ",".join(alpn),
    }
    if phase_timeout_ms is not None:
        env["SB_VLESS_PHASE_TIMEOUT_MS"] = str(phase_timeout_ms)
    if probe_io_timeout_ms is not None:
        env["SB_VLESS_PROBE_IO_TIMEOUT_MS"] = str(probe_io_timeout_ms)
    return env


def print_env(env: dict[str, str]) -> None:
    for key in sorted(env):
        print(f"export {key}={shlex.quote(env[key])}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--outbound", required=True)
    parser.add_argument("--target", default="example.com:80")
    parser.add_argument("--phase-timeout-ms", type=int)
    parser.add_argument("--probe-io-timeout-ms", type=int)
    parser.add_argument("--format", choices=("json", "env"), default="json")
    args = parser.parse_args()

    env = extract_env(
        load_config(pathlib.Path(args.config)),
        args.outbound,
        args.target,
        args.phase_timeout_ms,
        args.probe_io_timeout_ms,
    )
    if args.format == "env":
        print_env(env)
    else:
        json.dump(env, sys.stdout, indent=2, ensure_ascii=True)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
