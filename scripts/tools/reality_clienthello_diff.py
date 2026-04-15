#!/usr/bin/env python3
import argparse
import json
import sys


def is_grease(value: int) -> bool:
    return ((value >> 8) == (value & 0xFF)) and ((value & 0x0F) == 0x0A)


def norm_u8_list(values):
    return [f"0x{value:02x}" for value in values]


def norm_u16(value: int) -> str:
    return "GREASE" if is_grease(value) else f"0x{value:04x}"


def read_u8(data: bytes, offset: int):
    return data[offset], offset + 1


def read_u16(data: bytes, offset: int):
    return int.from_bytes(data[offset:offset + 2], "big"), offset + 2


def read_u24(data: bytes, offset: int):
    return int.from_bytes(data[offset:offset + 3], "big"), offset + 3


def parse_u16_list(data: bytes, prefix_len: int):
    if len(data) < prefix_len:
        return []
    size = int.from_bytes(data[:prefix_len], "big")
    body = data[prefix_len:prefix_len + size]
    return [norm_u16(int.from_bytes(body[i:i + 2], "big")) for i in range(0, len(body), 2)]


def parse_key_share(data: bytes):
    if len(data) < 2:
        return []
    total = int.from_bytes(data[:2], "big")
    body = data[2:2 + total]
    items = []
    offset = 0
    while offset + 4 <= len(body):
        group = int.from_bytes(body[offset:offset + 2], "big")
        key_len = int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        key = body[offset:offset + key_len]
        offset += key_len
        items.append({"group": norm_u16(group), "len": len(key)})
    return items


def parse_alpn(data: bytes):
    if len(data) < 2:
        return []
    total = int.from_bytes(data[:2], "big")
    body = data[2:2 + total]
    items = []
    offset = 0
    while offset < len(body):
        size = body[offset]
        offset += 1
        items.append(body[offset:offset + size].decode("ascii", errors="replace"))
        offset += size
    return items


def parse_server_name(data: bytes):
    if len(data) < 5:
        return []
    total = int.from_bytes(data[:2], "big")
    body = data[2:2 + total]
    items = []
    offset = 0
    while offset + 3 <= len(body):
        name_type = body[offset]
        name_len = int.from_bytes(body[offset + 1:offset + 3], "big")
        offset += 3
        name = body[offset:offset + name_len].decode("ascii", errors="replace")
        offset += name_len
        items.append({"type": name_type, "name": name})
    return items


def summarize_extension(ext_type: int, ext_data: bytes):
    summary = {
        "type": norm_u16(ext_type),
        "len": len(ext_data),
    }
    if ext_type == 0x0000:
        summary["server_names"] = parse_server_name(ext_data)
    elif ext_type == 0x000A:
        summary["supported_groups"] = parse_u16_list(ext_data, 2)
    elif ext_type == 0x000B:
        summary["ec_point_formats"] = norm_u8_list(ext_data[1:1 + ext_data[0]]) if ext_data else []
    elif ext_type == 0x000D:
        summary["signature_algorithms"] = parse_u16_list(ext_data, 2)
    elif ext_type == 0x0010:
        summary["alpn"] = parse_alpn(ext_data)
    elif ext_type == 0x002B:
        summary["supported_versions"] = parse_u16_list(ext_data, 1)
    elif ext_type == 0x0033:
        summary["key_share"] = parse_key_share(ext_data)
    elif ext_type == 0x0015:
        summary["padding_len"] = len(ext_data)
    return summary


def summarize_record(wire: bytes):
    if len(wire) < 5:
        raise ValueError("TLS record too short")
    record_type = wire[0]
    record_version = int.from_bytes(wire[1:3], "big")
    record_len = int.from_bytes(wire[3:5], "big")
    body = wire[5:5 + record_len]
    offset = 0
    hs_type, offset = read_u8(body, offset)
    hs_len, offset = read_u24(body, offset)
    client_version, offset = read_u16(body, offset)
    random = body[offset:offset + 32]
    offset += 32
    sid_len, offset = read_u8(body, offset)
    session_id = body[offset:offset + sid_len]
    offset += sid_len
    cipher_len, offset = read_u16(body, offset)
    cipher_suites = [
        norm_u16(int.from_bytes(body[i:i + 2], "big"))
        for i in range(offset, offset + cipher_len, 2)
    ]
    offset += cipher_len
    comp_len, offset = read_u8(body, offset)
    compression_methods = norm_u8_list(list(body[offset:offset + comp_len]))
    offset += comp_len
    ext_total, offset = read_u16(body, offset)
    ext_end = offset + ext_total
    extensions = []
    extension_order = []
    while offset + 4 <= ext_end:
        ext_type, offset = read_u16(body, offset)
        ext_len, offset = read_u16(body, offset)
        ext_data = body[offset:offset + ext_len]
        offset += ext_len
        extensions.append(summarize_extension(ext_type, ext_data))
        extension_order.append(norm_u16(ext_type))

    return {
        "record_type": f"0x{record_type:02x}",
        "record_version": f"0x{record_version:04x}",
        "record_len": record_len,
        "handshake_type": f"0x{hs_type:02x}",
        "handshake_len": hs_len,
        "client_version": f"0x{client_version:04x}",
        "random_len": len(random),
        "session_id_len": len(session_id),
        "cipher_suites": cipher_suites,
        "compression_methods": compression_methods,
        "extensions_order": extension_order,
        "extensions": extensions,
    }


def load_hex(path: str) -> bytes:
    with open(path, "r", encoding="utf-8") as handle:
        hex_data = "".join(handle.read().split())
    return bytes.fromhex(hex_data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-hex-file", required=True)
    parser.add_argument("--rust-hex-file", required=True)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    go_summary = summarize_record(load_hex(args.go_hex_file))
    rust_summary = summarize_record(load_hex(args.rust_hex_file))

    output = {
        "go": go_summary,
        "rust": rust_summary,
        "match": go_summary == rust_summary,
    }
    json.dump(output, sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")

    if args.strict and go_summary != rust_summary:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
