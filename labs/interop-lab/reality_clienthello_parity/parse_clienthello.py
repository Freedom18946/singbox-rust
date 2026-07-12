#!/usr/bin/env python3
"""Sanitizing ClientHello parser for the REALITY ClientHello-parity harness.

Parses one captured ClientHello TLS record into a REDACTED normalized profile + derived
digests. Standard library only. NEVER emits raw auth/key material:
  - ClientHello random        -> "<redacted>"
  - session_id value          -> dropped (length + role "reality-auth-redacted" only)
  - key_share key bytes       -> dropped (group + key_length only)
  - GREASE-ECH payload        -> dropped (payload length only)
  - SNI hostname              -> dropped (name length only)
GREASE values ARE emitted, but ONLY in a clearly-separate `grease_markers` block: they are
public RFC 8701 markers (not secrets) and feed the GREASE-entropy ADVISORY diagnostic. The
digest + field-set parity use GREASE as a CATEGORY, so they stay stable across Chrome's
per-hello GREASE randomization (Go) and the current Rust fixed values alike.

Raises ValueError on a malformed / truncated record.
"""
import hashlib
import json

# RFC 8701 GREASE values (the 16 reserved 0x?a?a points).
GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
RECORD_LEN_BUCKET = 32  # Chrome GREASE-ECH padding ladder spacing

# The from-spec JA4 algorithm is cross-checked against FoxIO's own published reference
# values (fixtures/foxio_reference_vectors/, BSD-3 LICENSE-JA4); see foxio_reference.py
# and tests/test_foxio_reference_vectors.py. The authority is that offline vector test.
FROM_SPEC_JA4_STATUS = "FOXIO_REFERENCE_VERIFIED"

EXT_NAMES = {
    0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
    13: "signature_algorithms", 16: "alpn", 18: "signed_cert_timestamp", 21: "padding",
    23: "extended_master_secret", 27: "compress_certificate", 35: "session_ticket",
    43: "supported_versions", 45: "psk_key_exchange_modes", 51: "key_share",
    17613: "application_settings", 51764: "trust_anchors",
    65037: "ech_outer", 65281: "renegotiation_info",
}


def is_grease(v):
    return v in GREASE


def _u16(b, i):
    if i + 2 > len(b):
        raise ValueError("truncated u16")
    return (b[i] << 8) | b[i + 1]


def _cat(v):
    """Category token: GREASE values collapse to 'GREASE'; else lowercase hex."""
    return "GREASE" if is_grease(v) else f"0x{v:04x}"


def parse_record(raw):
    """Parse one TLS record holding a ClientHello -> redacted normalized dict.
    Raises ValueError on malformed/truncated input."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 5:
        raise ValueError("record too short for a TLS header")
    content_type = raw[0]
    rec_ver = f"{raw[1]:02x}{raw[2]:02x}"
    rec_len = _u16(raw, 3)
    if content_type != 0x16:
        raise ValueError(f"not a handshake record (content_type=0x{content_type:02x})")
    body = raw[5:5 + rec_len]
    if len(body) != rec_len:
        raise ValueError("record body shorter than declared length")
    if len(body) < 4:
        raise ValueError("handshake header truncated")
    hs_type = body[0]
    if hs_type != 0x01:
        raise ValueError(f"not a ClientHello (handshake_type={hs_type})")
    hs_len = (body[1] << 16) | (body[2] << 8) | body[3]
    h = body[4:4 + hs_len]
    if len(h) != hs_len:
        raise ValueError("ClientHello body shorter than declared length")

    p = 0
    legacy_version = f"{h[p]:02x}{h[p+1]:02x}"; p += 2
    p += 32  # random (redacted, never read out)
    sid_len = h[p]; p += 1
    if p + sid_len > len(h):
        raise ValueError("truncated session_id")
    p += sid_len  # session_id value (redacted)
    cs_len = _u16(h, p); p += 2
    if p + cs_len > len(h) or cs_len % 2:
        raise ValueError("bad cipher_suites length")
    ciphers = [_u16(h, p + i) for i in range(0, cs_len, 2)]; p += cs_len
    cm_len = h[p]; p += 1
    compression = list(h[p:p + cm_len]); p += cm_len
    ext_total = _u16(h, p); p += 2
    end = p + ext_total
    if end > len(h):
        raise ValueError("truncated extensions block")
    exts = []
    while p < end:
        et = _u16(h, p); el = _u16(h, p + 2); ed = h[p + 4:p + 4 + el]
        if len(ed) != el:
            raise ValueError("truncated extension data")
        p += 4 + el
        exts.append((et, el, ed))

    grease_markers = {"cipher": [], "extension_types": [], "supported_groups": [],
                      "supported_versions": [], "key_share_groups": []}
    ext_struct = {}
    seen = {}
    for et, el, ed in exts:
        seen[et] = seen.get(et, 0) + 1
        if et == 0x0000:  # SNI — hostname redacted, length only
            try:
                ext_struct["sni"] = {"name_length": _u16(ed, 3)}
            except ValueError:
                ext_struct["sni"] = {"name_length": None}
        elif et == 0x000a:  # supported_groups
            n = _u16(ed, 0); gs = [_u16(ed, 2 + j) for j in range(0, n, 2)]
            ext_struct["supported_groups"] = [_cat(x) for x in gs]
            grease_markers["supported_groups"] = [f"0x{x:04x}" for x in gs if is_grease(x)]
        elif et == 0x000d:  # signature_algorithms (ORDER preserved)
            n = _u16(ed, 0); ext_struct["signature_algorithms"] = [f"0x{_u16(ed,2+j):04x}" for j in range(0, n, 2)]
        elif et == 0x0010:  # ALPN (order preserved)
            alpn = []; ll = _u16(ed, 0); q = 2
            while q < 2 + ll:
                pl = ed[q]; alpn.append(ed[q + 1:q + 1 + pl].decode("latin1")); q += 1 + pl
            ext_struct["alpn"] = alpn
        elif et == 0x002b:  # supported_versions
            ll = ed[0]; vs = [_u16(ed, 1 + j) for j in range(0, ll, 2)]
            ext_struct["supported_versions"] = [_cat(x) for x in vs]
            grease_markers["supported_versions"] = [f"0x{x:04x}" for x in vs if is_grease(x)]
        elif et == 0x0033:  # key_share — key bytes redacted, group+length only
            ks = []; ll = _u16(ed, 0); q = 2
            while q < 2 + ll:
                gid = _u16(ed, q); kl = _u16(ed, q + 2); q += 4 + kl
                ks.append({"group": _cat(gid), "key_length": kl})
                if is_grease(gid):
                    grease_markers["key_share_groups"].append(f"0x{gid:04x}")
            ext_struct["key_share"] = ks
        elif et == 0xca34:  # trust_anchors: Chrome 150 currently sends empty vector
            ext_struct["trust_anchors"] = {
                "list_length": _u16(ed, 0), "payload_length": el,
            }
        elif et == 0x0015:  # padding
            ext_struct["padding_length"] = el
        elif et == 0xfe0d:  # GREASE-ECH — payload redacted, length only
            ext_struct["grease_ech_payload_length"] = el
    for et, _, _ in exts:
        if is_grease(et):
            grease_markers["extension_types"].append(f"0x{et:04x}")
    grease_markers["cipher"] = [f"0x{c:04x}" for c in ciphers if is_grease(c)]
    duplicate_extension_types = [f"0x{t:04x}" for t, c in seen.items() if c > 1]

    cipher_tail = [f"0x{c:04x}" for c in ciphers if not is_grease(c)]
    ext_categories = [("GREASE" if is_grease(t) else EXT_NAMES.get(t, f"0x{t:04x}")) for t, _, _ in exts]
    ext_set = sorted(c for c in ext_categories if c != "GREASE")

    # normalized_profile: ONLY stable structural fields; GREASE as category; NO per-hello
    # volatile fields (record_len / ext order / GREASE-ECH payload). This is what the digest
    # + field-set parity use, so it is constant within a kernel and identical Go-vs-Rust.
    normalized_profile = {
        "legacy_version": legacy_version,
        "session_id": {"length": sid_len, "role": "reality-auth-redacted"},
        "cipher_tail_no_grease": cipher_tail,
        "cipher_grease_slot_positions": [i for i, c in enumerate(ciphers) if is_grease(c)],
        "compression_methods": compression,
        "supported_groups": ext_struct.get("supported_groups"),
        "signature_algorithms_in_order": ext_struct.get("signature_algorithms"),
        "supported_versions": ext_struct.get("supported_versions"),
        "alpn": ext_struct.get("alpn"),
        "key_share_groups": ext_struct.get("key_share"),
        "trust_anchors": ext_struct.get("trust_anchors"),
        "extension_set_sorted_grease_as_category": ext_set,
        "sni_name_length": (ext_struct.get("sni") or {}).get("name_length"),
    }
    derived = {
        "normalized_profile_digest": _digest(normalized_profile),
        "required_field_shape": _required_shape(normalized_profile),
    }
    ja4 = _from_spec_ja4(legacy_version, ciphers, exts, ext_struct)
    derived.update(ja4)

    return {
        "record": {"content_type": content_type, "legacy_version": rec_ver, "record_length": len(raw)},
        "client_hello": {
            "handshake_type": hs_type, "client_hello_length": hs_len, "legacy_version": legacy_version,
            "random": "<redacted>",
            "session_id": {"length": sid_len, "role": "reality-auth-redacted"},
            "cipher_suites": {"ordered_tail_no_grease": cipher_tail,
                              "grease_slot_positions": [i for i, c in enumerate(ciphers) if is_grease(c)],
                              "grease_in_rfc8701": all(is_grease(c) for c in ciphers if is_grease(c))},
            "compression_methods": compression,
        },
        "extensions": {
            "ordered_categories": ext_categories,
            "set_sorted": ext_set,
            "lengths_by_category": {("GREASE@%d" % i if is_grease(t) else EXT_NAMES.get(t, f"0x{t:04x}")): el
                                    for i, (t, el, _) in enumerate(exts)},
            "grease_slot_positions": [i for i, (t, _, _) in enumerate(exts) if is_grease(t)],
            "sni_name_length": (ext_struct.get("sni") or {}).get("name_length"),
            "alpn": ext_struct.get("alpn"),
            "supported_versions": ext_struct.get("supported_versions"),
            "supported_groups": ext_struct.get("supported_groups"),
            "signature_algorithms": ext_struct.get("signature_algorithms"),
            "key_share": ext_struct.get("key_share"),
            "trust_anchors": ext_struct.get("trust_anchors"),
            "grease_ech_payload_length": ext_struct.get("grease_ech_payload_length"),
            "padding_length": ext_struct.get("padding_length"),
            "duplicate_extension_types": duplicate_extension_types,
        },
        "normalized_profile": normalized_profile,
        "grease_markers": {"_note": "public RFC 8701 markers (not secrets); advisory entropy only; "
                                    "NOT part of the digest or field-set parity", **grease_markers},
        "derived": derived,
    }


def _digest(normalized_profile):
    return hashlib.sha256(json.dumps(normalized_profile, sort_keys=True).encode()).hexdigest()[:16]


def _required_shape(np):
    return {
        "cipher_tail_no_grease": np["cipher_tail_no_grease"],
        "supported_groups": np["supported_groups"],
        "signature_algorithms_in_order": np["signature_algorithms_in_order"],
        "supported_versions": np["supported_versions"],
        "alpn": np["alpn"],
        "key_share_groups": np["key_share_groups"],
        "trust_anchors": np["trust_anchors"],
        "extension_set_sorted_grease_as_category": np["extension_set_sorted_grease_as_category"],
        "compression_methods": np["compression_methods"],
        "session_id_length": np["session_id"]["length"],
        "session_id_role": np["session_id"]["role"],
    }


# FoxIO version code points (highest non-GREASE supported_versions, else legacy version).
_JA4_VERSION_MAP = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
                    0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}


def _tls_ver_2c(ext_struct, legacy_version):
    sv = ext_struct.get("supported_versions") or []
    best = None
    for v in sv:
        if v == "GREASE":
            continue
        n = int(v, 16); best = max(best, n) if best else n
    if best is None:
        best = int(legacy_version, 16)
    return _JA4_VERSION_MAP.get(best, "00")


def _ja4_alpn_segment(first_alpn):
    """FoxIO JA4 ALPN `a`-segment for the first ALPN value (`first_alpn` is a latin1 str,
    each char's ord == the original byte; "" when no ALPN). Rule: first+last char if both
    end bytes are ASCII-alphanumeric; otherwise hex(first_byte)[0] + hex(last_byte)[1]."""
    if not first_alpn:
        return "00"
    fb = ord(first_alpn[0]); lb = ord(first_alpn[-1])
    alnum = lambda x: 0x30 <= x <= 0x39 or 0x41 <= x <= 0x5a or 0x61 <= x <= 0x7a  # noqa: E731
    if alnum(fb) and alnum(lb):
        return chr(fb) + chr(lb)
    return f"{fb:02x}"[0] + f"{lb:02x}"[1]


def _compute_from_spec_ja4(transport, ver2c, sni_flag, ciphers_ng, exts_ng, sig_algs, first_alpn):
    """Core FoxIO JA4 (hashed+sorted) computation from GREASE-filtered int-list fields.
    Single source of truth shared by the byte parser and the reference-vector cross-check."""
    al = _ja4_alpn_segment(first_alpn)
    ja4_a = f"{transport}{ver2c}{sni_flag}{min(len(ciphers_ng),99):02d}{min(len(exts_ng),99):02d}{al}"
    ja4_b = (hashlib.sha256(",".join(f"{c:04x}" for c in sorted(ciphers_ng)).encode()).hexdigest()[:12]
             if ciphers_ng else "000000000000")
    exts_c = sorted(e for e in exts_ng if e not in (0x0000, 0x0010))
    if not exts_c:
        ja4_c = "000000000000"
    else:
        c_str = ",".join(f"{e:04x}" for e in exts_c)
        if sig_algs:  # FoxIO: string ends without underscore when there are no sig algs
            c_str += "_" + ",".join(f"{s:04x}" for s in sig_algs)
        ja4_c = hashlib.sha256(c_str.encode()).hexdigest()[:12]
    return {"from_spec_ja4": f"{ja4_a}_{ja4_b}_{ja4_c}",
            "from_spec_ja4_a": ja4_a, "from_spec_ja4_b": ja4_b, "from_spec_ja4_c": ja4_c,
            "from_spec_ja4_status": FROM_SPEC_JA4_STATUS}


def _from_spec_ja4(legacy_version, ciphers, exts, ext_struct):
    """FoxIO JA4 TLS-client algorithm computed from a parsed ClientHello. The algorithm is
    cross-checked against FoxIO's own published reference vectors (see FROM_SPEC_JA4_STATUS)."""
    cs = [c for c in ciphers if not is_grease(c)]
    exts_ng = [t for t, _, _ in exts if not is_grease(t)]
    sig = [int(s, 16) for s in ext_struct.get("signature_algorithms", [])]
    alpn = ext_struct.get("alpn") or []
    ver = _tls_ver_2c(ext_struct, legacy_version)
    sni_flag = "d" if "sni" in ext_struct else "i"
    first_alpn = alpn[0] if alpn else ""
    return _compute_from_spec_ja4("t", ver, sni_flag, cs, exts_ng, sig, first_alpn)


def from_spec_ja4_from_fields(*, transport="t", tls_version_2c, sni_present,
                              cipher_list, ext_type_list, sig_alg_list, first_alpn=""):
    """Field-driven entry for the FoxIO reference-vector cross-check. Takes already-decoded
    hex-string lists (4-char lower hex) plus a latin1 `first_alpn` str, and runs the SAME
    core computation as the live byte parser. GREASE values are filtered defensively."""
    cs = [int(c, 16) for c in cipher_list if not is_grease(int(c, 16))]
    exts_ng = [int(e, 16) for e in ext_type_list if not is_grease(int(e, 16))]
    sig = [int(s, 16) for s in sig_alg_list]
    sni_flag = "d" if sni_present else "i"
    return _compute_from_spec_ja4(transport, tls_version_2c, sni_flag, cs, exts_ng, sig, first_alpn)


if __name__ == "__main__":
    import sys
    print(json.dumps(parse_record(open(sys.argv[1], "rb").read()), indent=2))
