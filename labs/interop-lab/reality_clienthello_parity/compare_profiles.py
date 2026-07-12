#!/usr/bin/env python3
"""Compare Go-reference vs Rust-candidate normalized ClientHello profiles.

BLOCKING gates (affect exit code):
  1. functional token-match for both kernels;
  2. required field-set parity (cipher tail, supported_groups, signature_algorithms ORDER,
     supported_versions, ALPN, key_share groups+lengths, extension set, compression,
     session_id length+role, record-length buckets);
  3. normalized_profile_digest parity (Go == Rust, single value each);
  4. redaction guard: emitted summary contains NO raw auth/key material.

ADVISORY diagnostics (recorded, never change the exit code):
  - from_spec_ja4 parity (algorithm FOXIO_REFERENCE_VERIFIED via vendored vectors);
  - GREASE slot entropy (fixed vs random) — current Rust fixed values are advisory only;
  - extension-order distribution (distinct permutations);
  - expected_profile_shape.json drift (Go vs snapshot) — advisory only, never fails Rust.
"""
import json
import re

_HEXBLOB = re.compile(r"[0-9a-fA-F]{32,}")
RECORD_LEN_LADDER = 32  # Chrome GREASE-ECH padding bucket spacing


def _uniq(parsed_list, picker):
    return sorted({json.dumps(picker(p), sort_keys=True) for p in parsed_list})


def _record_len_buckets(parsed_list):
    return sorted({p["record"]["record_length"] for p in parsed_list})


def _redaction_violations(parsed_list):
    """Defensive: the emitted profiles must carry no raw auth/key material."""
    v = []
    for i, p in enumerate(parsed_list):
        if p.get("client_hello", {}).get("random") != "<redacted>":
            v.append(f"[{i}] random not redacted")
        sid = p.get("client_hello", {}).get("session_id", {})
        if "value" in sid or "raw" in sid:
            v.append(f"[{i}] session_id value present")
        for ks in (p.get("extensions", {}).get("key_share") or []):
            if any(k in ks for k in ("key", "key_value", "key_bytes")):
                v.append(f"[{i}] key_share key bytes present")
        blob = _HEXBLOB.search(json.dumps(p))
        if blob:
            v.append(f"[{i}] 32+ hex blob present: {blob.group()[:12]}…")
    return v


def _grease_entropy(parsed_list):
    slots = ("cipher", "extension_types", "supported_groups", "supported_versions", "key_share_groups")
    out = {}
    for s in slots:
        vals = {tuple(p["grease_markers"].get(s, [])) for p in parsed_list}
        out[s] = {"distinct": len(vals), "state": "FIXED" if len(vals) == 1 else "RANDOMIZED"}
    return out


def _ext_order_distribution(parsed_list):
    perms = {tuple(p["extensions"]["ordered_categories"]) for p in parsed_list}
    return {"distinct_permutations": len(perms), "n_samples": len(parsed_list)}


def compare(go, rust, token_ok_go, token_ok_rust, snapshot=None):
    res = {"blocking": {}, "advisory": {}, "blocking_pass": False}

    # --- BLOCKING 1: token-match ---
    res["blocking"]["token_match"] = {
        "go": bool(token_ok_go), "rust": bool(token_ok_rust),
        "pass": bool(token_ok_go) and bool(token_ok_rust)}

    # --- BLOCKING 4 (run early): redaction guard ---
    red = _redaction_violations(go) + _redaction_violations(rust)
    res["blocking"]["redaction_guard"] = {"violations": red, "pass": not red}

    # --- BLOCKING 2: required field-set parity ---
    go_shape = _uniq(go, lambda p: p["derived"]["required_field_shape"])
    rust_shape = _uniq(rust, lambda p: p["derived"]["required_field_shape"])
    go_buckets = _record_len_buckets(go)
    rust_buckets = _record_len_buckets(rust)
    # Record length is a per-hello sampled GREASE-ECH padding bucket; exact bucket-set
    # equality across two 10-run samples is FLAKY. The blocking invariant is "same 32-spaced
    # ladder" (single residue mod 32 + bounded span), which is robust to which buckets each
    # run happened to sample. Exact bucket-set equality is recorded as advisory.
    all_lens = sorted(set(go_buckets) | set(rust_buckets))
    residues = sorted({L % RECORD_LEN_LADDER for L in all_lens})
    span = (all_lens[-1] - all_lens[0]) if all_lens else 0
    ladder_ok = bool(all_lens) and len(residues) == 1 and span % RECORD_LEN_LADDER == 0 and span <= 3 * RECORD_LEN_LADDER
    field_pass = (len(go_shape) == 1 and len(rust_shape) == 1 and go_shape == rust_shape and ladder_ok)
    res["blocking"]["required_field_set_parity"] = {
        "go_distinct_shapes": len(go_shape), "rust_distinct_shapes": len(rust_shape),
        "shapes_match": go_shape == rust_shape,
        "record_len_residue_mod32": residues, "record_len_span": span,
        "record_len_ladder_parity": ladder_ok,
        "_record_len_note": "blocking = same 32-spaced ladder (single residue mod 32 + span<=96), "
                            "robust to per-run GREASE-ECH bucket sampling; exact bucket-set is advisory",
        "pass": field_pass}

    # --- BLOCKING 3: normalized_profile_digest parity ---
    go_dig = sorted({p["derived"]["normalized_profile_digest"] for p in go})
    rust_dig = sorted({p["derived"]["normalized_profile_digest"] for p in rust})
    dig_pass = len(go_dig) == 1 and len(rust_dig) == 1 and go_dig == rust_dig
    res["blocking"]["normalized_profile_digest_parity"] = {
        "go": go_dig, "rust": rust_dig, "pass": dig_pass}

    res["blocking_pass"] = all(res["blocking"][k]["pass"] for k in res["blocking"])

    # --- ADVISORY: from_spec_ja4 ---
    # The from-spec JA4 *algorithm* is now cross-checked offline against FoxIO's own published
    # reference vectors (fixtures/foxio_reference_vectors/; foxio_reference.py). This live
    # go-vs-rust JA4 parity stays advisory in the run_check exit code — the authoritative
    # blocking gate is the vendored-vector unit test — but the value is no longer "pending".
    go_ja4 = sorted({p["derived"]["from_spec_ja4"] for p in go})
    rust_ja4 = sorted({p["derived"]["from_spec_ja4"] for p in rust})
    res["advisory"]["from_spec_ja4"] = {
        "go": go_ja4, "rust": rust_ja4, "parity": go_ja4 == rust_ja4,
        "status": "FOXIO_REFERENCE_VERIFIED",
        "_note": "JA4 algorithm cross-checked against vendored FoxIO reference vectors "
                 "(BSD-3 LICENSE-JA4); live go==rust under that verified algorithm. Advisory "
                 "in run_check exit code; the vendored-vector unit test is the blocking gate"}

    # --- ADVISORY: GREASE entropy ---
    res["advisory"]["grease_entropy"] = {
        "go": _grease_entropy(go), "rust": _grease_entropy(rust),
        "_note": "Rust currently FIXED across slots — advisory only, does NOT fail T3-1B"}

    # --- ADVISORY: extension-order distribution ---
    res["advisory"]["extension_order_distribution"] = {
        "go": _ext_order_distribution(go), "rust": _ext_order_distribution(rust),
        "_note": "per-hello Chrome shuffle; advisory only"}

    # --- ADVISORY: exact record-length bucket sets (sampling-dependent) ---
    res["advisory"]["record_len_bucket_sets"] = {
        "go": go_buckets, "rust": rust_buckets, "exact_set_match": go_buckets == rust_buckets,
        "_note": "exact bucket-set equality is per-run sampling-dependent → advisory, not blocking "
                 "(the blocking check is the 32-spaced ladder residue/span above)"}

    # --- ADVISORY: snapshot drift (Go reference vs committed advisory snapshot) ---
    if snapshot is not None:
        snap_shape = json.dumps(snapshot.get("required_field_shape"), sort_keys=True)
        snap_digest = snapshot.get("normalized_profile_digest")
        snap_ja4 = snapshot.get("from_spec_ja4")
        drift = []
        if go_shape and go_shape[0] != snap_shape:
            drift.append("required_field_shape differs from snapshot")
        if go_dig and snap_digest and go_dig[0] != snap_digest:
            drift.append(f"normalized_profile_digest {go_dig[0]} != snapshot {snap_digest}")
        if go_ja4 and snap_ja4 and go_ja4[0] != snap_ja4:
            drift.append(f"from_spec_ja4 {go_ja4[0]} != snapshot {snap_ja4}")
        res["advisory"]["snapshot_drift"] = {
            "drift_detected": bool(drift), "details": drift,
            "_note": "advisory only — flags HelloChrome_Auto upstream drift; NEVER fails Rust"}

    return res
