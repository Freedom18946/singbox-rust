#!/usr/bin/env python3
"""A4.2A read-only historical -> external-observation PROJECTION prototype.

Projects ONE MT-REAL-02 historical round-summary JSON onto a provenance-annotated,
NON-canonical envelope (historical_projection.schema.json). This is a spike: it does
NOT promote anything, it does NOT write into the live observation corpus, it never
contacts the network, and it never mutates its inputs.

Hard rules (A4.2A spec, section "严格禁止的自动补齐"): the projection must NOT
  - write an unknown phase as false,
  - flatten a bi-modal phase into a stable true/false,
  - put a label->phase heuristic result into a canonical phase boolean,
  - invent a matrix_status exit code (e.g. 1 or 124) when none was recorded,
  - pass a date-synthesized midnight off as a real capture instant,
  - pass a git HEAD proxy off as a real config-content fingerprint,
  - report a pre-R82 (absent) subset gate as a real pass,
  - fabricate per-node observations for a pre-R44 round,
  - describe a projection as a dual-kernel parity increment,
  - restore the fresh09 fixed-identity binding.

A field only enters canonical_candidate when its provenance is DIRECT or
DERIVED_DETERMINISTIC. Any DERIVED_HEURISTIC / SYNTHETIC_PLACEHOLDER / MISSING
canonical required field forces PARTIAL (or UNSUPPORTED) and canonical_candidate=null.

stdlib only. Usage:
    python3 adapt_historical_round.py <round-summary.json> [--rollup live_rollup.json] [--out out.json]
"""
import argparse
import hashlib
import json
import os
import re
import sys

# ---- canonical external_observation leaf fields (provenance is reported for each) ----
PHASE_AXES = ("direct_reality", "transport_reality", "vless_dial", "vless_probe_io")
DIVERGENCE_LABELS = ("app_pre_post_diverged", "app_minimal_diverged",
                     "minimal_transport_diverged", "bridge_io_diverged")
# provenance buckets that block promotion
BLOCKING = {"DERIVED_HEURISTIC", "SYNTHETIC_PLACEHOLDER", "MISSING"}

SOURCE_THRESHOLD_NOTE = (
    "recovery closure = 3 consecutive all_ok rounds (golden_spec S4 §F; MT-REAL-02). "
    "No node-liveness numeric SLA; liveness is post-run classification."
)


def parse_round_num(round_str):
    """Leading integer of a round token ('82' -> 82, '59-B' -> 59)."""
    m = re.match(r"\s*(\d+)", str(round_str))
    return int(m.group(1)) if m else None


def detect_epoch(round_obj):
    """Coarse structural era. Round-number primary; total over all ints."""
    n = parse_round_num(round_obj.get("round"))
    if n is None:
        return "R41_R42_NO_RUNS"
    if n <= 42:
        return "R41_R42_NO_RUNS"
    if n <= 76:
        return "R44_R73_RUN_LABELS"
    if n <= 81:
        return "R77_R81_PRE_GATE"
    if n <= 84:
        return "R82_R84_SUBSET_GATE_PHASE_PROBE"
    if n <= 88:
        return "R85_R88_RECOVERY"
    return "R89_R91_MATRIX_STATUS_OBJECT"


def classify_run_health(labels):
    """Mirror the MT-REAL-02 run-health classifier from run labels."""
    labels = labels or []
    if any(l in DIVERGENCE_LABELS for l in labels):
        return "run_divergence"
    if labels == ["all_ok"] or ("all_ok" in labels and not any(
            l.startswith(("reality_all_", "probe_io_all_")) or l in DIVERGENCE_LABELS for l in labels)):
        return "run_all_ok"
    if any(l.startswith(("reality_all_", "probe_io_all_")) for l in labels):
        return "run_same_failure"
    return "run_unknown"


def node_keys(round_obj):
    bo = round_obj.get("by_outbound") or {}
    if bo:
        return list(bo.keys())
    runs = round_obj.get("runs")
    if isinstance(runs, list):
        seen = []
        for r in runs:
            o = (r or {}).get("outbound")
            if o and o not in seen:
                seen.append(o)
        return seen
    return []


def node_run_health_counts(round_obj, node):
    """Prefer recorded run_health_counts; else derive from runs[].labels."""
    bo = (round_obj.get("by_outbound") or {}).get(node) or {}
    rhc = bo.get("run_health_counts")
    if isinstance(rhc, dict) and rhc:
        return {k: rhc.get(k, 0) for k in ("run_all_ok", "run_divergence", "run_same_failure", "run_unknown")}
    counts = {"run_all_ok": 0, "run_divergence": 0, "run_same_failure": 0, "run_unknown": 0}
    for r in round_obj.get("runs") or []:
        if (r or {}).get("outbound") != node:
            continue
        rh = r.get("run_health") or classify_run_health(r.get("labels"))
        counts[rh] = counts.get(rh, 0) + 1
    return counts


def uniform_same_class(round_obj, node):
    """True iff the node's same-failure is uniform AND probe_io class == reality class
    (golden_spec S4 §B infrastructure-dead criterion)."""
    bo = (round_obj.get("by_outbound") or {}).get(node) or {}
    lc = bo.get("label_counts") or {}
    reality = {l.replace("reality_all_", "") for l in lc if l.startswith("reality_all_")}
    probe = {l.replace("probe_io_all_", "") for l in lc if l.startswith("probe_io_all_")}
    if not reality and not probe:
        # fall back to per-run labels
        for r in round_obj.get("runs") or []:
            if (r or {}).get("outbound") != node:
                continue
            for l in r.get("labels") or []:
                if l.startswith("reality_all_"):
                    reality.add(l.replace("reality_all_", ""))
                if l.startswith("probe_io_all_"):
                    probe.add(l.replace("probe_io_all_", ""))
    return bool(reality) and reality == probe and len(reality) == 1


def node_infra_health(counts, round_obj, node):
    if counts["run_unknown"] > 0 and counts["run_all_ok"] == 0 and counts["run_same_failure"] == 0 and counts["run_divergence"] == 0:
        return "unknown"  # matrix_error / matrix_timeout dominated
    if counts["run_all_ok"] > 0:
        return "healthy"
    if counts["run_same_failure"] > 0 and counts["run_divergence"] == 0 and uniform_same_class(round_obj, node):
        return "infrastructure-dead"
    if counts["run_divergence"] > 0:
        return "healthy"  # infra up; divergence is a client anomaly
    return "unknown"


def has_phase_probe(round_obj):
    ppe = round_obj.get("phase_probe_supporting_evidence") or {}
    pr = ppe.get("per_run")
    return bool(pr) and all(ax in (pr[0] or {}) for ax in PHASE_AXES)


def has_recovery_field(round_obj):
    bo = round_obj.get("by_outbound") or {}
    for v in bo.values():
        if isinstance(v, dict) and any("recovery_consecutive_rounds" in k for k in v):
            return True
    # round-level closure blocks
    for k in round_obj:
        if "recovery" in k.lower() or "closure_status" in k.lower():
            return True
    return False


def runs_have_int_matrix_status(round_obj):
    runs = round_obj.get("runs") or []
    if not runs:
        return False
    ints = [r.get("matrix_status") for r in runs if isinstance(r.get("matrix_status"), int)
            and not isinstance(r.get("matrix_status"), bool)]
    return len(ints) == len(runs)


def compute(round_obj, has_rollup):
    """Return (field_provenance dict, warnings list, node_health dict)."""
    prov, warn = {}, []
    pg = round_obj.get("pre_gate") or {}
    ls = round_obj.get("live_scope") or {}
    sm = round_obj.get("summary") or {}
    rhc = sm.get("run_health_counts") or {}
    bo = round_obj.get("by_outbound") or {}
    runs = round_obj.get("runs") if isinstance(round_obj.get("runs"), list) else []
    nodes = node_keys(round_obj)
    node_health = {n: node_run_health_counts(round_obj, n) for n in nodes}
    node_infra = {n: node_infra_health(node_health[n], round_obj, n) for n in nodes}

    # ---- top-level ----
    prov["schema_version"] = "DERIVED_DETERMINISTIC"          # constant 1
    prov["observation_id"] = "DERIVED_DETERMINISTIC"          # stable synthesized id
    prov["round_id"] = "DIRECT" if round_obj.get("round") is not None else "MISSING"
    prov["timestamp"] = "SYNTHETIC_PLACEHOLDER"               # date -> midnight; time-of-day not recorded
    warn.append("synthesized timestamp: source has only a date; T00:00:00Z is fabricated, not a capture instant")
    if pg.get("head_at_gate"):
        prov["config_fingerprint"] = "SYNTHETIC_PLACEHOLDER"  # gitrev proxy only
        warn.append("config_fingerprint is a gitrev proxy (pre_gate.head_at_gate), NOT a config-content hash")
    else:
        prov["config_fingerprint"] = "MISSING"
        warn.append("config_fingerprint missing: no committed config-content hash and no head_at_gate proxy")
    prov["cohort_id"] = "DIRECT" if ls.get("cohort") else "DERIVED_DETERMINISTIC"
    prov["verdict"] = "DERIVED_DETERMINISTIC"
    prov["notes"] = "DERIVED_DETERMINISTIC"

    # ---- run_plan ----
    prov["run_plan.subset_schema_gate_passed"] = "DIRECT" if "subset_schema_gate_passed" in pg else "MISSING"
    if "subset_schema_gate_passed" not in pg:
        warn.append("missing admission gate: subset-schema gate absent (pre-R82); not reported as a real pass")
    prov["run_plan.violations"] = "DIRECT" if isinstance((pg.get("subset_schema_gate") or {}).get("violations"), list) else "MISSING"
    if pg.get("dry_run", {}).get("selected") or ls.get("outbounds"):
        prov["run_plan.planned_node_ids"] = "DIRECT"
    elif nodes:
        prov["run_plan.planned_node_ids"] = "DERIVED_DETERMINISTIC"  # back-filled from observed (vacuous pre-R77)
    else:
        prov["run_plan.planned_node_ids"] = "MISSING"
    prov["run_plan.no_silent_expansion"] = "DERIVED_DETERMINISTIC" if "auto_extended" in ls else "MISSING"

    # ---- intake_counts ----
    ic = pg.get("intake_counts")
    for k in ("fresh_ready", "covered_existing", "duplicate", "not_ready"):
        prov["intake_counts." + k] = "DIRECT" if (isinstance(ic, dict) and k in ic) else "MISSING"
    if not isinstance(ic, dict):
        warn.append("missing admission gate: pre_gate.intake_counts absent (pre-R77)")

    # ---- nodes[] ----
    prov["nodes[].node_id"] = "DIRECT" if nodes else "MISSING"
    if has_phase_probe(round_obj):
        for ax in PHASE_AXES:
            prov["nodes[]." + ax] = "DIRECT"          # phase_probe_supporting_evidence.per_run[].<ax>.ok
    else:
        for ax in PHASE_AXES:
            prov["nodes[]." + ax] = "DERIVED_HEURISTIC"
        warn.append("lossy phase collapse: no per-run phase-probe; canonical phase booleans are NOT "
                    "populated from a label->phase heuristic (kept out of canonical_candidate)")
    prov["nodes[].tcp_reachable"] = "DERIVED_HEURISTIC"
    prov["nodes[].reality_dest_usable"] = "DERIVED_HEURISTIC"
    warn.append("tcp_reachable / reality_dest_usable are not separately observed by the probe tooling "
                "(only inferable from failure class) -> heuristic, never canonical")
    prov["nodes[].infra_health"] = "DERIVED_DETERMINISTIC"
    prov["nodes[].phase_class"] = "DERIVED_DETERMINISTIC"
    prov["nodes[].included_in_client_verdict"] = "DERIVED_DETERMINISTIC"
    prov["nodes[].exclusion_reason"] = "DERIVED_DETERMINISTIC"
    prov["nodes[].replacement_for"] = "DERIVED_DETERMINISTIC"      # determinate null (no rotation recorded)
    prov["nodes[].replacement_reason"] = "DERIVED_DETERMINISTIC"
    prov["nodes[].credential_present"] = "DERIVED_DETERMINISTIC"   # implied by S4 §A admission
    prov["nodes[].config_parse_ok"] = "DERIVED_DETERMINISTIC"
    if any(c["run_all_ok"] > 0 and (c["run_divergence"] + c["run_same_failure"] + c["run_unknown"]) > 0
           for c in node_health.values()):
        warn.append("mixed / bi-modal node behavior: at least one node mixed all_ok with failing runs; "
                    "a single per-node verdict cannot represent it (detail kept in phase_class/notes)")

    # ---- summary ----
    prov["summary.run_all_ok"] = "DERIVED_DETERMINISTIC" if (rhc or runs) else "DERIVED_HEURISTIC"
    prov["summary.run_same_failure"] = "DIRECT" if "run_same_failure" in rhc else ("DERIVED_DETERMINISTIC" if runs else "MISSING")
    prov["summary.run_divergence"] = "DIRECT" if "run_divergence" in rhc else ("DERIVED_DETERMINISTIC" if runs else "MISSING")
    if runs_have_int_matrix_status(round_obj):
        prov["summary.matrix_status"] = "DERIVED_DETERMINISTIC"   # reduce per-run int exit statuses
    else:
        prov["summary.matrix_status"] = "MISSING"
        warn.append("missing matrix exit status: no per-run integer matrix_status; an int code is NOT invented "
                    "from status_counts buckets or the matrix_status object")
    prov["summary.matrix_timeout"] = "DERIVED_DETERMINISTIC"
    prov["summary.healthy_node_count"] = "DERIVED_DETERMINISTIC"
    prov["summary.excluded_infra_dead_count"] = "DERIVED_DETERMINISTIC"
    prov["summary.banked"] = "DERIVED_DETERMINISTIC"
    prov["summary.source_threshold_note"] = "DERIVED_DETERMINISTIC"
    if has_recovery_field(round_obj):
        prov["summary.consecutive_all_ok_rounds"] = "DIRECT"
    elif has_rollup:
        prov["summary.consecutive_all_ok_rounds"] = "DERIVED_DETERMINISTIC"
    else:
        prov["summary.consecutive_all_ok_rounds"] = "MISSING"
        warn.append("missing recovery-chain depth: single-round summary carries no consecutive-all_ok depth and "
                    "no --rollup given; consecutive_all_ok_rounds set 0 and banked forced false")

    return prov, warn, node_infra


def build_source(path, round_obj):
    raw = open(path, "rb").read()
    return {
        "relative_path": os.path.relpath(os.path.abspath(path)),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "round_id": str(round_obj.get("round")),
        "source_date": str(round_obj.get("date")),
        "source_kind": round_obj.get("kind"),
    }


def synth_observation_id(round_obj, sha256):
    return "hist-r{}-{}-{}".format(round_obj.get("round"), round_obj.get("date"), sha256[:8])


def project(path, has_rollup):
    round_obj = json.load(open(path, encoding="utf-8"))
    src = build_source(path, round_obj)
    epoch = detect_epoch(round_obj)
    prov, warn, node_infra = compute(round_obj, has_rollup)

    blockers = sorted(f for f, p in prov.items() if p in BLOCKING)
    no_per_node = not node_keys(round_obj) and not has_phase_probe(round_obj)
    if epoch == "R41_R42_NO_RUNS" or no_per_node:
        status = "UNSUPPORTED"
    elif blockers:
        status = "PARTIAL"
    else:
        status = "PROMOTABLE_CANDIDATE"

    canonical_candidate = None
    if status == "PROMOTABLE_CANDIDATE":
        # Unreachable for the current historical corpus (timestamp/config_fingerprint are always
        # synthetic). Left intentionally null rather than assembled, because building a record here
        # would require emitting the synthetic fields the status check just proved absent.
        canonical_candidate = None

    return {
        "projection_schema_version": 1,
        "record_origin": "historical-projection",
        "source": src,
        "epoch": epoch,
        "projection_status": status,
        "field_provenance": prov,
        "warnings": warn,
        "promotion_blockers": blockers,
        "canonical_candidate": canonical_candidate,
    }


# ---- minimal stdlib self-validation against historical_projection.schema.json ----
def self_validate(projection):
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "historical_projection.schema.json")
    schema = json.load(open(schema_path, encoding="utf-8"))
    errs = []
    for k in schema["required"]:
        if k not in projection:
            errs.append("missing required key: " + k)
    if projection.get("projection_schema_version") != 1:
        errs.append("projection_schema_version must be 1")
    if projection.get("record_origin") != "historical-projection":
        errs.append("record_origin must be 'historical-projection'")
    if projection.get("epoch") not in schema["properties"]["epoch"]["enum"]:
        errs.append("bad epoch: %r" % projection.get("epoch"))
    if projection.get("projection_status") not in schema["properties"]["projection_status"]["enum"]:
        errs.append("bad projection_status")
    prov_enum = set(schema["properties"]["field_provenance"]["additionalProperties"]["enum"])
    for f, p in (projection.get("field_provenance") or {}).items():
        if p not in prov_enum:
            errs.append("bad provenance %r for %s" % (p, f))
    src = projection.get("source") or {}
    if not re.match(r"^[0-9a-f]{64}$", src.get("sha256", "")):
        errs.append("source.sha256 not a 64-hex digest")
    # cross-rule: candidate non-null only when promotable; blockers empty iff promotable
    promotable = projection.get("projection_status") == "PROMOTABLE_CANDIDATE"
    if projection.get("canonical_candidate") is not None and not promotable:
        errs.append("canonical_candidate must be null unless PROMOTABLE_CANDIDATE")
    if bool(projection.get("promotion_blockers")) == promotable:
        errs.append("promotion_blockers must be empty iff PROMOTABLE_CANDIDATE")
    # any blocking provenance must be listed in promotion_blockers
    listed = set(projection.get("promotion_blockers") or [])
    for f, p in (projection.get("field_provenance") or {}).items():
        if p in BLOCKING and f not in listed:
            errs.append("blocking field not in promotion_blockers: " + f)
    return errs


def main():
    ap = argparse.ArgumentParser(description="A4.2A read-only historical -> external-observation projection")
    ap.add_argument("round_summary", help="path to one MT-REAL-02 round-summary JSON (read-only)")
    ap.add_argument("--rollup", help="optional live_rollup.json for cross-round recovery-depth reconstruction")
    ap.add_argument("--out", help="write projection JSON here instead of stdout")
    args = ap.parse_args()

    projection = project(args.round_summary, has_rollup=bool(args.rollup))
    errs = self_validate(projection)
    if errs:
        sys.stderr.write("SELF-VALIDATION FAILED (projection not emitted):\n")
        for e in errs:
            sys.stderr.write("  - " + e + "\n")
        sys.exit(2)

    text = json.dumps(projection, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        sys.stderr.write("wrote %s  [status=%s blockers=%d]\n"
                         % (args.out, projection["projection_status"], len(projection["promotion_blockers"])))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
