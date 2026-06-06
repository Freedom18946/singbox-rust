#!/usr/bin/env python3
"""Read-only validator for REALITY External Healthy-Cohort Observation records.

Structures + checks one pre-release real-network observation round per the
External Healthy-Cohort Observation Protocol in
labs/interop-lab/docs/dual_kernel_golden_spec.md S4 (sections A-F). This tier is
OBSERVATIONAL and never a merge gate; no public node identity is mandatory.

stdlib-only (no jsonschema / no pip deps). external_observation.schema.json is the
structural spec; this script is authoritative for the cross-field semantics that
draft-07 cannot express. NO thresholds are invented here — the only numeric rule
is the MT-REAL-02 recovery closure depth (3 consecutive all_ok rounds), extracted
from golden_spec S4 section F; its provenance is stated in the README.

Usage:
    python3 validate_external_observation.py <record.json>
Exit 0 on a valid record (prints a summary); non-zero on any violation (prints
reviewer-readable diagnostics). Never modifies the input file.
"""
import json
import pathlib
import sys

# MT-REAL-02 recovery-watch closure depth (golden_spec S4 §F: "recovery closure =
# 3 consecutive all_ok rounds"). Extracted, not invented.
RECOVERY_CLOSURE_ROUNDS = 3

VERDICTS = ("PASS", "DEGRADED", "INCONCLUSIVE")
INFRA_HEALTH = ("healthy", "infrastructure-dead", "unknown")


class Errors:
    def __init__(self):
        self.items = []

    def add(self, path, rule, actual, fix):
        self.items.append({"path": path, "rule": rule, "actual": actual, "fix": fix})

    def ok(self):
        return not self.items


def _req(obj, key, path, typ, errs):
    """Require obj[key] present and of python type `typ`; return value or None."""
    if not isinstance(obj, dict) or key not in obj:
        errs.add(f"{path}.{key}", "required field missing", "absent",
                 f"add `{key}`")
        return None
    val = obj[key]
    if typ is not None and not isinstance(val, typ) or (typ is int and isinstance(val, bool)):
        # bool is a subclass of int in python; reject bool where int expected
        errs.add(f"{path}.{key}", f"must be {getattr(typ, '__name__', typ)}",
                 repr(val), f"set `{key}` to a {getattr(typ, '__name__', typ)}")
        return None
    return val


def _nonempty_str(v):
    return isinstance(v, str) and v.strip() != ""


def validate_structure(rec, errs):
    if not isinstance(rec, dict):
        errs.add("$", "root must be an object", type(rec).__name__, "wrap in {}")
        return
    if rec.get("schema_version") != 1:
        errs.add("$.schema_version", "must equal 1", repr(rec.get("schema_version")),
                 "set schema_version: 1")
    for k in ("observation_id", "cohort_id", "round_id", "timestamp", "config_fingerprint", "notes"):
        v = rec.get(k, None)
        if k == "notes":
            if not isinstance(v, str):
                errs.add(f"$.{k}", "must be a string", repr(v), f"set `{k}`")
        elif not _nonempty_str(v):
            errs.add(f"$.{k}", "required non-empty string", repr(v), f"set `{k}`")
    if "verdict" not in rec:
        errs.add("$.verdict", "required field missing", "absent",
                 "add verdict: PASS / DEGRADED / INCONCLUSIVE")
    elif rec["verdict"] not in VERDICTS:
        errs.add("$.verdict", f"must be one of {VERDICTS}", repr(rec["verdict"]),
                 "use PASS / DEGRADED / INCONCLUSIVE")

    rp = _req(rec, "run_plan", "$", dict, errs)
    if isinstance(rp, dict):
        _req(rp, "subset_schema_gate_passed", "$.run_plan", bool, errs)
        _req(rp, "no_silent_expansion", "$.run_plan", bool, errs)
        if not isinstance(rp.get("violations"), list):
            errs.add("$.run_plan.violations", "must be an array", repr(rp.get("violations")), "use []")
        if not isinstance(rp.get("planned_node_ids"), list):
            errs.add("$.run_plan.planned_node_ids", "must be an array", repr(rp.get("planned_node_ids")), "use []")

    ic = _req(rec, "intake_counts", "$", dict, errs)
    if isinstance(ic, dict):
        for k in ("fresh_ready", "covered_existing", "duplicate", "not_ready"):
            _req(ic, k, "$.intake_counts", int, errs)

    sm = _req(rec, "summary", "$", dict, errs)
    if isinstance(sm, dict):
        for k in ("healthy_node_count", "excluded_infra_dead_count", "run_same_failure",
                  "run_divergence", "matrix_status", "consecutive_all_ok_rounds"):
            _req(sm, k, "$.summary", int, errs)
        for k in ("run_all_ok", "matrix_timeout", "banked"):
            _req(sm, k, "$.summary", bool, errs)
        if not isinstance(sm.get("source_threshold_note"), str):
            errs.add("$.summary.source_threshold_note", "must be a string",
                     repr(sm.get("source_threshold_note")), "cite the MT-REAL-02 source rule")

    nodes = rec.get("nodes")
    if not isinstance(nodes, list):
        errs.add("$.nodes", "must be an array", repr(nodes), "use [] with node records")
        return
    for i, n in enumerate(nodes):
        p = f"$.nodes[{i}]"
        if not isinstance(n, dict):
            errs.add(p, "node must be an object", type(n).__name__, "use a node object")
            continue
        if not _nonempty_str(n.get("node_id")):
            errs.add(f"{p}.node_id", "required non-empty string", repr(n.get("node_id")), "set node_id")
        for k in ("credential_present", "config_parse_ok", "tcp_reachable", "reality_dest_usable",
                  "direct_reality", "transport_reality", "vless_dial", "vless_probe_io",
                  "included_in_client_verdict"):
            if not isinstance(n.get(k), bool):
                errs.add(f"{p}.{k}", "must be boolean", repr(n.get(k)), f"set `{k}` true/false")
        if n.get("infra_health") not in INFRA_HEALTH:
            errs.add(f"{p}.infra_health", f"must be one of {INFRA_HEALTH}", repr(n.get("infra_health")),
                     "use healthy / infrastructure-dead / unknown")
        for k in ("replacement_for", "replacement_reason", "phase_class", "exclusion_reason"):
            if k in n and not (n[k] is None or isinstance(n[k], str)):
                errs.add(f"{p}.{k}", "must be string or null", repr(n.get(k)), f"set `{k}` to a string or null")


def validate_semantics(rec, errs):
    """Cross-field rules (golden_spec S4 protocol). Only runs on a structurally
    sound enough record; guards against missing pieces."""
    sm = rec.get("summary")
    rp = rec.get("run_plan")
    nodes = rec.get("nodes") if isinstance(rec.get("nodes"), list) else []
    verdict = rec.get("verdict")
    if not isinstance(sm, dict) or not isinstance(rp, dict):
        return  # structural pass needed first

    # ---- per-node: infra-dead exclusion + replacement recording ----
    infra_dead = 0
    for i, n in enumerate(nodes):
        if not isinstance(n, dict):
            continue
        p = f"$.nodes[{i}]"
        if n.get("infra_health") == "infrastructure-dead":
            infra_dead += 1
            if n.get("included_in_client_verdict") is not False:
                errs.add(f"{p}.included_in_client_verdict",
                         "infrastructure-dead node MUST be excluded from the client verdict (node outage != Rust regression)",
                         repr(n.get("included_in_client_verdict")),
                         "set included_in_client_verdict: false for an infra-dead node")
            if not _nonempty_str(n.get("exclusion_reason")):
                errs.add(f"{p}.exclusion_reason",
                         "infrastructure-dead node MUST record a non-empty exclusion_reason",
                         repr(n.get("exclusion_reason")),
                         'set exclusion_reason, e.g. "uniform same-class timeout (probe_io==reality)"')
        # replacement must be recorded
        if _nonempty_str(n.get("replacement_for")) and not _nonempty_str(n.get("replacement_reason")):
            errs.add(f"{p}.replacement_reason",
                     "a replacement node (replacement_for set) MUST record replacement_reason",
                     repr(n.get("replacement_reason")),
                     "state why the replaced node was dropped (e.g. steady-state timeout)")

    # ---- summary count consistency ----
    if isinstance(sm.get("excluded_infra_dead_count"), int) and sm["excluded_infra_dead_count"] != infra_dead:
        errs.add("$.summary.excluded_infra_dead_count",
                 "must equal the number of infrastructure-dead nodes",
                 f"{sm['excluded_infra_dead_count']} (actual infra-dead nodes: {infra_dead})",
                 f"set excluded_infra_dead_count: {infra_dead}")

    # ---- no silent sample-face expansion ----
    planned = set(rp.get("planned_node_ids") or [])
    if rp.get("no_silent_expansion") is not True:
        errs.add("$.run_plan.no_silent_expansion",
                 "must be true (the sample face must not be silently expanded)",
                 repr(rp.get("no_silent_expansion")),
                 "set no_silent_expansion: true and only observe planned/replacement nodes")
    for i, n in enumerate(nodes):
        if not isinstance(n, dict):
            continue
        nid = n.get("node_id")
        is_repl = _nonempty_str(n.get("replacement_for"))
        if _nonempty_str(nid) and nid not in planned and not is_repl:
            errs.add(f"$.nodes[{i}].node_id",
                     "observed node is neither in run_plan.planned_node_ids nor a recorded replacement (silent sample-face expansion)",
                     repr(nid),
                     "add it to planned_node_ids, or record replacement_for + replacement_reason")

    # ---- A4.0b consistency hardening (golden_spec S4 §C/§D/§E invariants) ----
    # rule 1: healthy_node_count == actual number of healthy nodes
    healthy_nodes = sum(1 for n in nodes if isinstance(n, dict) and n.get("infra_health") == "healthy")
    if isinstance(sm.get("healthy_node_count"), int) and sm["healthy_node_count"] != healthy_nodes:
        errs.add("$.summary.healthy_node_count",
                 "must equal the number of healthy nodes",
                 f"{sm['healthy_node_count']} (actual healthy nodes: {healthy_nodes})",
                 f"set healthy_node_count: {healthy_nodes}")

    # rule 3: a node included in the client verdict must be healthy
    for i, n in enumerate(nodes):
        if isinstance(n, dict) and n.get("included_in_client_verdict") is True and n.get("infra_health") != "healthy":
            errs.add(f"$.nodes[{i}].included_in_client_verdict",
                     "a node included in the client verdict MUST be healthy (infra_health == 'healthy')",
                     f"included with infra_health={n.get('infra_health')!r}",
                     "exclude the node (included_in_client_verdict: false) or set infra_health: healthy")

    # rule 10: node_id uniqueness
    ids = [n.get("node_id") for n in nodes if isinstance(n, dict) and _nonempty_str(n.get("node_id"))]
    dup_ids = sorted({x for x in ids if ids.count(x) > 1})
    if dup_ids:
        errs.add("$.nodes[].node_id", "node_id values must be unique",
                 f"duplicate node_id(s): {dup_ids}", "give each node a distinct node_id")

    # rule 9: planned_node_ids uniqueness
    planned_list = rp.get("planned_node_ids") if isinstance(rp.get("planned_node_ids"), list) else []
    dup_planned = sorted({x for x in planned_list if planned_list.count(x) > 1})
    if dup_planned:
        errs.add("$.run_plan.planned_node_ids", "planned_node_ids must be unique",
                 f"duplicate planned id(s): {dup_planned}", "remove duplicate planned node ids")

    # rule 7: replacement_for must reference a planned node
    for i, n in enumerate(nodes):
        if isinstance(n, dict) and _nonempty_str(n.get("replacement_for")) and n["replacement_for"] not in planned:
            errs.add(f"$.nodes[{i}].replacement_for",
                     "replacement_for must reference a node listed in run_plan.planned_node_ids",
                     repr(n.get("replacement_for")),
                     "point replacement_for at the planned (replaced) node id, or add that id to planned_node_ids")

    # rule 6: run_all_ok must agree with included-node phase facts
    included_nodes = [n for n in nodes if isinstance(n, dict) and n.get("included_in_client_verdict") is True]

    def _all_phases_ok(n):
        return all(n.get(ph) is True for ph in ("direct_reality", "transport_reality", "vless_dial", "vless_probe_io"))

    all_included_ok = len(included_nodes) > 0 and all(_all_phases_ok(n) for n in included_nodes)
    if sm.get("run_all_ok") is True and not all_included_ok:
        errs.add("$.summary.run_all_ok",
                 "run_all_ok == true requires >= 1 included node and EVERY included node's four phases all true",
                 f"included={len(included_nodes)} all_included_phases_ok={all_included_ok}",
                 "set run_all_ok: false, or make every included node pass all four phases")

    # rules 11/12/13: PASS or banked => subset gate passed, no violations, no silent expansion
    pass_or_banked = (verdict == "PASS") or (sm.get("banked") is True)
    if pass_or_banked:
        if rp.get("subset_schema_gate_passed") is not True:
            errs.add("$.run_plan.subset_schema_gate_passed",
                     "PASS or banked requires subset_schema_gate_passed == true",
                     repr(rp.get("subset_schema_gate_passed")),
                     "only PASS/bank a round whose subset-schema gate passed")
        if rp.get("violations") != []:
            errs.add("$.run_plan.violations",
                     "PASS or banked requires an empty violations list",
                     repr(rp.get("violations")),
                     "resolve all subset-schema violations before PASS/bank")
        if rp.get("no_silent_expansion") is not True:
            errs.add("$.run_plan.no_silent_expansion",
                     "PASS or banked requires no_silent_expansion == true",
                     repr(rp.get("no_silent_expansion")),
                     "ensure the sample face was not silently expanded before PASS/bank")

    # ---- verdict-specific rules ----
    def s(k):
        return sm.get(k)

    if verdict == "PASS":
        checks = [
            (s("run_all_ok") is True, "$.summary.run_all_ok", "PASS requires run_all_ok == true", s("run_all_ok"), "run_all_ok: true"),
            (s("run_same_failure") == 0, "$.summary.run_same_failure", "PASS requires run_same_failure == 0", s("run_same_failure"), "run_same_failure: 0"),
            (s("run_divergence") == 0, "$.summary.run_divergence", "PASS requires run_divergence == 0", s("run_divergence"), "run_divergence: 0"),
            (s("matrix_status") == 0, "$.summary.matrix_status", "PASS requires matrix_status == 0", s("matrix_status"), "matrix_status: 0"),
            (s("matrix_timeout") is False, "$.summary.matrix_timeout", "PASS requires matrix_timeout == false", s("matrix_timeout"), "matrix_timeout: false"),
            (isinstance(s("healthy_node_count"), int) and s("healthy_node_count") > 0,
             "$.summary.healthy_node_count", "PASS requires healthy_node_count > 0", s("healthy_node_count"), "observe >= 1 healthy node"),
            (len(included_nodes) > 0, "$.nodes",
             "PASS requires at least one node included in the client verdict", len(included_nodes),
             "include >= 1 healthy node in the client verdict"),
        ]
        for cond, path, rule, actual, fix in checks:
            if not cond:
                errs.add(path, rule, repr(actual), fix)
        # rule 5: PASS => every included node passes all four phases
        for i, n in enumerate(nodes):
            if isinstance(n, dict) and n.get("included_in_client_verdict") is True and not _all_phases_ok(n):
                errs.add(f"$.nodes[{i}]",
                         "PASS requires every included node to pass all four phases "
                         "(direct_reality/transport_reality/vless_dial/vless_probe_io)",
                         "included node with a failed phase",
                         "exclude the node or set its four phases true")
        if s("banked") is True:
            r = s("consecutive_all_ok_rounds")
            if not (isinstance(r, int) and r >= RECOVERY_CLOSURE_ROUNDS):
                errs.add("$.summary.consecutive_all_ok_rounds",
                         f"a banked PASS requires consecutive_all_ok_rounds >= {RECOVERY_CLOSURE_ROUNDS} (MT-REAL-02 recovery closure depth, golden_spec S4 §F)",
                         repr(r),
                         f"reach {RECOVERY_CLOSURE_ROUNDS} consecutive all_ok rounds before banking, or set banked: false")

    elif verdict == "DEGRADED":
        client_anomaly = (isinstance(s("run_divergence"), int) and s("run_divergence") > 0) or any(
            isinstance(n, dict) and n.get("included_in_client_verdict") is True
            and not all(n.get(ph) is True for ph in ("direct_reality", "transport_reality", "vless_dial", "vless_probe_io"))
            for n in nodes
        )
        if not client_anomaly:
            errs.add("$.verdict",
                     "DEGRADED requires a reproducible CLIENT anomaly (run_divergence > 0, or a node included_in_client_verdict with a failed phase); it must NOT be triggered solely by infrastructure-dead nodes",
                     "no client-attributed anomaly found",
                     "use INCONCLUSIVE for pure infra failure, or record the client-side divergence")

    elif verdict == "INCONCLUSIVE":
        if s("banked") is not False:
            errs.add("$.summary.banked",
                     "INCONCLUSIVE rounds are not banked",
                     repr(s("banked")),
                     "set banked: false for an INCONCLUSIVE round")


def main():
    if len(sys.argv) != 2:
        print("usage: validate_external_observation.py <record.json>", file=sys.stderr)
        sys.exit(2)
    path = pathlib.Path(sys.argv[1])
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"  FAIL: cannot read {path}: {e}", file=sys.stderr)
        sys.exit(2)
    try:
        rec = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"  FAIL: {path} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    errs = Errors()
    validate_structure(rec, errs)
    validate_semantics(rec, errs)

    if not errs.ok():
        print(f"INVALID: {path} ({len(errs.items)} violation(s))")
        for it in errs.items:
            print(f"  - path={it['path']}")
            print(f"    rule={it['rule']}")
            print(f"    actual={it['actual']}")
            print(f"    fix={it['fix']}")
        sys.exit(1)

    sm = rec["summary"]
    print(f"VALID: {path}")
    print(f"  observation_id = {rec['observation_id']}")
    print(f"  cohort_id={rec['cohort_id']}  round_id={rec['round_id']}  verdict={rec['verdict']}")
    print(f"  healthy_nodes={sm['healthy_node_count']}  excluded_infra_dead={sm['excluded_infra_dead_count']}  banked={sm['banked']}")
    sys.exit(0)


if __name__ == "__main__":
    main()
