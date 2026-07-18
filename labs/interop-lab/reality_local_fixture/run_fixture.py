#!/usr/bin/env python3
"""A1 controlled local REALITY functional-parity fixture orchestrator.

Pipeline: build -> render -> bring up local topology (readiness/timeout/log/teardown)
-> positive matrix (both clients -> Go server; Go client -> Rust server; phase probe) ->
negative matrix (bad_public_key / bad_uuid / dead_dest / occupied_port) -> emit
round-summary.json + per_run/*.json + rendered configs + process logs.

Topology (all 127.0.0.1, NO public node / NO openssl s_server / NO socat):
  reality_server       Go VLESS+REALITY inbound (-tags with_utls)
  rust_reality_server  Rust VLESS+REALITY inbound helper
  tls_dest        in-repo concurrent Go tls.Listener (handshake target)
  http_target     in-repo Go HTTP server returning a fixed token
  {go,rust}_client_socks + go_reverse_client_socks client entrypoints

Scope: bidirectional Go/Rust REALITY interoperability plus local VLESS dataplane.
Does NOT validate real-network camouflage or move 52/56 BHV parity.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import time

from render_configs import b64url_to_hex

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return _ANSI.sub("", s)


def extract_phases(d):
    """Auto-extract the 4 phase items (ok/class/error) from a probe output dict.

    NOT hand-written: this is the single transform from raw probe JSON to the
    per_run / round-summary phase record. Returns None if the probe produced no
    output (timeout/crash)."""
    if not d:
        return None
    return {
        k: {"ok": d[k]["ok"], "class": d[k]["class"], "error": d[k].get("error")}
        for k in ("direct_reality", "transport_reality", "vless_dial", "vless_probe_io")
    }

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]  # labs/interop-lab/reality_local_fixture -> repo root
ENV_TOOL = REPO / "scripts/tools/reality_vless_env_from_config.py"
RENDER = HERE / "render_configs.py"
GO_BUILD_TAGS = "with_utls"


def go_fork_dir() -> pathlib.Path:
    cands = sorted((REPO / "go_fork_source").glob("sing-box-*"))
    if not cands:
        raise SystemExit("go_fork_source/sing-box-* not found")
    return cands[-1]


def sh(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def wait_port(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False


class ProcManager:
    def __init__(self, logdir: pathlib.Path):
        self.logdir = logdir
        logdir.mkdir(parents=True, exist_ok=True)
        self.procs = []  # (name, popen, logfile)

    def start(self, name, argv, env=None, cwd=None):
        logf = open(self.logdir / f"{name}.log", "wb")
        full = dict(os.environ)
        if env:
            full.update(env)
        p = subprocess.Popen(argv, stdout=logf, stderr=subprocess.STDOUT, env=full,
                             cwd=str(cwd) if cwd else None, start_new_session=True)
        self.procs.append((name, p, logf))
        return p

    def teardown(self) -> dict:
        status = {}
        for name, p, logf in reversed(self.procs):
            if p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                except Exception:
                    p.terminate()
                try:
                    p.wait(timeout=5)
                    status[name] = "terminated"
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                    except Exception:
                        p.kill()
                    status[name] = "killed"
            else:
                status[name] = f"exited:{p.returncode}"
            logf.close()
        self.procs = []
        return status


def build_all(bindir: pathlib.Path, skip: bool) -> dict:
    bindir.mkdir(parents=True, exist_ok=True)
    go_sb = bindir / "sing-box-utls"
    helper = bindir / "fixture-helper"
    app = REPO / "target/debug/app"
    probe = REPO / "target/debug/examples/vless_reality_phase_probe"
    rust_server = REPO / "target/debug/examples/vless_reality_server_fixture"
    info = {"go_build_tags": GO_BUILD_TAGS}
    if skip:
        info["skipped"] = True
        return {
            "go_sb": go_sb,
            "helper": helper,
            "app": app,
            "probe": probe,
            "rust_server": rust_server,
            "info": info,
        }

    print("[build] Go sing-box (-tags %s) ..." % GO_BUILD_TAGS, flush=True)
    r = sh(["go", "-C", str(go_fork_dir()), "build", "-tags", GO_BUILD_TAGS, "-o", str(go_sb), "./cmd/sing-box"])
    if r.returncode:
        raise SystemExit("go sing-box build failed:\n" + r.stderr[-2000:])

    print("[build] Go fixture-helper ...", flush=True)
    r = sh(["go", "-C", str(HERE / "helper"), "build", "-o", str(helper), "."])
    if r.returncode:
        raise SystemExit("helper build failed:\n" + r.stderr[-2000:])

    print("[build] Rust app (acceptance,transport_reality) ...", flush=True)
    r = sh(["cargo", "build", "-p", "app", "--features", "acceptance,transport_reality", "--bin", "app"], cwd=REPO)
    if r.returncode:
        raise SystemExit("rust app build failed:\n" + r.stderr[-3000:])

    print("[build] Rust phase probe ...", flush=True)
    r = sh(["cargo", "build", "-p", "sb-adapters", "--example", "vless_reality_phase_probe",
            "--features", "adapter-vless,tls_reality,sb-transport"], cwd=REPO)
    if r.returncode:
        raise SystemExit("rust probe build failed:\n" + r.stderr[-3000:])

    print("[build] Rust VLESS+REALITY server fixture ...", flush=True)
    r = sh(["cargo", "build", "-p", "sb-adapters", "--example", "vless_reality_server_fixture",
            "--features", "adapter-vless,tls_reality"], cwd=REPO)
    if r.returncode:
        raise SystemExit("rust server fixture build failed:\n" + r.stderr[-3000:])

    return {
        "go_sb": go_sb,
        "helper": helper,
        "app": app,
        "probe": probe,
        "rust_server": rust_server,
        "info": info,
    }


def probe_env(rust_cfg: pathlib.Path, target: str, m: dict) -> dict:
    r = sh(["python3", str(ENV_TOOL), "--config", str(rust_cfg), "--outbound", "vless-reality-out",
            "--target", target, "--phase-timeout-ms", str(m["timeouts"]["phase_timeout_ms"]),
            "--probe-io-timeout-ms", str(m["timeouts"]["probe_io_timeout_ms"]), "--format", "json"])
    if r.returncode:
        raise SystemExit("env extract failed for %s:\n%s" % (rust_cfg, r.stderr))
    return json.loads(r.stdout)


def run_probe(probe_bin: pathlib.Path, env: dict, timeout_s: float):
    t0 = time.time()
    try:
        r = subprocess.run([str(probe_bin)], env={**os.environ, **env},
                          capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return None, round((time.time() - t0) * 1000, 1), True
    # A non-timeout probe crash (panic/SIGKILL/early-exit -> empty or non-JSON
    # stdout) must NOT abort the whole orchestration and discard the round's
    # evidence; surface it as a clean structured failure (d=None) instead.
    try:
        return json.loads(r.stdout), round((time.time() - t0) * 1000, 1), False
    except (json.JSONDecodeError, ValueError):
        return None, round((time.time() - t0) * 1000, 1), False


def curl_token(socks_port: int, url: str, token: str, timeout_s: float, bodyfile: pathlib.Path):
    # Truncate any prior body first: `curl -o` does NOT truncate on early
    # connection failure, so a failed run could otherwise read a previous run's
    # body and falsely report a token match.
    try:
        bodyfile.unlink()
    except OSError:
        pass
    r = sh(["curl", "-sS", "--max-time", str(timeout_s), "--socks5-hostname",
            f"127.0.0.1:{socks_port}", url, "-o", str(bodyfile), "-w", "%{http_code} %{time_total}"])
    code, _, ttot = (r.stdout.strip().partition(" "))
    body = ""
    try:
        body = bodyfile.read_text(errors="replace").strip()
    except OSError:
        pass
    return {
        "http_code": code or "000",
        # A run counts only if curl succeeded, HTTP was 200, AND the body equals
        # the expected token — body-equality alone is insufficient (see above).
        "token_match": (r.returncode == 0 and code == "200" and body == token),
        "elapsed_ms": round(float(ttot or 0) * 1000, 1),
        "curl_rc": r.returncode,
        "err": (r.stderr.strip()[:200] if r.returncode else ""),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--bin-dir", help="where to build/find binaries (default: <repo>/target/reality_fixture_bin, out-of-tree so --out stays evidence-only and reusable across --skip-build runs)")
    ap.add_argument("--out")
    args = ap.parse_args()

    m = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    manifest_checksum = "sha256:" + hashlib.sha256((HERE / "manifest.json").read_bytes()).hexdigest()
    git_rev = sh(["git", "-C", str(REPO), "rev-parse", "HEAD"]).stdout.strip() or "unknown"
    run_id = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    out = pathlib.Path(args.out) if args.out else (REPO / "labs/interop-lab/artifacts/reality_local_fixture" / run_id)
    out.mkdir(parents=True, exist_ok=True)
    rendered = out / "rendered"
    logs = out / "logs"
    per_run_dir = out / "per_run"
    per_run_dir.mkdir(parents=True, exist_ok=True)
    bodyfile = out / "_curl_body.tmp"

    p = m["ports"]
    target_url = f"http://127.0.0.1:{p['http_target']}{m['http_target_path']}"
    target_hp = f"127.0.0.1:{p['http_target']}"
    token = m["expected_token"]
    T = m["timeouts"]
    N = args.runs

    print(f"[a1] run_id={run_id} out={out}")
    bin_dir = pathlib.Path(args.bin_dir) if args.bin_dir else (REPO / "target" / "reality_fixture_bin")
    bins = build_all(bin_dir, args.skip_build)

    print("[render] configs from manifest ...", flush=True)
    r = sh(["python3", str(RENDER), "--manifest", str(HERE / "manifest.json"), "--out-dir", str(rendered)])
    if r.returncode:
        raise SystemExit("render failed:\n" + r.stdout + r.stderr)

    # config validation with the real kernels
    val = {}
    val["go_server"] = sh([str(bins["go_sb"]), "check", "-c", str(rendered / "go_server.json")]).returncode
    val["go_client"] = sh([str(bins["go_sb"]), "check", "-c", str(rendered / "go_client.json")]).returncode
    val["go_reverse_client"] = sh([str(bins["go_sb"]), "check", "-c", str(rendered / "go_reverse_client.json")]).returncode
    val["rust_client"] = sh([str(bins["app"]), "check", "-c", str(rendered / "rust_client.json")]).returncode
    print("[validate]", val, flush=True)

    summary = {
        "fixture_version": m["fixture_version"],
        "git_revision": git_rev,
        "go_build_tags": GO_BUILD_TAGS,
        "manifest_checksum": manifest_checksum,
        "run_id": run_id,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "scope": "Bidirectional Go/Rust REALITY interoperability plus local VLESS dataplane; NOT real-network camouflage; NOT a 52/56 BHV increment.",
        "acceptance_model": {
            "tier": "local_deterministic_gate",
            "meaning": "This fixture is the merge-blocking tier: both clients reach a controlled Go REALITY server, and a Go uTLS REALITY client reaches the Rust REALITY server. ClientHello fingerprint shape is covered by the separate local Chrome canary; real-network camouflage belongs to external healthy-cohort observation.",
        },
        "topology": {**{k: f"127.0.0.1:{v}" for k, v in p.items()}, "sni": m["sni"], "flow": m["flow"], "token": token},
        "artifacts": {"per_run": "per_run/", "rendered_configs": "rendered/", "process_logs": "logs/"},
        "config_validation": val,
        "positive": {},
        "negative": {},
        "teardown": {},
    }

    # ---------------- POSITIVE ----------------
    pm = ProcManager(logs)
    try:
        pm.start("tls_dest", [str(bins["helper"]), "-mode", "tls-dest",
                              "-listen", f"127.0.0.1:{p['tls_dest']}", "-sni", m["sni"]])
        pm.start("http_target", [str(bins["helper"]), "-mode", "http-target",
                                 "-listen", f"127.0.0.1:{p['http_target']}", "-token", token])
        pm.start("reality_server", [str(bins["go_sb"]), "run", "-c", str(rendered / "go_server.json")])
        rust_server_env = {
            "SB_REALITY_SERVER_LISTEN": f"127.0.0.1:{p['rust_reality_server']}",
            "SB_REALITY_SERVER_TARGET": f"127.0.0.1:{p['tls_dest']}",
            "SB_REALITY_SERVER_NAMES": m["sni"],
            "SB_REALITY_SERVER_PRIVATE_KEY_HEX": b64url_to_hex(m["x25519"]["private_key_b64"]),
            "SB_REALITY_SERVER_SHORT_IDS": m["short_id"],
            "SB_VLESS_UUID": m["uuid"],
        }
        pm.start("rust_reality_server", [str(bins["rust_server"])], env=rust_server_env)
        pm.start("go_client", [str(bins["go_sb"]), "run", "-c", str(rendered / "go_client.json")])
        pm.start("go_reverse_client", [str(bins["go_sb"]), "run", "-c", str(rendered / "go_reverse_client.json")])
        pm.start("rust_client", [str(bins["app"]), "run", "-c", str(rendered / "rust_client.json")])

        ready = {
            "tls_dest": wait_port("127.0.0.1", p["tls_dest"], T["startup_timeout_s"]),
            "http_target": wait_port("127.0.0.1", p["http_target"], T["startup_timeout_s"]),
            "reality_server": wait_port("127.0.0.1", p["reality_server"], T["startup_timeout_s"]),
            "rust_reality_server": wait_port("127.0.0.1", p["rust_reality_server"], T["startup_timeout_s"]),
            "go_client": wait_port("127.0.0.1", p["go_client_socks"], T["startup_timeout_s"]),
            "go_reverse_client": wait_port("127.0.0.1", p["go_reverse_client_socks"], T["startup_timeout_s"]),
            "rust_client": wait_port("127.0.0.1", p["rust_client_socks"], T["startup_timeout_s"]),
        }
        summary["positive"]["readiness"] = ready
        print("[positive] readiness", ready, flush=True)
        if not all(ready.values()):
            # Topology failed to come up. Still emit a round-summary with a FAIL
            # verdict (don't just raise) so a consumer parsing the JSON verdict
            # cannot mistake an aborted run for "no result".
            summary["positive"]["readiness_ok"] = False
            summary["teardown"]["positive"] = pm.teardown()
            summary["verdict"] = {
                "positive_all_ok": False, "negative_all_pass": False,
                "config_validation_ok": all(v == 0 for v in val.values()),
                "local_deterministic_gate": "FAIL",
                "abort_reason": "positive readiness failed: " + json.dumps(ready),
            }
            (out / "round-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print("[a1] readiness FAILED -> FAIL round-summary ->", out / "round-summary.json")
            sys.exit(1)

        # Go client e2e token x N
        go_runs = []
        for i in range(1, N + 1):
            rec = {"case": "positive", "kernel": "go_client", "run_index": i,
                   **curl_token(p["go_client_socks"], target_url, token, T["request_timeout_s"], bodyfile)}
            go_runs.append(rec)
        (per_run_dir / "positive_go_client.json").write_text(json.dumps(go_runs, indent=2))

        # Go uTLS REALITY client -> Rust REALITY+VLESS server x N
        go_reverse_runs = []
        for i in range(1, N + 1):
            rec = {"case": "positive", "kernel": "go_client_to_rust_server", "run_index": i,
                   **curl_token(p["go_reverse_client_socks"], target_url, token, T["request_timeout_s"], bodyfile)}
            go_reverse_runs.append(rec)
        (per_run_dir / "positive_go_client_to_rust_server.json").write_text(
            json.dumps(go_reverse_runs, indent=2)
        )

        # Rust client (app) e2e token x N
        rust_runs = []
        for i in range(1, N + 1):
            rec = {"case": "positive", "kernel": "rust_client", "run_index": i,
                   **curl_token(p["rust_client_socks"], target_url, token, T["request_timeout_s"], bodyfile)}
            rust_runs.append(rec)
        (per_run_dir / "positive_rust_client.json").write_text(json.dumps(rust_runs, indent=2))

        # Rust phase probe x N (records the 4 phase items)
        penv = probe_env(rendered / "rust_client.json", target_hp, m)
        probe_runs = []
        for i in range(1, N + 1):
            d, ms, timed_out = run_probe(bins["probe"], penv, T["negative_proc_timeout_s"])
            probe_runs.append({"case": "positive", "kernel": "rust_phase_probe", "run_index": i,
                               "elapsed_ms": ms, "timed_out": timed_out, "phase_results": extract_phases(d)})
        (per_run_dir / "positive_rust_phase_probe.json").write_text(json.dumps(probe_runs, indent=2))

        go_ok = sum(1 for r in go_runs if r["token_match"])
        go_reverse_ok = sum(1 for r in go_reverse_runs if r["token_match"])
        rust_ok = sum(1 for r in rust_runs if r["token_match"])
        probe_ok = sum(1 for r in probe_runs if r["phase_results"] and all(
            r["phase_results"][k]["ok"] for k in r["phase_results"]))
        # Embed the auto-collected per_run rows so round-summary.json is self-contained
        # (case / kernel / run_index / phase_results / token_match / elapsed all present).
        summary["positive"]["go_client"] = {"runs": N, "token_match_count": go_ok, "all_ok": go_ok == N, "per_run": go_runs}
        summary["positive"]["go_client_to_rust_server"] = {
            "runs": N,
            "token_match_count": go_reverse_ok,
            "all_ok": go_reverse_ok == N,
            "flow": m["reverse_flow"],
            "per_run": go_reverse_runs,
        }
        summary["positive"]["rust_client"] = {"runs": N, "token_match_count": rust_ok, "all_ok": rust_ok == N, "per_run": rust_runs}
        summary["positive"]["rust_phase_probe"] = {"runs": N, "all_phases_ok_count": probe_ok, "all_ok": probe_ok == N, "per_run": probe_runs}
        print(
            f"[positive] go->go={go_ok}/{N} go->rust={go_reverse_ok}/{N} "
            f"rust->go={rust_ok}/{N} probe_all_ok={probe_ok}/{N}",
            flush=True,
        )
    finally:
        summary["teardown"]["positive"] = pm.teardown()

    # ---------------- NEGATIVE ----------------
    def neg_case(name, server_cfg, rust_cfg, expect_fn, start_occupier=False):
        nm = ProcManager(logs / name)
        observed = {}
        try:
            if start_occupier:
                # occupy reality_server port BEFORE the server starts
                nm.start("occupier", [str(bins["helper"]), "-mode", "http-target",
                                      "-listen", f"127.0.0.1:{p['reality_server']}", "-token", "occupied"])
                wait_port("127.0.0.1", p["reality_server"], T["startup_timeout_s"])
            else:
                nm.start("tls_dest", [str(bins["helper"]), "-mode", "tls-dest",
                                      "-listen", f"127.0.0.1:{p['tls_dest']}", "-sni", m["sni"]])
                nm.start("http_target", [str(bins["helper"]), "-mode", "http-target",
                                         "-listen", f"127.0.0.1:{p['http_target']}", "-token", token])
                wait_port("127.0.0.1", p["tls_dest"], T["startup_timeout_s"])
                wait_port("127.0.0.1", p["http_target"], T["startup_timeout_s"])

            srv = nm.start("reality_server", [str(bins["go_sb"]), "run", "-c", str(rendered / server_cfg)])

            if start_occupier:
                # the server must FAIL to bind; give it a moment then inspect
                time.sleep(2.5)
                rc = srv.poll()
                logtxt = (logs / name / "reality_server.log").read_text(errors="replace") if (logs / name / "reality_server.log").exists() else ""
                lines = logtxt.splitlines()
                # Prefer the BIND-specific line (what occupied_port is actually
                # testing); fall back to any fatal/error line only for diagnostics.
                diag = (next((ln for ln in lines if "address already in use" in ln.lower()
                              or "bind:" in ln.lower()), "")
                        or next((ln for ln in lines if any(s in ln.lower()
                                 for s in ("fatal", "error", "in use"))), ""))
                observed = {"server_exited": rc is not None, "exit_code": rc, "diagnostic": strip_ansi(diag)[:300]}
                return expect_fn(observed), observed

            if not wait_port("127.0.0.1", p["reality_server"], T["startup_timeout_s"]):
                observed = {"error": "reality_server not ready"}
                return False, observed

            penv = probe_env(rendered / rust_cfg, target_hp, m)
            d, ms, timed_out = run_probe(bins["probe"], penv, T["negative_proc_timeout_s"])
            observed = {"elapsed_ms": ms, "timed_out": timed_out, "phase_results": extract_phases(d)}
            (per_run_dir / f"negative_{name}.json").write_text(json.dumps(observed, indent=2))
            return expect_fn(observed), observed
        finally:
            summary["teardown"][name] = nm.teardown()

    # bad_public_key: REALITY fails at direct_reality; NO phase falsely ok
    def exp_bad_pubkey(o):
        ph = o.get("phase_results")
        return bool(ph) and (ph["direct_reality"]["ok"] is False) and not any(ph[k]["ok"] for k in ph)
    ok, obs = neg_case("bad_public_key", "go_server.json", "rust_client_bad_pubkey.json", exp_bad_pubkey)
    summary["negative"]["bad_public_key"] = {
        "expectation": "direct_reality fails; no phase falsely reports success", "pass": ok, "observed": obs}

    # bad_uuid: REALITY phases ok; vless_probe_io must fail
    def exp_bad_uuid(o):
        ph = o.get("phase_results")
        if not ph:
            return False
        io = ph["vless_probe_io"]
        # REALITY layers must succeed AND the VLESS dial must open; the rejection
        # must land at the post-dial DATA stage (not the REALITY handshake) — that
        # layer distinction is the whole point of this case.
        return (ph["direct_reality"]["ok"] and ph["transport_reality"]["ok"]
                and ph["vless_dial"]["ok"] and (io["ok"] is False)
                and io["class"] in ("post_dial_eof", "connection_reset", "broken_pipe"))
    ok, obs = neg_case("bad_uuid", "go_server.json", "rust_client_bad_uuid.json", exp_bad_uuid)
    summary["negative"]["bad_uuid"] = {
        "expectation": "REALITY phase ok; vless_probe_io fails", "pass": ok, "observed": obs}

    # dead_dest: server dest is dead -> clear fail within timeout, no wedge
    def exp_dead_dest(o):
        ph = o.get("phase_results")
        elapsed = o.get("elapsed_ms")
        # "fails fast" must be actually bounded, not merely "< the 60s proc ceiling":
        # a partial wedge would push elapsed toward a phase-timeout multiple.
        fast = isinstance(elapsed, (int, float)) and elapsed < (2 * T["phase_timeout_ms"])
        return (o.get("timed_out") is False) and fast and bool(ph) and (ph["direct_reality"]["ok"] is False)
    ok, obs = neg_case("dead_dest", "go_server_dead_dest.json", "rust_client.json", exp_dead_dest)
    summary["negative"]["dead_dest"] = {
        "expectation": "fails fast (direct_reality not ok), exits within timeout, no wedge", "pass": ok, "observed": obs}

    # occupied_port: reality server can't bind -> startup failure with diagnosable error
    def exp_occupied(o):
        diag = (o.get("diagnostic") or "").lower()
        # Require a BIND-specific diagnostic, not just any error/fatal line, so the
        # case can't pass on an unrelated startup failure.
        return (bool(o.get("server_exited")) and (o.get("exit_code") not in (0, None))
                and ("address already in use" in diag or "bind" in diag))
    ok, obs = neg_case("occupied_port", "go_server.json", "rust_client.json", exp_occupied, start_occupier=True)
    summary["negative"]["occupied_port"] = {
        "expectation": "fixture startup fails with a diagnosable bind error", "pass": ok, "observed": obs}

    # ---------------- VERDICT ----------------
    pos = summary["positive"]
    pos_ok = all([
        pos.get("go_client", {}).get("all_ok"),
        pos.get("go_client_to_rust_server", {}).get("all_ok"),
        pos.get("rust_client", {}).get("all_ok"),
        pos.get("rust_phase_probe", {}).get("all_ok"),
    ])
    neg_ok = all(summary["negative"][k]["pass"] for k in summary["negative"])
    cfg_ok = all(v == 0 for v in val.values())
    summary["verdict"] = {
        "positive_all_ok": pos_ok,
        "negative_all_pass": neg_ok,
        "config_validation_ok": cfg_ok,
        "local_deterministic_gate": "PASS" if (pos_ok and neg_ok and cfg_ok) else "FAIL",
    }

    (out / "round-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if bodyfile.exists():
        bodyfile.unlink()
    print("\n[a1] verdict:", json.dumps(summary["verdict"]))
    print("[a1] round-summary ->", out / "round-summary.json")
    sys.exit(0 if summary["verdict"]["local_deterministic_gate"] == "PASS" else 1)


if __name__ == "__main__":
    main()
