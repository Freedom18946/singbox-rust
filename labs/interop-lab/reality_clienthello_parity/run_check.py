#!/usr/bin/env python3
"""Orchestrate the local REALITY ClientHello-parity check (read-only, no public network).

Pipeline: render configs from the committed manifest into a TEMP dir -> bring up the local
fixture topology (tls_dest / http_target / reality_server, fixed ports unchanged) -> start a
transparent recorder on a configurable port -> run the Go reference client and the Rust
candidate client N times each through the recorder (token-match) -> parse the captured
ClientHellos (raw bytes in a tempfile dir, removed on exit) -> compare profiles -> write a
SANITIZED summary to the gitignored artifacts dir -> tear everything down.

Exit 0 iff the BLOCKING parity gates pass; advisory diagnostics never change the exit code.
Never overwrites committed evidence; never modifies the committed manifest (uses a temp copy).
"""
import argparse
import datetime
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]
FIXTURE = REPO / "labs/interop-lab/reality_local_fixture"
GO_SB = REPO / "target/reality_fixture_bin/sing-box-utls"
HELPER = REPO / "target/reality_fixture_bin/fixture-helper"
APP = REPO / "target/debug/app"
RENDER = FIXTURE / "render_configs.py"

sys.path.insert(0, str(HERE))
import capture_clienthello as cap          # noqa: E402
import parse_clienthello as P              # noqa: E402
import compare_profiles as C               # noqa: E402
import foxio_reference as FR               # noqa: E402


def spawn(name, argv, logdir):
    lf = open(os.path.join(logdir, f"{name}.log"), "wb")
    return subprocess.Popen([str(a) for a in argv], stdout=lf, stderr=subprocess.STDOUT,
                            start_new_session=True)


def curl(socks, url, token):
    r = subprocess.run(["curl", "-sS", "--max-time", "12", "--socks5-hostname",
                        f"127.0.0.1:{socks}", url], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == token


def patch_client(src, dst, rec_port):
    d = json.loads(pathlib.Path(src).read_text())
    for ob in d.get("outbounds", []):
        if ob.get("server_port") == 18443:   # go schema
            ob["server_port"] = rec_port
        if ob.get("port") == 18443:           # rust v2 schema
            ob["port"] = rec_port
    pathlib.Path(dst).write_text(json.dumps(d, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--recorder-port", type=int, default=28443)
    ap.add_argument("--out")
    ap.add_argument("--debug-retain-raw", action="store_true",
                    help="keep raw ClientHello records on disk (may contain REALITY auth material)")
    args = ap.parse_args()

    for b in (GO_SB, HELPER, APP):
        if not b.exists():
            sys.exit(f"missing binary {b} — run `make verify-reality-local` once to build the fixture bins")

    m = json.loads((FIXTURE / "manifest.json").read_text())
    ports = m["ports"]; token = m["expected_token"]; sni = m["sni"]
    url = f"http://127.0.0.1:{ports['http_target']}{m['http_target_path']}"
    run_id = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    out = pathlib.Path(args.out) if args.out else (
        REPO / "labs/interop-lab/artifacts/reality_clienthello_parity" / run_id)
    out.mkdir(parents=True, exist_ok=True)

    tmp = tempfile.TemporaryDirectory(prefix="reality_ch_parity_")
    work = pathlib.Path(tmp.name)
    rawdir = work / "raw"; rawdir.mkdir()
    rendered = work / "rendered"; logdir = work / "logs"; logdir.mkdir()
    if args.debug_retain_raw:
        rawdir = out / "raw_DEBUG"; rawdir.mkdir(exist_ok=True)
        print(cap.RAW_WARNING, file=sys.stderr)

    procs = []
    rec = None

    def teardown():
        if rec is not None:
            rec.stop()
        for p in reversed(procs):
            if p.poll() is None:
                pgid = None
                try:
                    pgid = os.getpgid(p.pid)
                except ProcessLookupError:
                    continue
                except OSError as exc:
                    print(f"warn: failed to read process pgid pid={p.pid}: {exc}", file=sys.stderr)
                if pgid is not None:
                    try:
                        os.killpg(pgid, signal.SIGTERM)
                    except ProcessLookupError:
                        continue
                    except OSError as exc:
                        print(f"warn: failed to SIGTERM process pid={p.pid}: {exc}", file=sys.stderr)
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if pgid is not None:
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            continue
                        except OSError as exc:
                            print(f"warn: failed to SIGKILL process pid={p.pid}: {exc}", file=sys.stderr)
                    p.wait(timeout=5)

    def terminate_client_process(kernel, cp):
        pgid = None
        try:
            pgid = os.getpgid(cp.pid)
        except ProcessLookupError:
            pass
        except OSError as exc:
            print(f"warn: failed to read {kernel}_client pgid pid={cp.pid}: {exc}", file=sys.stderr)

        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as exc:
                print(f"warn: failed to SIGTERM {kernel}_client pid={cp.pid}: {exc}", file=sys.stderr)

        try:
            cp.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass

        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                print(f"warn: failed to SIGKILL {kernel}_client pid={cp.pid}: {exc}", file=sys.stderr)
        cp.wait(timeout=5)

    try:
        r = subprocess.run(["python3", str(RENDER), "--manifest", str(FIXTURE / "manifest.json"),
                            "--out-dir", str(rendered)], capture_output=True, text=True)
        if r.returncode:
            sys.exit("render failed:\n" + r.stdout + r.stderr)
        go_cfg = work / "go_client_rec.json"; rust_cfg = work / "rust_client_rec.json"
        patch_client(rendered / "go_client.json", go_cfg, args.recorder_port)
        patch_client(rendered / "rust_client.json", rust_cfg, args.recorder_port)

        procs.append(spawn("tls_dest", [HELPER, "-mode", "tls-dest",
                     "-listen", f"127.0.0.1:{ports['tls_dest']}", "-sni", sni], str(logdir)))
        procs.append(spawn("http_target", [HELPER, "-mode", "http-target",
                     "-listen", f"127.0.0.1:{ports['http_target']}", "-token", token], str(logdir)))
        procs.append(spawn("reality_server", [GO_SB, "run", "-c", str(rendered / "go_server.json")], str(logdir)))
        if not all(cap.wait_port(ports[p]) for p in ("tls_dest", "http_target", "reality_server")):
            sys.exit("topology failed to come up")

        rec = cap.Recorder(args.recorder_port, "127.0.0.1", ports["reality_server"], str(rawdir))
        rec.start()
        if not cap.wait_port(args.recorder_port):
            sys.exit("recorder failed to come up")

        token_ok = {}
        for kernel, cfg, socks, binp in (("go", go_cfg, ports["go_client_socks"], GO_SB),
                                         ("rust", rust_cfg, ports["rust_client_socks"], APP)):
            rec.set_kernel(kernel)
            cp = spawn(f"{kernel}_client", [binp, "run", "-c", str(cfg)], str(logdir))
            procs.append(cp)
            cap.wait_port(socks)
            token_ok[kernel] = sum(1 for _ in range(args.runs) if curl(socks, url, token)) == args.runs
            import time; time.sleep(0.4)
            terminate_client_process(kernel, cp)
            if cp in procs:
                procs.remove(cp)

        rec.stop()
        go = [P.parse_record((rawdir / "go" / f).read_bytes()) for f in sorted(os.listdir(rawdir / "go"))]
        rust = [P.parse_record((rawdir / "rust" / f).read_bytes()) for f in sorted(os.listdir(rawdir / "rust"))]

        snap = None
        snap_path = HERE / "fixtures" / "expected_profile_shape.json"
        if snap_path.exists():
            snap = json.loads(snap_path.read_text())
        result = C.compare(go, rust, token_ok["go"], token_ok["rust"], snap)

        summary = {
            "run_id": run_id, "runs": args.runs,
            "blocking_pass": result["blocking_pass"],
            "blocking": result["blocking"], "advisory": result["advisory"],
            "go_normalized_profile": go[0]["normalized_profile"] if go else None,
            "rust_normalized_profile": rust[0]["normalized_profile"] if rust else None,
            "go_from_spec_ja4": sorted({p["derived"]["from_spec_ja4"] for p in go}),
            "rust_from_spec_ja4": sorted({p["derived"]["from_spec_ja4"] for p in rust}),
            "foxio_reference_crosscheck": FR.verify_against_vendored_vectors(),
            "counts": {"go": len(go), "rust": len(rust)},
        }
        (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps({"blocking_pass": result["blocking_pass"],
                          "go": len(go), "rust": len(rust),
                          "token_match": result["blocking"]["token_match"],
                          "digest": result["blocking"]["normalized_profile_digest_parity"],
                          "field_set": result["blocking"]["required_field_set_parity"]["pass"],
                          "summary": str(out / "summary.json")}, indent=2))
        sys.exit(0 if result["blocking_pass"] else 1)
    finally:
        teardown()
        tmp.cleanup()  # remove raw temp records (unless debug-retain wrote to out/)


if __name__ == "__main__":
    main()
