# Security Audit Report

**Project**: singbox-rust  
**Audit Window**: 2026-02-12T17:29:38Z  
**Policy Baseline**: L17 (block only `HIGH` / `CRITICAL`; track `MEDIUM` and `unmaintained`)

## Related Artifacts

Supporting TLS/ECH artifacts for this audit live under `reports/security/`:

- `reports/security/tls_fingerprint_baseline.json`
- `reports/security/ech_interop_minimal.json`
- `reports/security/ech_interop_minimal_logs/`

## 1) Dependency Security

### 1.1 `cargo audit`
- **Command**: `cargo audit`
- **Execution**: 2026-02-12T17:29:38Z (local run)
- **Result**: `exit code 1` (tool reports findings), **policy result = PASS (non-blocking)**

Findings:
- Vulnerability: `RUSTSEC-2023-0071` (`rsa 0.9.9`, severity `5.9 medium`, via `arti-client` dependency tree)
- Additional warnings: multiple `unmaintained` advisories (tracked)
- **No HIGH/CRITICAL advisories were reported in this run**

Policy interpretation:
- L17 gate only blocks HIGH/CRITICAL.
- Current vulnerability severity is medium, so release gate is **warning/track**, not blocker.

### 1.2 `cargo deny check licenses`
- **Command**: `cargo deny check licenses --hide-inclusion-graph`
- **Execution**: 2026-02-12T17:29:38Z (local run)
- **Result**: `licenses ok` (exit code 0)

Notes from tool output:
- `bounded-vec-deque` license expression uses deprecated SPDX alias (`GPL-3.0+ OR BSD-3-Clause`) -> parse warning only
- `deny.toml` contains unmatched allowance `Unicode-DFS-2016` -> warning only

## 2) Secret Handling / Logging

### 2.1 Secret keyword log scan
- **Command**: `rg -n --glob '*.rs' '(password|secret|token|api[_-]?key)' crates app | rg -i '(info!|warn!|debug!|trace!)'`
- **Result**: matched logs mention auth events/requirements, e.g. "password authentication attempt/success/failed"
- **Assessment**: no evidence in sampled output of raw credential value emission; logs appear to record metadata/events

### 2.2 Config secret exposure
- **Method**: spot-check by grep + code-path review of auth modules
- **Assessment**: no direct raw secret print found in current sampled paths; continue periodic review during changes to auth/config parsing

## 3) TLS and Auth Controls

### 3.1 TLS baseline
- Rust TLS stack remains rustls-based (TLS 1.2+ baseline)
- No evidence in this audit run of enabling legacy TLS 1.0/1.1

### 3.2 Timing-safe comparison
- **Command**: `rg -n 'ConstantTimeEq|ct_eq' crates app`
- **Result**: constant-time comparisons found in multiple auth paths, including:
  - `app/src/admin_debug/auth/apikey.rs`
  - `app/src/admin_debug/http_server.rs`
  - `crates/sb-security/src/credentials.rs`
  - `crates/sb-adapters/src/inbound/naive.rs`
- **Assessment**: PASS (timing-safe compare primitives are in use)

## 4) Command Injection Surface (Targeted Review)

- **Command**: `rg -n 'Command::new\(' crates app scripts`
- **Result**: command execution points are present across platform/network helper code and tests
- **Assessment**: no direct exploitable path confirmed in this L17 pass; retain as ongoing review item, especially callsites where command/args are indirectly composed

## 5) L17 Security Conclusion

| Check | Outcome | Blocking? |
|---|---|---|
| `cargo audit` | MEDIUM + unmaintained findings only | No (policy) |
| `cargo deny check licenses` | Pass with warnings | No |
| Secret/log leak scan | No raw secret leakage seen in sampled matches | No |
| Constant-time auth compare | Present in key auth paths | No |

**Final status (L17 policy)**: **PASS with tracked warnings**  
**Tracked exceptions**: medium/unmaintained advisories (documented above)  
**Blocker threshold**: HIGH/CRITICAL only (none observed in this run)
