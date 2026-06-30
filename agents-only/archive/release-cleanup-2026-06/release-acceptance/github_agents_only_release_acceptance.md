# .github and agents-only Release Acceptance

Date: 2026-06-30
Scope: `.github/` policy stub, `agents-only/` navigation docs, governance scripts, and local
artifact integrity checks.

## Verdict

PASS-LOCAL for `.github/` workflow-disablement hygiene and `agents-only/` navigation /
governance integrity.

This is repository-governance hygiene only. It does not claim REALITY movement,
dual-kernel BHV/parity movement, workflow automation, release packaging completion, or
product behavior change.

## Findings Fixed

- `agents-only/README.md` still listed a `planning/` directory that no longer exists.
- `agents-only/README.md` had an old update stamp and described `06-scripts/` only as
  generic helpers, hiding its current local governance role.
- `agents-only/06-scripts/README.md` omitted `verify-consistency.sh` and
  `restore-context.sh`, and called `check-boundaries.sh` a CI boundary check even though
  GitHub Actions are permanently disabled.

## `.github/` Result

- `.github/` contains only `README.md`.
- No tracked or untracked `.github/workflows/*` path exists.
- `.github/README.md` remains the active policy stub: GitHub Actions are permanently
  disabled; verification is local.

## `agents-only/` Result

- Entry links in `agents-only/README.md`, `agents-only/init.md`,
  `agents-only/workpackage_latest.md`, `agents-only/06-scripts/README.md`, and
  `.github/README.md` resolve locally.
- All `agents-only/**/*.sh` files pass shell syntax checks according to their shebangs.
- `agents-only` Python helpers compile.
- `agents-only` JSON artifacts parse, with one documented historical exception:
  `agents-only/mt_real_01_evidence/phase3_runtime/logs_endpoint.json` is a zero-byte
  endpoint capture and was not modified.
- YAML artifacts parse.
- Existing consistency and boundary gates pass.

## Verification

```bash
find .github -maxdepth 3 -print | sort
git ls-files '.github/workflows/*'
python3 - <<'PY'
import pathlib, re, sys, urllib.parse
files = [
    pathlib.Path('agents-only/README.md'),
    pathlib.Path('agents-only/init.md'),
    pathlib.Path('agents-only/workpackage_latest.md'),
    pathlib.Path('agents-only/06-scripts/README.md'),
    pathlib.Path('.github/README.md'),
]
bad = []
for p in files:
    text = p.read_text(encoding='utf-8')
    for m in re.finditer(r'\[[^\]]+\]\(([^)]+)\)', text):
        target = m.group(1).split('#', 1)[0]
        if not target or re.match(r'^[a-z]+:', target):
            continue
        if not (p.parent / urllib.parse.unquote(target)).resolve().exists():
            bad.append((str(p), m.group(1)))
if bad:
    print(bad)
    sys.exit(1)
print('entry links ok')
PY
bash -lc 'while IFS= read -r file; do case "$(head -n 1 "$file")" in *zsh*) zsh -n "$file" ;; *) bash -n "$file" ;; esac; done < <(find agents-only -name "*.sh" -type f | sort)'
python3 -m py_compile agents-only/a42_historical_projection_spike/adapt_historical_round.py agents-only/archive/MT-GUI/mt_gui_02_evidence/mock_public_infra.py
python3 - <<'PY'
import json, pathlib, sys
allowed_empty = {pathlib.Path('agents-only/mt_real_01_evidence/phase3_runtime/logs_endpoint.json')}
bad = []
for p in sorted(pathlib.Path('agents-only').rglob('*.json')):
    if p in allowed_empty and p.stat().st_size == 0:
        continue
    try:
        json.loads(p.read_text(encoding='utf-8'))
    except Exception as e:
        bad.append((str(p), str(e)))
if bad:
    print(bad)
    sys.exit(1)
print('json ok with documented empty endpoint capture exception')
PY
python3 - <<'PY'
import pathlib, sys, yaml
bad = []
for p in sorted(pathlib.Path('agents-only').rglob('*.yml')) + sorted(pathlib.Path('agents-only').rglob('*.yaml')):
    try:
        yaml.safe_load(p.read_text(encoding='utf-8'))
    except Exception as e:
        bad.append((str(p), str(e)))
if bad:
    print(bad)
    sys.exit(1)
print('yaml ok')
PY
./agents-only/06-scripts/verify-consistency.sh
./agents-only/06-scripts/check-boundaries.sh
git diff --check
```
