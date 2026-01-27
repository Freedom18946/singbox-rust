#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-docs}"

if [[ ! -d "$ROOT" ]]; then
  echo "error: directory not found: $ROOT" >&2
  exit 2
fi

ROOT="$ROOT" python - <<'PY'
import os, re, sys
root = os.environ.get('ROOT', 'docs')
link_re = re.compile(r'\[[^\]]*\]\(([^)]+)\)')
missing = set()
for dirpath, _, filenames in os.walk(root):
    for fn in filenames:
        if not fn.endswith('.md'):
            continue
        path = os.path.join(dirpath, fn)
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
        for m in link_re.finditer(text):
            target = m.group(1).strip()
            if target.startswith(('http', '#', 'mailto:')):
                continue
            target = target.split('#', 1)[0]
            if not target:
                continue
            if target.startswith('/'):
                tpath = target.lstrip('/')
            else:
                tpath = os.path.normpath(os.path.join(dirpath, target))
            if os.path.isdir(tpath):
                if os.path.exists(os.path.join(tpath, 'README.md')):
                    continue
            if not os.path.exists(tpath):
                missing.add((path, target))

if missing:
    print(f"MISSING LINKS: {len(missing)}")
    for p, t in sorted(missing):
        print(f"{p}: {t}")
    sys.exit(1)
print("OK: no missing links")
PY
