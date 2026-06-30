# .e2e Release Acceptance

Date: 2026-06-30
Scope: `.e2e/` artifact tree and directly associated `scripts/e2e/` entrypoints.

## Verdict

PASS-LOCAL for repository hygiene and local E2E artifact handling.

This is a scripts/artifact-tree acceptance pass only. It does not claim REALITY movement,
dual-kernel BHV/parity movement, workflow automation, release packaging completion, or
external Go-vs-Rust parity closure.

## Findings Fixed

- `scripts/e2e/run.sh`, `scripts/e2e/clean.sh`, and `scripts/e2e/diff.sh` resolved the
  project root as `scripts/`, so they wrote/read `scripts/.e2e` or `scripts/target`
  instead of the repository root.
- `scripts/e2e/clean.sh` used GNU `find -printf` for `--keep-last` and smart report
  pruning; this is not portable to macOS BSD `find`.
- `scripts/e2e/clean.sh --dry-run` did not announce dry-run mode on early-exit paths
  such as `--keep-last` and `--older-than`.
- `.e2e/.gitignore` and `.e2e/README.md` documented `pids/.gitkeep` and
  `soak/.gitkeep`, but those tracked directory anchors were absent.
- `scripts/e2e/udp/shadowsocks.sh` used a zsh shebang but referenced `BASH_SOURCE` in
  its entrypoint guard; under `set -u`, sourcing or running the file could fail before
  the test body.

## Changes

- Root discovery now resolves to the repository root for the main E2E runner, cleaner,
  diff reporter, and Shadowsocks UDP probe.
- `.e2e/pids/.gitkeep` and `.e2e/soak/.gitkeep` anchor the documented runtime
  directories.
- `clean.sh` now creates the full `.e2e` directory structure, uses a Python stdlib
  helper for oldest-file selection, and avoids the previous unsafe `eval find` helper.
- Dry-run messaging now covers early-exit cleanup modes.
- Documentation now reflects the tracked `.gitkeep` anchors and the `soak/` artifact
  directory.

## Verification

```bash
bash -n scripts/e2e/run.sh scripts/e2e/clean.sh scripts/e2e/diff.sh
while IFS= read -r file; do
  case "$(head -n 1 "$file")" in
    *zsh*) zsh -n "$file" ;;
    *bash*) bash -n "$file" ;;
  esac
done < <(find scripts/e2e -name '*.sh' -type f | sort)
zsh -n scripts/e2e/udp/shadowsocks.sh
zsh -c 'source scripts/e2e/udp/shadowsocks.sh'
scripts/e2e/clean.sh --dry-run --verbose
scripts/e2e/clean.sh --smart --dry-run --verbose
scripts/e2e/clean.sh --keep-last 1 --dry-run --verbose
scripts/e2e/clean.sh --older-than 9999d --dry-run --verbose
cargo run -q -p app -- check --config .e2e/config.yaml
scripts/e2e/diff.sh
./agents-only/06-scripts/verify-consistency.sh
make boundaries
git diff --check
```

`scripts/e2e/diff.sh` returned the expected local-disabled result because
`GO_SINGBOX_BIN` was not set; it created `target/e2e-diff` under the repository root and
did not create `scripts/target`.
