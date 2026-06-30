<!-- tier: B -->
# .claude Release Acceptance

Date: 2026-06-30
Scope: `.claude/`

## Result

`.claude/` is release-accepted as **local ignored tooling state** and is intentionally kept
outside git.

## Directory Review

Tracked status:

- No `.claude/` files were tracked by git.
- `.gitignore` explicitly ignores `.claude/` under the Claude Code tooling section.

Files reviewed:

- `.claude/settings.local.json`
- `.claude/agents/parallel-task-executor.md`
- `.claude/plans/fix04-reality-fingerprint.md`

## Findings

- `settings.local.json` was a local permission whitelist, not shared release config. It included
  broad historical allowances such as `git push:*`, `git checkout:*`, `git stash:*`, `python3:*`,
  and stale project paths.
- `parallel-task-executor.md` was a Claude local subagent prompt. It duplicated local agent
  behavior and was not referenced by repo tooling.
- `fix04-reality-fingerprint.md` was an old REALITY FIX-04 implementation plan. Its content is
  superseded by the committed REALITY A1/T3 evidence and current governance in `active_context.md`
  plus `labs/interop-lab/docs/dual_kernel_golden_spec.md`.

## Disposition

Keep `.claude/` local and ignored. Do not commit its contents. Keep `.gitignore` unchanged so
future Claude local state stays outside the release tree.

## Verification

Commands run:

```bash
find .claude -maxdepth 5 -print
git ls-files .claude
git check-ignore -v .claude .claude/* .claude/*/*
rg -n "\\.claude|parallel-task-executor|fix04-reality-fingerprint|settings\\.local\\.json" \
  . .gitignore --glob '!target/**' --glob '!go_fork_source/**' --glob '!GUI_fork_source/**' \
  --glob '!agents-only/archive/**' --glob '!agents-only/log.md'
test -f .claude/settings.local.json
test -f .claude/agents/parallel-task-executor.md
test -f .claude/plans/fix04-reality-fingerprint.md
./agents-only/06-scripts/verify-consistency.sh
git diff --check
git status --short --branch
```

All checks passed. `git status` stays clean with `.claude/` present because `.claude/` is ignored
and untracked.

## Non-claims

This is local tooling hygiene only. It does not claim product behavior change, release packaging
completion, workflow automation, REALITY closure movement, or dual-kernel BHV/parity movement.
