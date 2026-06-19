<!-- tier: B -->
# P1313-12 GUI 1.25.1 Low-Priority Contract

Priority: P2

Primary evidence:

- `GUI_fork_source/GUI.for.SingBox-1.25.1/UPGRADE_1.19.0_TO_1.25.1.md`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/frontend/src/api/kernel.ts`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/frontend/src/stores/kernelApi.ts`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/frontend/src/utils/generator.ts`
- `agents-only/fable5审计报告/post_fable_packages/README.md`

## Goal

Keep GUI 1.25.1 compatibility shape current through fixtures and local API probes while
real Wails/desktop joint testing remains paused.

## Current Gap

The GUI upgrade report shows process, log-file, system proxy, WebSocket, delay timeout, and
generated-config changes. However post-FABLE package07 is explicitly paused indefinitely, so
desktop automation should not resume.

## Task Split

1. Kernel launch contract fixture.
   - Confirm Rust emits `sing-box started`.
   - Confirm log-file path behavior when stdout/stderr are redirected.
   - Confirm PID file lifecycle assumptions.
   - Test through a local script/harness, not Wails click automation.

2. Clash API base URL contract.
   - Host-only controller.
   - host:port controller.
   - bracketed IPv6 controller.
   - secret bearer propagation.

3. Lazy WebSocket channels.
   - Connect `/logs`, `/memory`, `/traffic`, `/connections` independently.
   - Disconnect one channel while others stay active.
   - Reconnect after destroy/init sequence.

4. System proxy endpoint shape.
   - Mixed preferred over HTTP over SOCKS.
   - `schema`, `host`, `port`, `username`, `password`, `proxyType`.
   - Auth with colon in password.
   - Listen host normalization for loopback and wildcard.

5. Generated config golden set.
   - Default profile.
   - TUN enabled/disabled.
   - Selector/urltest/default outbound ids.
   - `icon`/`hidden` fields.
   - cache_file with `store_rdrc` omitted.
   - DNS fakeip/local/remote shapes.
   - Route rules for sniff/hijack/clash modes/rule sets.

6. Documentation.
   - Record that this is GUI shape validation only.
   - Keep package07/desktop automation paused.

## Acceptance

- Golden fixtures pass Rust production config check.
- Local API shape probe passes against an app instance built with `gui_runtime` or `parity`.
- No Wails automation commands are run unless the user resumes GUI joint testing.

## Non-Goals

- No desktop click automation.
- No root TUN dataplane proof.
- No GUI readiness claim.
