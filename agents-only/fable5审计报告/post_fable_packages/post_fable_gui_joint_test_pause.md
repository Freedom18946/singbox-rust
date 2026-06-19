<!-- tier: B -->
# post_fable_gui_joint_test_pause

Date: 2026-06-19.

## Decision

Real Wails/GUI joint testing is paused indefinitely. package07 remains PARTIAL,
and package20/testability-bridge work is not to be opened unless the user
explicitly resumes this line.

The immediate operating goal is to keep the user's installed macOS
GUI.for.SingBox app on its intended kernel and current profile/config, without
repository-built Wails artifacts or seeded automation data influencing manual
testing.

## Local Cleanup

Moved repository-generated Wails artifacts out of the repo:

```text
GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin
GUI_fork_source/GUI.for.SingBox-1.19.0/frontend/dist
```

Temporary holding location:

```text
/tmp/20260619_gui_joint_pause_cleanup
```

The persistent GUI fork source files under `build/` were left intact. The
frontend `node_modules/` dependency tree was also left intact because it is not
a built app bundle and does not affect the installed GUI app's runtime state.

## App Support Hygiene

Checked the current macOS App Support state at:

```text
/Users/bob/Library/Application Support/GUI.for.SingBox
```

No PF18/PF19 seeded profile markers, local-origin URL, repository path marker,
or Rust `target/debug/app` marker were found in:

```text
profiles.yaml
user.yaml
sing-box/config.json
```

Current observed kernels are Go sing-box binaries, not the Rust test binary:

```text
sing-box        -> sing-box version 1.13.13
sing-box-latest -> sing-box version 1.14.0-alpha.32
```

Because the current profile/config appears to be the user's real GUI state, no
App Support files were overwritten or deleted.

## Verification

Local checks after cleanup:

```text
find GUI_fork_source/GUI.for.SingBox-1.19.0 -maxdepth 3 \( -path '*/build/bin' -o -path '*/frontend/dist' \) -print
```

returned no paths.

```text
rg -n "PF1[89]|pf1[89]|Local Direct|18080|target/debug/app|singbox-rust" \
  "$HOME/Library/Application Support/GUI.for.SingBox/profiles.yaml" \
  "$HOME/Library/Application Support/GUI.for.SingBox/user.yaml" \
  "$HOME/Library/Application Support/GUI.for.SingBox/sing-box/config.json"
```

returned no matches.

```text
lsof -nP -iTCP:20122 -iTCP:20123 -sTCP:LISTEN
```

returned no listeners at cleanup time.

## Next Step

Wait for the user to manually test the installed macOS GUI.for.SingBox app. Do
not restart GUI automation, rebuild the Wails app, seed App Support, or promote
package07 until the user gives a new explicit direction.
