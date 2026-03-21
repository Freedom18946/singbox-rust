# Environment Variables

This page documents the environment variables that are stable and relevant to the current user-facing CLI.

## Core Runtime

| Variable | Purpose |
| --- | --- |
| `RUST_LOG` | Standard Rust log filter |
| `SB_LOG_LEVEL` | Alternative log-level override |
| `SB_LOG_FORMAT` | Log format override |
| `SB_PRINT_ENV` | Print environment snapshot at startup |
| `SB_HARDEN` | Enable hardened mode |
| `HEALTH` | Enable outbound health task when set to `1` |

## `run` Command Fallbacks

| Variable | Equivalent flag |
| --- | --- |
| `ADMIN_LISTEN` | `--admin-listen` |
| `ADMIN_TOKEN` | `--admin-token` |

These are the only admin-related environment variables that the current `app run` CLI advertises as flag fallbacks.

## Internal / Debug Admin Variables

Some lower-level admin and debug components still use `SB_*` variables such as `SB_ADMIN_TOKEN`. Those variables are not the primary launch contract for `app run`, and the live docs prefer the `ADMIN_*` interface above.
