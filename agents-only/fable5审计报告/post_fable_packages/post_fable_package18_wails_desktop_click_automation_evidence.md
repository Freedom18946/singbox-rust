<!-- tier: B -->
# post_fable_package18_wails_desktop_click_automation_evidence

Date: 2026-06-17.

Artifact root:

```bash
/tmp/pf18_wails_click_automation
```

## Latest Result

`/tmp/pf18_wails_click_automation/result.json`:

```json
{
  "status": "BLOCKED_STOP",
  "message": "GUI Stop did not stop the core or release ports",
  "drive_method": "computer_use_mcp",
  "gui_pid": "73110",
  "core_pid": "76539"
}
```

Important nuance: Start reached `native_sent` in the latest full package18
script run; the run is still not a package07 PASS because Stop did not complete
through GUI automation.

## Stage Summary

Observed `result.json.stages` highlights:

| Stage | Result |
|---|---|
| AX precheck | `pass` |
| Preexisting GUI process check | `none` |
| cargo build | `pass` |
| Wails build | `pass` |
| App Support backup | `pass` |
| Controlled seed | `pass` |
| Wails launch | `open_invoked` |
| Desktop window | `external_confirmed` |
| Profile/start visible | `external_confirmed` |
| Start click | `native_sent` |
| Core started | `pid_config_ports_present` |
| Clash API | `pass` |
| GUI running view | `pass` |
| Loopback proxy traffic | `pass` |
| Stop click | `native_attempted_waiting_external` |
| Stop cleanup | `failed` |
| Trap cleanup/restore | App Support restored, ports closed |

## Key Evidence Files

- `result.json` — final machine-readable status.
- `seed_user.yaml`, `seed_profiles.yaml` — controlled GUI data seed.
- `screenshot_launch.png`, `screenshot_before_start_click.png`,
  `screenshot_after_start.png` — real Wails window evidence.
- `external_window_seen.txt`, `external_profile_seen.txt` — computer-use visible
  window/profile confirmations.
- `pid.txt` — GUI-owned Rust core pid.
- `generated_config.json` — GUI-generated config.
- `core_command.txt` — GUI launch command pointing to the app bundle data path.
- `clash_configs.json`, `clash_proxies.json` — Bearer `pf18probe` API responses.
- `curl_status.txt`, `curl_body.txt`, `curl_err.txt` — loopback proxy traffic
  evidence; status was `200`, body was `pf18 origin ok`.
- `stop_click.log` — Stop attempt evidence.

## Generated Config Checks

The GUI-generated config contained:

- mixed inbound `127.0.0.1:20122`;
- Clash API `127.0.0.1:20123`, secret `pf18probe`;
- `external_ui_download_detour: "pf18-direct"`;
- direct route lowered to outbound tag `pf18-direct`;
- TUN absent from active inbounds;
- local DNS server `pf18-dns-local`.

The seed was adjusted during implementation to avoid duplicate generated tags:
explicit direct/block outbounds use `pf18-direct` and `pf18-block`, while GUI
built-in direct/block entries keep their default `direct` and `block` tags.

## Core/API/Traffic Proof

`core_command.txt` showed the Wails-launched command:

```text
.../GUI.for.SingBox.app/Contents/MacOS/data/sing-box/sing-box run --disable-color -c .../data/sing-box/config.json -D .../data/sing-box
```

The `data` path is the Wails app support symlink created by the GUI bridge, so
the pid/config artifacts came from the real GUI runtime path.

The Clash API checks passed:

- `GET /configs` with `Authorization: Bearer pf18probe`;
- `GET /proxies` with `Authorization: Bearer pf18probe`.

Loopback HTTP through the GUI-started mixed proxy passed:

```text
curl status: 200
body: pf18 origin ok
```

## Stop Blocker

The running view appeared and exposed the Wails runtime dashboard. Native AX
click attempts did not resolve the Stop icon. `computer-use` could read and
raise the Wails window, but coordinate click calls returned `noWindowsAvailable`
for the full app path, and System Events coordinate click was blocked by macOS
assistive-access enforcement (`-25211`). Cleanup then killed the core and
restored App Support, so package18 ended as `BLOCKED_STOP`.

## Status Decision

package18 is DONE because the script, documentation, and evidence package now
reproduce and preserve the real Wails desktop attempt.

package07 remains PARTIAL because the full closure rule requires verified GUI
Start and GUI Stop without relying on cleanup for Stop.
