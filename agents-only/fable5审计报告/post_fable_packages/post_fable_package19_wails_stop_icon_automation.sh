#!/usr/bin/env bash
# post_fable_package19 - Wails Stop icon desktop automation.
#
# This script is intentionally evidence-first. package07 may only close when
# result.json status=PASS and cleanup did not stop the core.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GUI_DIR="$REPO/GUI_fork_source/GUI.for.SingBox-1.25.1"
APP_BUNDLE="$GUI_DIR/build/bin/GUI.for.SingBox.app"
APP_EXEC="$APP_BUNDLE/Contents/MacOS/GUI.for.SingBox"
KERNEL="${KERNEL:-$REPO/target/debug/app}"
WAILS="${WAILS:-$HOME/go/bin/wails}"
WORK="${WORK:-/tmp/pf19_wails_stop_icon_automation}"
APP_SUPPORT="$HOME/Library/Application Support/GUI.for.SingBox"
PROFILE_ID="pf19-local-direct"
PROFILE_NAME="PF19 Local Direct"
MIXED_PORT=20122
CLASH_PORT=20123
ORIGIN_PORT=18080
SECRET="pf19probe"
ASSIST_WAIT_SECONDS="${PF19_ASSIST_WAIT_SECONDS:-120}"
ALLOW_EXTERNAL_CLICK="${PF19_ALLOW_EXTERNAL_CLICK:-1}"
EXTERNAL_DRIVE_LABEL="${PF19_EXTERNAL_DRIVE_LABEL:-computer_use_mcp}"
SKIP_BUILD="${PF19_SKIP_BUILD:-0}"
SKIP_WAILS_BUILD="${PF19_SKIP_WAILS_BUILD:-0}"
STRICT_EXIT="${PF19_STRICT_EXIT:-0}"
EXTERNAL_WINDOW_SEEN_FILE="$WORK/external_window_seen.txt"
EXTERNAL_PROFILE_SEEN_FILE="$WORK/external_profile_seen.txt"
PF19_SWIFT_HELPER_READY=0

rm -rf "$WORK"
mkdir -p "$WORK"

STAGES="$WORK/stages.log"
META="$WORK/meta.log"
ARTIFACTS="$WORK/artifacts.log"
STATUS_FILE="$WORK/status.txt"
MESSAGE_FILE="$WORK/message.txt"
ORIGIN_PID_FILE="$WORK/origin.pid"
GUI_PID_FILE="$WORK/gui.pid"
CORE_PID_FILE="$WORK/core.pid"
APP_SUPPORT_EXISTED_FILE="$WORK/app_support_existed.txt"
BACKUP_DIR="$WORK/app_support_backup"

: >"$STAGES"
: >"$META"
: >"$ARTIFACTS"
echo "FAILED_INTERNAL" >"$STATUS_FILE"
echo "script did not finish" >"$MESSAGE_FILE"

log() { printf '[pf19] %s\n' "$*" | tee -a "$WORK/attempt.log"; }
stage() { printf '%s=%s\n' "$1" "$2" >>"$STAGES"; }
meta() { printf '%s=%s\n' "$1" "$2" >>"$META"; }
artifact() { printf '%s=%s\n' "$1" "$2" >>"$ARTIFACTS"; }
set_status() { echo "$1" >"$STATUS_FILE"; echo "$2" >"$MESSAGE_FILE"; }

port_open() {
  nc -z 127.0.0.1 "$1" >/dev/null 2>&1
}

wait_port_closed() {
  port="$1"
  for _ in $(seq 1 50); do
    if ! port_open "$port"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

copy_if_exists() {
  src="$1"
  dst="$2"
  if [ -e "$src" ]; then
    cp -p "$src" "$WORK/$dst" 2>/dev/null || cp "$src" "$WORK/$dst" 2>/dev/null || true
    artifact "${dst%.*}" "$dst"
  fi
}

write_result() {
  exit_code="$1"
  python3 - "$WORK" "$exit_code" <<'PY'
import json
import os
import sys

work = sys.argv[1]
exit_code = int(sys.argv[2])

def read_text(name, default=""):
    try:
        with open(os.path.join(work, name), "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return default

def read_kv_log(name):
    out = {}
    path = os.path.join(work, name)
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            out[key] = value
    return out

artifacts = read_kv_log("artifacts.log")
for filename in [
    "attempt.log",
    "ax_precheck.txt",
    "preexisting_gui_processes.txt",
    "cargo_build_gui_runtime.log",
    "wails_build_goproxy_cn.log",
    "open.log",
    "ui_tree_launch.txt",
    "ui_tree_launch.txt.err",
    "ui_tree_before_start_click.txt",
    "ui_tree_before_start_click.txt.err",
    "ui_tree_after_start.txt",
    "ui_tree_after_stop.txt",
    "ui_tree_log_modal.txt",
    "screenshot_launch.png",
    "screenshot_launch_analysis.json",
    "launch_window_geometry.log",
    "launch_window_geometry.err",
    "screenshot_before_start_click.png",
    "screenshot_before_start_click_analysis.json",
    "screenshot_after_start.png",
    "screenshot_before_stop.png",
    "screenshot_after_stop.png",
    "swift_helper_build.log",
    "window_bounds.json",
    "stop_toolbar_candidates.json",
    "stop_coordinates.json",
    "stop_geometry.log",
    "stop_geometry.err",
    "stop_crop_region.txt",
    "stop_toolbar_before.png",
    "stop_toolbar_after.png",
    "stop_click_axpress.log",
    "stop_click_computer_use.log",
    "stop_click_swift.log",
    "stop_click_cliclick.log",
    "stop_click_system_events.log",
    "start_click.log",
    "stop_click.log",
    "generated_config.json",
    "pid.txt",
    "core_command.txt",
    "clash_configs.json",
    "clash_proxies.json",
    "curl_status.txt",
    "curl_body.txt",
    "curl_err.txt",
]:
    if os.path.exists(os.path.join(work, filename)):
        artifacts.setdefault(filename.replace(".", "_"), filename)

result = {
    "status": read_text("status.txt", "FAILED_INTERNAL"),
    "message": read_text("message.txt", "script did not finish"),
    "exit_code": exit_code,
    "work": work,
    "repo": read_kv_log("meta.log").get("repo"),
    "app": read_kv_log("meta.log").get("app"),
    "app_executable": read_kv_log("meta.log").get("app_executable"),
    "app_support": read_kv_log("meta.log").get("app_support"),
    "profile": read_kv_log("meta.log").get("profile"),
    "drive_method": read_kv_log("meta.log").get("drive_method", "native"),
    "gui_pid": read_text("gui.pid", None),
    "core_pid": read_text("core.pid", None),
    "stop_event_sent": read_kv_log("meta.log").get("stop_event_sent", "false") == "true",
    "stop_backend": read_kv_log("meta.log").get("stop_backend"),
    "stop_coordinates": read_kv_log("meta.log").get("stop_coordinates"),
    "stop_core_exited_pre_cleanup": read_kv_log("meta.log").get("stop_core_exited_pre_cleanup", "false") == "true",
    "stop_ports_released_pre_cleanup": read_kv_log("meta.log").get("stop_ports_released_pre_cleanup", "false") == "true",
    "cleanup_killed_core": read_kv_log("meta.log").get("cleanup_killed_core", "false") == "true",
    "cleanup_killed_gui": read_kv_log("meta.log").get("cleanup_killed_gui", "false") == "true",
    "package07_closure_eligible": read_kv_log("meta.log").get("package07_closure_eligible", "false") == "true",
    "stages": read_kv_log("stages.log"),
    "artifacts": artifacts,
}
with open(os.path.join(work, "result.json"), "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

cleanup() {
  log "cleanup starting"
  cleanup_killed_core=false
  cleanup_killed_gui=false
  if [ -f "$CORE_PID_FILE" ]; then
    core_pid="$(cat "$CORE_PID_FILE" 2>/dev/null || true)"
    if [ -n "${core_pid:-}" ] && kill -0 "$core_pid" >/dev/null 2>&1; then
      cleanup_killed_core=true
      kill -INT "$core_pid" >/dev/null 2>&1 || true
      for _ in $(seq 1 30); do
        kill -0 "$core_pid" >/dev/null 2>&1 || break
        sleep 0.2
      done
      kill -0 "$core_pid" >/dev/null 2>&1 && kill -9 "$core_pid" >/dev/null 2>&1 || true
    fi
  fi
  if [ -f "$GUI_PID_FILE" ]; then
    gui_pid="$(cat "$GUI_PID_FILE" 2>/dev/null || true)"
    if [ -n "${gui_pid:-}" ] && kill -0 "$gui_pid" >/dev/null 2>&1; then
      cleanup_killed_gui=true
      kill "$gui_pid" >/dev/null 2>&1 || true
      for _ in $(seq 1 30); do
        kill -0 "$gui_pid" >/dev/null 2>&1 || break
        sleep 0.2
      done
      kill -0 "$gui_pid" >/dev/null 2>&1 && kill -9 "$gui_pid" >/dev/null 2>&1 || true
    fi
  fi
  if [ -f "$ORIGIN_PID_FILE" ]; then
    origin_pid="$(cat "$ORIGIN_PID_FILE" 2>/dev/null || true)"
    [ -n "${origin_pid:-}" ] && kill "$origin_pid" >/dev/null 2>&1 || true
  fi

  if [ -f "$APP_SUPPORT_EXISTED_FILE" ]; then
    rm -rf "$APP_SUPPORT"
    if grep -q '^yes$' "$APP_SUPPORT_EXISTED_FILE" && [ -d "$BACKUP_DIR" ]; then
      mkdir -p "$(dirname "$APP_SUPPORT")"
      ditto "$BACKUP_DIR" "$APP_SUPPORT" >/dev/null 2>&1 || cp -R "$BACKUP_DIR" "$APP_SUPPORT"
      stage "cleanup_restore" "restored_app_support"
    else
      stage "cleanup_restore" "removed_seeded_app_support"
    fi
  else
    stage "cleanup_restore" "not_started"
  fi
  wait_port_closed "$MIXED_PORT" && stage "mixed_port_after_cleanup" "closed" || stage "mixed_port_after_cleanup" "still_open"
  wait_port_closed "$CLASH_PORT" && stage "clash_port_after_cleanup" "closed" || stage "clash_port_after_cleanup" "still_open"
  meta "cleanup_killed_core" "$cleanup_killed_core"
  meta "cleanup_killed_gui" "$cleanup_killed_gui"
  log "cleanup complete"
}

finish() {
  rc="$1"
  trap - EXIT
  cleanup
  write_result "$rc"
  status="$(cat "$STATUS_FILE")"
  log "result status=$status work=$WORK/result.json"
  if [ "$STRICT_EXIT" = "1" ] && [ "$status" != "PASS" ]; then
    exit 1
  fi
  case "$status" in
    FAILED_INTERNAL) exit 1 ;;
    *) exit 0 ;;
  esac
}

trap 'finish $?' EXIT

dump_ax_tree() {
  out="$1"
  pid="$(current_gui_pid)"
  [ -n "$pid" ] || return 1
  osascript - "$pid" >"$out" 2>"$out.err" <<'APPLESCRIPT'
on safeName(e)
  try
    return name of e as text
  on error
    return ""
  end try
end safeName

on safeValue(e)
  try
    return value of e as text
  on error
    return ""
  end try
end safeValue

on safeDescription(e)
  try
    return description of e as text
  on error
    return ""
  end try
end safeDescription

on safeRole(e)
  try
    return role of e as text
  on error
    return ""
  end try
end safeRole

on safePosition(e)
  try
    set p to position of e
    return (item 1 of p as text) & "," & (item 2 of p as text)
  on error
    return ""
  end try
end safePosition

on safeSize(e)
  try
    set s to size of e
    return (item 1 of s as text) & "x" & (item 2 of s as text)
  on error
    return ""
  end try
end safeSize

on run argv
  set targetPid to (item 1 of argv) as integer
  tell application "System Events"
    tell (first process whose unix id is targetPid)
      set frontmost to true
      set w to window 1
      set elems to entire contents of w
      set rows to {}
      try
        set end of rows to "raw_contents=" & (elems as text)
      on error errMsg number errNum
        set end of rows to "raw_contents_error=" & (errNum as text) & " " & errMsg
      end try
      repeat with i from 1 to count of elems
        try
          set e to item i of elems
          set lineText to "index=" & (i as text) & " role=" & my safeRole(e) & " name=" & my safeName(e) & " value=" & my safeValue(e) & " desc=" & my safeDescription(e) & " pos=" & my safePosition(e) & " size=" & my safeSize(e)
        on error errMsg number errNum
          set lineText to "index=" & (i as text) & " error=" & (errNum as text) & " " & errMsg
        end try
        set end of rows to lineText
      end repeat
      set oldDelimiters to AppleScript's text item delimiters
      set AppleScript's text item delimiters to linefeed
      set outputText to rows as text
      set AppleScript's text item delimiters to oldDelimiters
      return outputText
    end tell
  end tell
end run
APPLESCRIPT
  # Some macOS osascript builds put log lines in stderr only.
  if [ ! -s "$out" ] && [ -s "$out.err" ]; then
    cp "$out.err" "$out"
  fi
}

screenshot() {
  out="$1"
  screencapture -x "$out" >/dev/null 2>&1 || true
}

analyze_screenshot() {
  in_file="$1"
  out_file="$2"
  [ -s "$in_file" ] || return 1
  python3 - "$in_file" "$out_file" <<'PY'
import json
import sys
try:
    from PIL import Image
except Exception as exc:
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump({"image": sys.argv[1], "analysis_available": False, "error": str(exc)}, f, indent=2)
    raise SystemExit(0)

img = Image.open(sys.argv[1]).convert("RGB")
pixels = list(img.resize((64, 40)).getdata())
avg = sum(sum(p) for p in pixels) / (len(pixels) * 3)
nonblack = sum(1 for p in pixels if max(p) > 8)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({
        "image": sys.argv[1],
        "analysis_available": True,
        "sample_width": 64,
        "sample_height": 40,
        "average_rgb_channel": avg,
        "nonblack_sample_pixels": nonblack,
        "mostly_black": nonblack < 16,
    }, f, indent=2, sort_keys=True)
PY
}

current_gui_pid() {
  if [ -s "$GUI_PID_FILE" ]; then
    cat "$GUI_PID_FILE"
  else
    pgrep -x "GUI.for.SingBox" | tail -n 1 || true
  fi
}

gui_window_count() {
  pid="$1"
  osascript - "$pid" 2>/dev/null <<'APPLESCRIPT'
on run argv
  set targetPid to (item 1 of argv) as integer
  tell application "System Events"
    tell (first process whose unix id is targetPid)
      return count windows
    end tell
  end tell
end run
APPLESCRIPT
}

activate_window() {
  pid="$(current_gui_pid)"
  [ -n "$pid" ] || return 1
  osascript - "$pid" >/dev/null 2>>"$WORK/activate_window.err" <<'APPLESCRIPT'
on run argv
  set targetPid to (item 1 of argv) as integer
  tell application "System Events"
    tell (first process whose unix id is targetPid)
      set frontmost to true
      delay 0.2
      try
        perform action "AXRaise" of window 1
      end try
    end tell
  end tell
end run
APPLESCRIPT
}

ax_press_text() {
  target="$1"
  log_file="$2"
  pid="$(current_gui_pid)"
  [ -n "$pid" ] || return 1
  osascript - "$target" "$pid" >"$log_file" 2>&1 <<'APPLESCRIPT'
on safeText(e)
  set parts to {}
  try
    set end of parts to name of e as text
  end try
  try
    set end of parts to value of e as text
  end try
  try
    set end of parts to description of e as text
  end try
  return parts as text
end safeText

on tryPress(e)
  set cur to e
  repeat 8 times
    try
      perform action "AXPress" of cur
      return "AXPress " & (role of cur as text) & " " & (cur as text)
    end try
    try
      click cur
      return "click " & (role of cur as text) & " " & (cur as text)
    end try
    try
      set cur to parent of cur
    on error
      exit repeat
    end try
  end repeat
  return ""
end tryPress

on run argv
  set target to item 1 of argv
  set targetPid to (item 2 of argv) as integer
  tell application "System Events"
    tell (first process whose unix id is targetPid)
      set frontmost to true
      set w to window 1
      set elems to entire contents of w
      repeat with e in elems
        if my safeText(e) contains target then
          set r to my tryPress(e)
          if r is not "" then
            return "pressed target '" & target & "' via " & r
          end if
        end if
      end repeat
    end tell
  end tell
  error "target not pressable: " & target
end run
APPLESCRIPT
}

ax_center_for_text() {
  target="$1"
  pid="$(current_gui_pid)"
  [ -n "$pid" ] || return 1
  osascript - "$target" "$pid" 2>/dev/null <<'APPLESCRIPT'
on safeText(e)
  set parts to {}
  try
    set end of parts to name of e as text
  end try
  try
    set end of parts to value of e as text
  end try
  try
    set end of parts to description of e as text
  end try
  return parts as text
end safeText

on hasSize(e)
  try
    set s to size of e
    if (item 1 of s) > 2 and (item 2 of s) > 2 then return true
  end try
  return false
end hasSize

on roleOf(e)
  try
    return role of e as text
  on error
    return ""
  end try
end roleOf

on bestPressableAncestor(e)
  set cur to e
  set best to e
  repeat 8 times
    try
      if my hasSize(cur) then set best to cur
      set r to my roleOf(cur)
      if r contains "button" or r contains "group" then
        if my hasSize(cur) then return cur
      end if
      set cur to parent of cur
    on error
      exit repeat
    end try
  end repeat
  return best
end bestPressableAncestor

on run argv
  set target to item 1 of argv
  set targetPid to (item 2 of argv) as integer
  tell application "System Events"
    tell (first process whose unix id is targetPid)
      set frontmost to true
      set w to window 1
      set elems to entire contents of w
      repeat with e in elems
        if my safeText(e) contains target then
          set b to my bestPressableAncestor(e)
          set p to position of b
          set s to size of b
          set x to (item 1 of p) + ((item 1 of s) / 2)
          set y to (item 2 of p) + ((item 2 of s) / 2)
          return (x as integer as text) & " " & (y as integer as text) & " " & (item 1 of s as integer as text) & " " & (item 2 of s as integer as text)
        end if
      end repeat
    end tell
  end tell
  error "target not found: " & target
end run
APPLESCRIPT
}

click_xy() {
  x="$1"
  y="$2"
  label="$3"
  log_file="$4"
  if python3 - "$x" "$y" >"$log_file" 2>&1 <<'PY'
import sys
import time
try:
    import Quartz
except Exception as exc:
    print(f"Quartz unavailable: {exc}")
    raise SystemExit(2)
x = float(sys.argv[1])
y = float(sys.argv[2])
for event_type in (Quartz.kCGEventMouseMoved, Quartz.kCGEventLeftMouseDown, Quartz.kCGEventLeftMouseUp):
    event = Quartz.CGEventCreateMouseEvent(None, event_type, (x, y), Quartz.kCGMouseButtonLeft)
    Quartz.CGEventPost(Quartz.kCGHIDEventTap, event)
    time.sleep(0.08)
print(f"clicked {x},{y}")
PY
  then
    echo "clicked $label via Quartz at $x,$y" >>"$log_file"
    return 0
  fi
  if command -v cliclick >/dev/null 2>&1; then
    cliclick c:"$x","$y" >>"$log_file" 2>&1 && return 0
  fi
  osascript -e "tell application \"System Events\" to click at {$x,$y}" >>"$log_file" 2>&1
}

swift_helper_bin() {
  printf '%s\n' "/tmp/pf19_wails_stop_helper"
}

ensure_swift_helper() {
  helper="$(swift_helper_bin)"
  if [ "$PF19_SWIFT_HELPER_READY" = "1" ] && [ -x "$helper" ]; then
    return 0
  fi
  src="/tmp/pf19_wails_stop_helper.swift"
  cat >"$src" <<'SWIFT'
import AppKit
import ApplicationServices
import Foundation

func die(_ message: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(code)
}

func axValue(_ element: AXUIElement, _ attr: CFString) -> AnyObject? {
    var value: AnyObject?
    let err = AXUIElementCopyAttributeValue(element, attr, &value)
    return err == .success ? value : nil
}

func axString(_ element: AXUIElement, _ attr: CFString) -> String {
    if let value = axValue(element, attr) {
        return String(describing: value)
    }
    return ""
}

func axPoint(_ element: AXUIElement) -> CGPoint? {
    guard let value = axValue(element, kAXPositionAttribute as CFString) else { return nil }
    if CFGetTypeID(value) != AXValueGetTypeID() { return nil }
    var point = CGPoint.zero
    if AXValueGetValue(value as! AXValue, .cgPoint, &point) {
        return point
    }
    return nil
}

func axSize(_ element: AXUIElement) -> CGSize? {
    guard let value = axValue(element, kAXSizeAttribute as CFString) else { return nil }
    if CFGetTypeID(value) != AXValueGetTypeID() { return nil }
    var size = CGSize.zero
    if AXValueGetValue(value as! AXValue, .cgSize, &size) {
        return size
    }
    return nil
}

func firstAXWindow(_ pid: pid_t) -> AXUIElement? {
    let app = AXUIElementCreateApplication(pid)
    guard let windows = axValue(app, kAXWindowsAttribute as CFString) as? [AXUIElement], !windows.isEmpty else {
        return nil
    }
    return windows[0]
}

func axWindowRect(_ pid: pid_t) -> CGRect? {
    guard let window = firstAXWindow(pid), let point = axPoint(window), let size = axSize(window) else {
        return nil
    }
    return CGRect(origin: point, size: size)
}

func cgWindowRect(_ pid: pid_t) -> CGRect? {
    guard let windows = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] else {
        return nil
    }
    var best: CGRect?
    var bestArea: CGFloat = 0
    for window in windows {
        guard let owner = window[kCGWindowOwnerPID as String] as? Int, owner == Int(pid) else { continue }
        if let layer = window[kCGWindowLayer as String] as? Int, layer != 0 { continue }
        if let onscreen = window[kCGWindowIsOnscreen as String] as? Int, onscreen == 0 { continue }
        guard let bounds = window[kCGWindowBounds as String] as? [String: Any] else { continue }
        let x = bounds["X"] as? CGFloat ?? 0
        let y = bounds["Y"] as? CGFloat ?? 0
        let w = bounds["Width"] as? CGFloat ?? 0
        let h = bounds["Height"] as? CGFloat ?? 0
        if w > 100 && h > 100 {
            let rect = CGRect(x: x, y: y, width: w, height: h)
            let area = w * h
            if area > bestArea {
                best = rect
                bestArea = area
            }
        }
    }
    return best
}

func windowRect(_ pid: pid_t) -> (CGRect, String) {
    if let rect = axWindowRect(pid) {
        return (rect, "ax")
    }
    if let rect = cgWindowRect(pid) {
        return (rect, "cgwindow")
    }
    die("no window bounds for pid \(pid)", 44)
}

func writeJSON(_ object: Any, _ path: String) {
    do {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: path))
    } catch {
        die("write json failed for \(path): \(error)", 45)
    }
}

struct Candidate {
    let element: AXUIElement
    let role: String
    let name: String
    let value: String
    let desc: String
    let x: CGFloat
    let y: CGFloat
    let w: CGFloat
    let h: CGFloat

    func json(_ rank: Int) -> [String: Any] {
        [
            "rank": rank,
            "role": role,
            "name": name,
            "value": value,
            "description": desc,
            "x": Double(x),
            "y": Double(y),
            "width": Double(w),
            "height": Double(h),
            "center_x": Double(x + w / 2),
            "center_y": Double(y + h / 2)
        ]
    }
}

func children(_ element: AXUIElement) -> [AXUIElement] {
    return (axValue(element, kAXChildrenAttribute as CFString) as? [AXUIElement]) ?? []
}

func collectCandidates(_ element: AXUIElement, _ window: CGRect, _ out: inout [Candidate], _ depth: Int = 0) {
    if depth > 10 { return }
    if let point = axPoint(element), let size = axSize(element) {
        let role = axString(element, kAXRoleAttribute as CFString)
        let name = axString(element, kAXTitleAttribute as CFString)
        let value = axString(element, kAXValueAttribute as CFString)
        let desc = axString(element, kAXDescriptionAttribute as CFString)
        let small = size.width >= 6 && size.height >= 6 && size.width <= 90 && size.height <= 90
        let rightToolbar = point.x >= window.minX + window.width - 180
        let topToolbar = point.y >= window.minY + 45 && point.y <= window.minY + 125
        if small && rightToolbar && topToolbar {
            out.append(Candidate(element: element, role: role, name: name, value: value, desc: desc, x: point.x, y: point.y, w: size.width, h: size.height))
        }
    }
    for child in children(element) {
        collectCandidates(child, window, &out, depth + 1)
    }
}

func stopCandidates(_ pid: pid_t, _ window: CGRect) -> [Candidate] {
    guard let root = firstAXWindow(pid) else { return [] }
    var out: [Candidate] = []
    collectCandidates(root, window, &out)
    return out.sorted {
        if abs($0.x - $1.x) > 1 { return $0.x < $1.x }
        return $0.y < $1.y
    }
}

func writeGeometry(_ pid: pid_t, _ boundsPath: String, _ candidatesPath: String, _ coordsPath: String) -> (CGFloat, CGFloat, String, [Candidate]) {
    let (rect, boundsSource) = windowRect(pid)
    let candidates = stopCandidates(pid, rect)
    writeJSON([
        "pid": Int(pid),
        "source": boundsSource,
        "x": Double(rect.minX),
        "y": Double(rect.minY),
        "width": Double(rect.width),
        "height": Double(rect.height)
    ], boundsPath)
    writeJSON(candidates.enumerated().map { idx, item in item.json(idx + 1) }, candidatesPath)

    let source: String
    let x: CGFloat
    let y: CGFloat
    if let rightmost = candidates.last {
        source = "ax_rightmost_toolbar_candidate"
        x = rightmost.x + rightmost.w / 2
        y = rightmost.y + rightmost.h / 2
    } else {
        source = "window_relative_source_informed_fallback"
        x = rect.minX + rect.width - 40
        y = rect.minY + 88
    }
    writeJSON([
        "pid": Int(pid),
        "source": source,
        "x": Double(x),
        "y": Double(y),
        "window_x": Double(rect.minX),
        "window_y": Double(rect.minY),
        "window_width": Double(rect.width),
        "window_height": Double(rect.height),
        "source_note": "OverView.vue toolbar order is log, restart, stop; Stop is the rightmost small icon in the overview toolbar."
    ], coordsPath)
    return (x, y, source, candidates)
}

func raiseApp(_ pid: pid_t) {
    if let app = NSRunningApplication(processIdentifier: pid) {
        _ = app.activate(options: [.activateAllWindows])
    }
    if let window = firstAXWindow(pid) {
        AXUIElementPerformAction(window, kAXRaiseAction as CFString)
    }
    usleep(250_000)
}

func pressCandidate(_ candidate: Candidate) -> Bool {
    var current: AXUIElement? = candidate.element
    for _ in 0..<8 {
        guard let element = current else { break }
        if AXUIElementPerformAction(element, kAXPressAction as CFString) == .success {
            return true
        }
        if let parentValue = axValue(element, kAXParentAttribute as CFString) {
            current = (parentValue as! AXUIElement)
        } else {
            current = nil
        }
    }
    return false
}

func postClick(_ pid: pid_t, _ x: CGFloat, _ y: CGFloat) {
    raiseApp(pid)
    let point = CGPoint(x: x, y: y)
    for eventType in [CGEventType.mouseMoved, CGEventType.leftMouseDown, CGEventType.leftMouseUp] {
        guard let event = CGEvent(mouseEventSource: nil, mouseType: eventType, mouseCursorPosition: point, mouseButton: .left) else {
            die("CGEventCreateMouseEvent failed", 46)
        }
        event.post(tap: .cghidEventTap)
        usleep(80_000)
    }
}

let args = CommandLine.arguments
if args.count < 2 { die("usage: pf19_wails_stop_helper <command> ...", 2) }
let command = args[1]

if command == "stop-point" {
    if args.count != 6 { die("usage: stop-point <pid> <bounds.json> <candidates.json> <coords.json>", 2) }
    let pid = pid_t(Int32(args[2])!)
    let (x, y, source, _) = writeGeometry(pid, args[3], args[4], args[5])
    print("\(Int(round(x))) \(Int(round(y))) \(source)")
} else if command == "axpress-stop" {
    if args.count != 6 { die("usage: axpress-stop <pid> <bounds.json> <candidates.json> <coords.json>", 2) }
    let pid = pid_t(Int32(args[2])!)
    raiseApp(pid)
    let (x, y, source, candidates) = writeGeometry(pid, args[3], args[4], args[5])
    if let rightmost = candidates.last, pressCandidate(rightmost) {
        print("pressed \(Int(round(x))) \(Int(round(y))) \(source)")
    } else {
        die("AXPress stop candidate failed", 47)
    }
} else if command == "click" {
    if args.count != 5 { die("usage: click <pid> <x> <y>", 2) }
    let pid = pid_t(Int32(args[2])!)
    guard let x = Double(args[3]), let y = Double(args[4]) else { die("invalid coordinates", 2) }
    postClick(pid, CGFloat(x), CGFloat(y))
    print("clicked \(Int(round(x))) \(Int(round(y)))")
} else {
    die("unknown command: \(command)", 2)
}
SWIFT
  if command -v swiftc >/dev/null 2>&1; then
    swiftc "$src" -o "$helper" >"$WORK/swift_helper_build.log" 2>&1
  elif command -v xcrun >/dev/null 2>&1; then
    xcrun swiftc "$src" -o "$helper" >"$WORK/swift_helper_build.log" 2>&1
  else
    printf 'swiftc not found\n' >"$WORK/swift_helper_build.log"
    return 1
  fi
  artifact "swift_helper_build" "swift_helper_build.log"
  if [ -x "$helper" ]; then
    PF19_SWIFT_HELPER_READY=1
    return 0
  fi
  return 1
}

confirm_window_via_swift() {
  pid="$1"
  ensure_swift_helper || return 1
  "$(swift_helper_bin)" stop-point "$pid" "$WORK/window_bounds.json" "$WORK/stop_toolbar_candidates.json" "$WORK/stop_coordinates.json" >"$WORK/launch_window_geometry.log" 2>"$WORK/launch_window_geometry.err" || return 1
  artifact "launch_window_geometry" "launch_window_geometry.log"
  artifact "launch_window_geometry_err" "launch_window_geometry.err"
  artifact "window_bounds" "window_bounds.json"
  artifact "stop_toolbar_candidates" "stop_toolbar_candidates.json"
  artifact "stop_coordinates" "stop_coordinates.json"
  return 0
}

crop_stop_toolbar() {
  in_file="$1"
  out_file="$2"
  if [ ! -s "$WORK/stop_coordinates.json" ]; then
    return 1
  fi
  python3 - "$WORK/stop_coordinates.json" >"$WORK/stop_crop_region.txt" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    d = json.load(f)
x = max(0, int(round(float(d["x"]) - 95)))
y = max(0, int(round(float(d["y"]) - 35)))
print(f"{x},{y},140,75")
PY
  region="$(cat "$WORK/stop_crop_region.txt")"
  screencapture -x -R "$region" "$out_file" >/dev/null 2>&1 || cp "$in_file" "$out_file" 2>/dev/null || true
}

write_stop_geometry() {
  pid="$(current_gui_pid)"
  [ -n "$pid" ] || return 1
  ensure_swift_helper || return 1
  geometry_line="$("$(swift_helper_bin)" stop-point "$pid" "$WORK/window_bounds.json" "$WORK/stop_toolbar_candidates.json" "$WORK/stop_coordinates.json" 2>"$WORK/stop_geometry.err")" || return 1
  printf '%s\n' "$geometry_line" >"$WORK/stop_geometry.log"
  artifact "window_bounds" "window_bounds.json"
  artifact "stop_toolbar_candidates" "stop_toolbar_candidates.json"
  artifact "stop_coordinates" "stop_coordinates.json"
  artifact "stop_geometry" "stop_geometry.log"
  set -- $geometry_line
  STOP_X="$1"
  STOP_Y="$2"
  STOP_SOURCE="$3"
  meta "stop_coordinates" "$STOP_X,$STOP_Y,$STOP_SOURCE"
  return 0
}

ax_press_button_index() {
  idx="$1"
  log_file="$2"
  pid="$(current_gui_pid)"
  [ -n "$pid" ] || return 1
  osascript - "$idx" "$pid" >"$log_file" 2>&1 <<'APPLESCRIPT'
on run argv
  set idx to (item 1 of argv) as integer
  set targetPid to (item 2 of argv) as integer
  tell application "System Events"
    tell (first process whose unix id is targetPid)
      set frontmost to true
      perform action "AXPress" of button idx of window 1
      return "pressed button " & idx
    end tell
  end tell
end run
APPLESCRIPT
}

try_click_text() {
  target="$1"
  label="$2"
  log_file="$3"
  activate_window
  if ax_press_text "$target" "$log_file"; then
    meta "drive_method" "native_axpress"
    return 0
  fi
  center="$(ax_center_for_text "$target" || true)"
  if [ -n "$center" ]; then
    set -- $center
    if click_xy "$1" "$2" "$label" "$log_file"; then
      meta "drive_method" "native_coordinate"
      return 0
    fi
  fi
  return 1
}

preflight() {
  meta "repo" "$REPO"
  meta "app" "$APP_BUNDLE"
  meta "app_executable" "$APP_EXEC"
  meta "app_support" "$APP_SUPPORT"
  meta "profile" "$PROFILE_NAME"
  meta "drive_method" "native"
  stage "preflight" "running"
  uname -a >"$WORK/env_uname.txt" 2>&1 || true
  artifact "env_uname" "env_uname.txt"

  if [ "$(uname -s)" != "Darwin" ]; then
    stage "platform" "not_darwin"
    set_status "BLOCKED_UI_NOT_FOUND" "Wails desktop click automation requires macOS"
    finish 0
  fi
  for tool in python3 osascript screencapture curl nc pgrep ps ditto; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      stage "tool_$tool" "missing"
      set_status "FAILED_INTERNAL" "missing required tool: $tool"
      finish 1
    fi
  done

  osascript -e 'tell application "System Events" to UI elements enabled' >"$WORK/ax_precheck.txt" 2>&1
  artifact "ax_precheck" "ax_precheck.txt"
  if ! grep -q "true" "$WORK/ax_precheck.txt"; then
    stage "accessibility_precheck" "blocked"
    set_status "BLOCKED_ACCESSIBILITY" "System Events accessibility control is not enabled"
    finish 0
  fi
  stage "accessibility_precheck" "pass"

  pgrep -x "GUI.for.SingBox" >"$WORK/preexisting_gui_processes.txt" 2>/dev/null || true
  artifact "preexisting_gui_processes" "preexisting_gui_processes.txt"
  if [ -s "$WORK/preexisting_gui_processes.txt" ]; then
    stage "preexisting_gui_processes" "present"
    set_status "BLOCKED_PREEXISTING_GUI" "preexisting GUI.for.SingBox process is running"
    finish 0
  fi
  stage "preexisting_gui_processes" "none"
}

build_phase() {
  stage "build" "running"
  if [ "$SKIP_BUILD" != "1" ]; then
    (cd "$REPO" && cargo build -p app --bin app --features gui_runtime) >"$WORK/cargo_build_gui_runtime.log" 2>&1
    artifact "cargo_build_gui_runtime" "cargo_build_gui_runtime.log"
    if [ $? -ne 0 ]; then
      stage "cargo_build" "failed"
      set_status "BLOCKED_BUILD" "cargo build -p app --bin app --features gui_runtime failed"
      finish 0
    fi
  fi
  if [ ! -x "$KERNEL" ]; then
    stage "kernel_binary" "missing"
    set_status "BLOCKED_BUILD" "kernel binary missing or not executable: $KERNEL"
    finish 0
  fi
  stage "cargo_build" "pass"

  if [ "$SKIP_WAILS_BUILD" != "1" ]; then
    if [ ! -x "$WAILS" ]; then
      stage "wails_binary" "missing"
      set_status "BLOCKED_BUILD" "wails binary missing: $WAILS"
      finish 0
    fi
    (cd "$GUI_DIR" && GOPROXY=https://goproxy.cn,direct "$WAILS" build -clean) >"$WORK/wails_build_goproxy_cn.log" 2>&1
    artifact "wails_build_goproxy_cn" "wails_build_goproxy_cn.log"
    if [ $? -ne 0 ]; then
      stage "wails_build" "failed"
      set_status "BLOCKED_BUILD" "wails build -clean failed"
      finish 0
    fi
  fi
  if [ ! -d "$APP_BUNDLE" ] || [ ! -x "$APP_EXEC" ]; then
    stage "wails_app_bundle" "missing"
    set_status "BLOCKED_BUILD" "Wails app bundle missing after build"
    finish 0
  fi
  stage "wails_build" "pass"
}

seed_app_support() {
  stage "app_support_backup" "running"
  if [ -e "$APP_SUPPORT" ]; then
    echo "yes" >"$APP_SUPPORT_EXISTED_FILE"
    ditto "$APP_SUPPORT" "$BACKUP_DIR" >/dev/null 2>&1 || cp -R "$APP_SUPPORT" "$BACKUP_DIR"
  else
    echo "no" >"$APP_SUPPORT_EXISTED_FILE"
  fi
  stage "app_support_backup" "pass"

  rm -rf "$APP_SUPPORT"
  mkdir -p "$APP_SUPPORT/sing-box" "$APP_SUPPORT/plugins" "$APP_SUPPORT/rulesets" "$APP_SUPPORT/subscribes" "$APP_SUPPORT/.cache"
  cp "$KERNEL" "$APP_SUPPORT/sing-box/sing-box"
  chmod +x "$APP_SUPPORT/sing-box/sing-box"

  cat >"$APP_SUPPORT/user.yaml" <<EOF
lang: en
theme: light
color: default
primaryColor: "#000"
secondaryColor: "#545454"
fontFamily: system-ui, "Microsoft YaHei UI", "Source Han Sans CN", "Twemoji Mozilla", sans-serif
profilesView: grid
subscribesView: grid
rulesetsView: grid
pluginsView: grid
scheduledtasksView: grid
windowStartState: 0
webviewGpuPolicy: 1
width: 1000
height: 720
exitOnClose: true
closeKernelOnExit: true
autoSetSystemProxy: false
proxyBypassList: ""
autoStartKernel: false
autoRestartKernel: false
userAgent: GUI.for.SingBox/v1.25.1
startupDelay: 30
connections:
  visibility: {}
  order: []
kernel:
  realMemoryUsage: false
  branch: main
  profile: $PROFILE_ID
  autoClose: true
  unAvailable: true
  cardMode: true
  cardColumns: 4
  sortByDelay: false
  testUrl: http://127.0.0.1:$ORIGIN_PORT/
  concurrencyLimit: 4
  controllerCloseMode: all
  controllerSensitivity: 2
  main:
    env: {}
    args:
      - run
      - --disable-color
      - -c
      - \$APP_BASE_PATH/\$CORE_BASE_PATH/config.json
      - -D
      - \$APP_BASE_PATH/\$CORE_BASE_PATH
  alpha:
    env: {}
    args:
      - run
      - --disable-color
      - -c
      - \$APP_BASE_PATH/\$CORE_BASE_PATH/config.json
      - -D
      - \$APP_BASE_PATH/\$CORE_BASE_PATH
pluginSettings: {}
githubApiToken: ""
multipleInstance: true
addPluginToMenu: false
addGroupToMenu: false
rollingRelease: false
debugOutline: false
debugNoAnimation: true
debugNoRounded: false
debugBorder: false
contentProtection: false
requestProxyMode: custom
customProxy: ""
pages:
  - Overview
  - Profiles
  - Subscriptions
  - Plugins
EOF

  cat >"$APP_SUPPORT/profiles.yaml" <<EOF
- id: $PROFILE_ID
  name: $PROFILE_NAME
  log:
    disabled: false
    level: info
    output: ""
    timestamp: false
  experimental:
    clash_api:
      external_controller: 127.0.0.1:$CLASH_PORT
      external_ui: ""
      external_ui_download_url: ""
      external_ui_download_detour: outbound-direct
      secret: $SECRET
      default_mode: rule
      access_control_allow_origin:
        - "*"
      access_control_allow_private_network: false
    cache_file:
      enabled: true
      path: cache.db
      cache_id: pf19-cache
      store_fakeip: true
      store_rdrc: true
      rdrc_timeout: 7d
  inbounds:
    - id: mixed-in
      type: mixed
      tag: mixed-in
      enable: true
      mixed:
        listen:
          listen: 127.0.0.1
          listen_port: $MIXED_PORT
          tcp_fast_open: false
          tcp_multi_path: false
          udp_fragment: false
        users: []
    - id: tun-in
      type: tun
      tag: tun-in
      enable: false
      tun:
        interface_name: ""
        address:
          - 172.18.0.1/30
          - fdfe:dcba:9876::1/126
        mtu: 0
        auto_route: false
        strict_route: false
        route_address: []
        route_exclude_address: []
        endpoint_independent_nat: false
        stack: mixed
  outbounds:
    - id: outbound-select
      tag: select
      type: selector
      outbounds:
        - id: direct
          type: Built-in
          tag: direct
      interrupt_exist_connections: true
      url: http://127.0.0.1:$ORIGIN_PORT/
      interval: 3m
      tolerance: 150
      include: ""
      exclude: ""
    - id: outbound-direct
      tag: pf19-direct
      type: direct
      outbounds: []
      interrupt_exist_connections: true
      url: ""
      interval: 3m
      tolerance: 150
      include: ""
      exclude: ""
    - id: outbound-block
      tag: pf19-block
      type: block
      outbounds: []
      interrupt_exist_connections: true
      url: ""
      interval: 3m
      tolerance: 150
      include: ""
      exclude: ""
    - id: outbound-global
      tag: GLOBAL
      type: selector
      outbounds:
        - id: direct
          type: Built-in
          tag: direct
        - id: block
          type: Built-in
          tag: block
      interrupt_exist_connections: true
      url: ""
      interval: 3m
      tolerance: 150
      include: ""
      exclude: ""
  route:
    rules:
      - id: pf19-rule-direct
        type: clash_mode
        payload: direct
        enable: true
        invert: false
        action: route
        outbound: outbound-direct
        sniffer: []
        strategy: default
        server: ""
      - id: pf19-rule-global
        type: clash_mode
        payload: global
        enable: true
        invert: false
        action: route
        outbound: outbound-global
        sniffer: []
        strategy: default
        server: ""
    rule_set: []
    auto_detect_interface: true
    default_interface: ""
    final: outbound-select
    find_process: false
    default_domain_resolver:
      server: pf19-dns-local
      client_subnet: ""
  dns:
    servers:
      - id: pf19-dns-local
        tag: pf19-dns-local
        type: local
        detour: ""
        domain_resolver: ""
        server: ""
        server_port: ""
        path: ""
        interface: ""
        inet4_range: ""
        inet6_range: ""
        hosts_path: []
        predefined: {}
    rules: []
    disable_cache: false
    disable_expire: false
    independent_cache: false
    client_subnet: ""
    final: pf19-dns-local
    strategy: default
  mixin:
    priority: mixin
    format: json
    config: "{}"
  script:
    code: |-
      const onGenerate = async (config) => {
        return config
      }
EOF

  printf '[]\n' >"$APP_SUPPORT/plugins.yaml"
  printf '[]\n' >"$APP_SUPPORT/subscribes.yaml"
  printf '[]\n' >"$APP_SUPPORT/rulesets.yaml"
  printf '[]\n' >"$APP_SUPPORT/scheduledtasks.yaml"
  copy_if_exists "$APP_SUPPORT/user.yaml" "seed_user.yaml"
  copy_if_exists "$APP_SUPPORT/profiles.yaml" "seed_profiles.yaml"
  stage "seed_test_data" "pass"
}

start_origin() {
  mkdir -p "$WORK/origin"
  printf 'pf19 origin ok\n' >"$WORK/origin/index.html"
  (cd "$WORK/origin" && python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1) >"$WORK/origin.log" 2>&1 &
  echo $! >"$ORIGIN_PID_FILE"
  artifact "origin_log" "origin.log"
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$ORIGIN_PORT/" >/dev/null 2>&1; then
      stage "local_origin" "pass"
      return 0
    fi
    sleep 0.2
  done
  stage "local_origin" "failed"
  set_status "FAILED_INTERNAL" "local loopback origin did not start"
  finish 1
}

launch_wails() {
  stage "desktop_launch" "running"
  open -n "$APP_BUNDLE" >"$WORK/open.log" 2>&1
  artifact "open_log" "open.log"
  gui_pid=""
  for _ in $(seq 1 80); do
    gui_pid="$(pgrep -x "GUI.for.SingBox" | tail -n 1 || true)"
    if [ -n "$gui_pid" ]; then
      echo "$gui_pid" >"$GUI_PID_FILE"
      break
    fi
    sleep 0.25
  done
  if [ -z "$gui_pid" ]; then
    stage "desktop_launch" "no_process"
    set_status "BLOCKED_UI_NOT_FOUND" "Wails app process did not appear"
    finish 0
  fi
  stage "desktop_launch" "open_invoked"
  log "open invoked GUI pid=$gui_pid"

  for _ in $(seq 1 100); do
    window_count="$(gui_window_count "$gui_pid" || true)"
    if [ "${window_count:-0}" -gt 0 ] 2>/dev/null; then
      activate_window
      dump_ax_tree "$WORK/ui_tree_launch.txt" || true
      if [ -s "$WORK/ui_tree_launch.txt" ] && ! grep -q "execution error" "$WORK/ui_tree_launch.txt"; then
        stage "desktop_window" "process_visible_to_system_events"
        artifact "ui_tree_launch" "ui_tree_launch.txt"
        screenshot "$WORK/screenshot_launch.png"
        analyze_screenshot "$WORK/screenshot_launch.png" "$WORK/screenshot_launch_analysis.json" || true
        artifact "screenshot_launch" "screenshot_launch.png"
        artifact "screenshot_launch_analysis" "screenshot_launch_analysis.json"
        return 0
      fi
    fi
    if confirm_window_via_swift "$gui_pid"; then
      activate_window || true
      dump_ax_tree "$WORK/ui_tree_launch.txt" || true
      artifact "ui_tree_launch" "ui_tree_launch.txt"
      artifact "ui_tree_launch_err" "ui_tree_launch.txt.err"
      screenshot "$WORK/screenshot_launch.png"
      analyze_screenshot "$WORK/screenshot_launch.png" "$WORK/screenshot_launch_analysis.json" || true
      artifact "screenshot_launch" "screenshot_launch.png"
      artifact "screenshot_launch_analysis" "screenshot_launch_analysis.json"
      stage "desktop_window" "swift_bounds_confirmed"
      return 0
    fi
    sleep 0.5
  done

  if [ "$ALLOW_EXTERNAL_CLICK" = "1" ]; then
    printf 'Computer-use assist requested: confirm the real Wails window is visible, then write %s.\n' "$EXTERNAL_WINDOW_SEEN_FILE" >"$WORK/assist_window_needed.txt"
    artifact "assist_window_needed" "assist_window_needed.txt"
    log "external desktop assist window open for launch visibility (${ASSIST_WAIT_SECONDS}s)"
    for _ in $(seq 1 "$((ASSIST_WAIT_SECONDS * 2))"); do
      if [ -s "$EXTERNAL_WINDOW_SEEN_FILE" ]; then
        meta "drive_method" "$EXTERNAL_DRIVE_LABEL"
        artifact "external_window_seen" "external_window_seen.txt"
        screenshot "$WORK/screenshot_launch.png"
        analyze_screenshot "$WORK/screenshot_launch.png" "$WORK/screenshot_launch_analysis.json" || true
        artifact "screenshot_launch" "screenshot_launch.png"
        artifact "screenshot_launch_analysis" "screenshot_launch_analysis.json"
        stage "desktop_window" "external_confirmed"
        return 0
      fi
      sleep 0.5
    done
  fi

  stage "desktop_window" "not_visible"
  set_status "BLOCKED_UI_NOT_FOUND" "Wails process started but no desktop window was visible"
  finish 0
}

wait_seed_visible() {
  for _ in $(seq 1 60); do
    activate_window
    dump_ax_tree "$WORK/ui_tree_before_start_click.txt" || true
    if ! grep -q "execution error" "$WORK/ui_tree_before_start_click.txt" && grep -q "$PROFILE_NAME" "$WORK/ui_tree_before_start_click.txt" && grep -q "Click to Start" "$WORK/ui_tree_before_start_click.txt"; then
      artifact "ui_tree_before_start_click" "ui_tree_before_start_click.txt"
      screenshot "$WORK/screenshot_before_start_click.png"
      analyze_screenshot "$WORK/screenshot_before_start_click.png" "$WORK/screenshot_before_start_click_analysis.json" || true
      artifact "screenshot_before_start_click" "screenshot_before_start_click.png"
      artifact "screenshot_before_start_click_analysis" "screenshot_before_start_click_analysis.json"
      stage "profile_visible" "pass"
      return 0
    fi
    sleep 0.5
  done
  artifact "ui_tree_before_start_click" "ui_tree_before_start_click.txt"
  artifact "ui_tree_before_start_click_err" "ui_tree_before_start_click.txt.err"

  if [ "$ALLOW_EXTERNAL_CLICK" = "1" ]; then
    printf 'Computer-use assist requested: confirm profile "%s" and "Click to Start" are visible, then write %s.\n' "$PROFILE_NAME" "$EXTERNAL_PROFILE_SEEN_FILE" >"$WORK/assist_profile_needed.txt"
    artifact "assist_profile_needed" "assist_profile_needed.txt"
    log "external desktop assist window open for profile/start visibility (${ASSIST_WAIT_SECONDS}s)"
    for _ in $(seq 1 "$((ASSIST_WAIT_SECONDS * 2))"); do
      if [ -s "$EXTERNAL_PROFILE_SEEN_FILE" ]; then
        meta "drive_method" "$EXTERNAL_DRIVE_LABEL"
        artifact "external_profile_seen" "external_profile_seen.txt"
        screenshot "$WORK/screenshot_before_start_click.png"
        analyze_screenshot "$WORK/screenshot_before_start_click.png" "$WORK/screenshot_before_start_click_analysis.json" || true
        artifact "screenshot_before_start_click" "screenshot_before_start_click.png"
        artifact "screenshot_before_start_click_analysis" "screenshot_before_start_click_analysis.json"
        stage "profile_visible" "external_confirmed"
        return 0
      fi
      sleep 0.5
    done
  fi

  stage "profile_visible" "not_found"
  if grep -q "swift_bounds_confirmed" "$STAGES" 2>/dev/null; then
    stage "profile_visible" "blocked_accessibility_after_window_geometry"
    set_status "BLOCKED_ACCESSIBILITY" "Wails window bounds exist, but AX tree/Computer Use could not expose the seeded profile or Start control"
  else
    set_status "BLOCKED_UI_NOT_FOUND" "seeded profile or start control not found in Wails AX tree"
  fi
  finish 0
}

probe_core_once() {
  pid_path="$APP_SUPPORT/sing-box/pid.txt"
  config_path="$APP_SUPPORT/sing-box/config.json"
  if [ ! -s "$pid_path" ]; then
    return 1
  fi
  pid="$(cat "$pid_path" 2>/dev/null || true)"
  if [ -z "$pid" ] || ! kill -0 "$pid" >/dev/null 2>&1; then
    return 1
  fi
  echo "$pid" >"$CORE_PID_FILE"
  cp "$pid_path" "$WORK/pid.txt" 2>/dev/null || true
  artifact "pid_file" "pid.txt"
  [ -f "$config_path" ] && cp "$config_path" "$WORK/generated_config.json"
  [ -f "$WORK/generated_config.json" ] && artifact "generated_config" "generated_config.json"
  ps -p "$pid" -o command= >"$WORK/core_command.txt" 2>&1 || true
  artifact "core_command" "core_command.txt"
  port_open "$MIXED_PORT" || return 1
  port_open "$CLASH_PORT" || return 1
  return 0
}

wait_for_core() {
  seconds="$1"
  loops=$((seconds * 2))
  [ "$loops" -lt 1 ] && loops=1
  for _ in $(seq 1 "$loops"); do
    if probe_core_once; then
      stage "core_started" "pid_config_ports_present"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

click_start() {
  stage "start_click" "native_attempting"
  try_click_text "$PROFILE_NAME" "profile" "$WORK/profile_click.log" || true
  sleep 0.5
  if try_click_text "Click to Start" "start" "$WORK/start_click.log"; then
    stage "start_click" "native_sent"
  else
    ax_press_button_index 2 "$WORK/start_click_button2.log" && stage "start_click" "native_button2_sent" || stage "start_click" "native_attempted"
    cat "$WORK/start_click_button2.log" >>"$WORK/start_click.log" 2>/dev/null || true
  fi
  artifact "start_click_log" "start_click.log"

  if wait_for_core 20; then
    return 0
  fi

  if [ "$ALLOW_EXTERNAL_CLICK" = "1" ]; then
    stage "start_click" "native_attempted_waiting_external"
    printf 'Computer-use assist requested: click the real Wails "Click to Start" button now.\n' >"$WORK/assist_start_needed.txt"
    artifact "assist_start_needed" "assist_start_needed.txt"
    log "external desktop assist window open for Start (${ASSIST_WAIT_SECONDS}s)"
    if wait_for_core "$ASSIST_WAIT_SECONDS"; then
      meta "drive_method" "$EXTERNAL_DRIVE_LABEL"
      stage "start_click" "external_sent"
      return 0
    fi
  fi

  stage "core_started" "not_run"
  set_status "BLOCKED_START_NO_CORE" "Start was attempted but no GUI-started Rust core pid/config/ports appeared"
  finish 0
}

verify_api_and_traffic() {
  stage "clash_api" "running"
  if curl -fsS -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/configs" -o "$WORK/clash_configs.json" --max-time 5; then
    artifact "configs_response" "clash_configs.json"
  else
    stage "clash_api" "configs_failed"
    set_status "BLOCKED_API_NO_RESPONSE" "Clash API /configs did not respond to Bearer token"
    finish 0
  fi
  if curl -fsS -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/proxies" -o "$WORK/clash_proxies.json" --max-time 5; then
    artifact "proxies_response" "clash_proxies.json"
    stage "clash_api" "pass"
  else
    stage "clash_api" "proxies_failed"
    set_status "BLOCKED_API_NO_RESPONSE" "Clash API /proxies did not respond to Bearer token"
    finish 0
  fi

  dump_ax_tree "$WORK/ui_tree_after_start.txt" || true
  artifact "ui_tree_after_start" "ui_tree_after_start.txt"
  screenshot "$WORK/screenshot_after_start.png"
  artifact "screenshot_after_start" "screenshot_after_start.png"
  if grep -q "Click to Start" "$WORK/ui_tree_after_start.txt"; then
    stage "gui_running_view" "not_confirmed"
  else
    stage "gui_running_view" "pass"
  fi

  status="$(curl -sS -o "$WORK/curl_body.txt" -w "%{http_code}" -x "http://127.0.0.1:$MIXED_PORT" "http://127.0.0.1:$ORIGIN_PORT/" --max-time 8 2>"$WORK/curl_err.txt" || true)"
  printf '%s\n' "$status" >"$WORK/curl_status.txt"
  artifact "curl_status" "curl_status.txt"
  artifact "curl_body" "curl_body.txt"
  artifact "curl_err" "curl_err.txt"
  if [ "$status" = "200" ]; then
    stage "loopback_proxy_traffic" "pass"
  else
    stage "loopback_proxy_traffic" "failed_http_$status"
    set_status "BLOCKED_TRAFFIC" "loopback HTTP traffic through GUI-started proxy failed"
    finish 0
  fi
}

core_stopped() {
  if [ ! -f "$CORE_PID_FILE" ]; then
    wait_port_closed "$MIXED_PORT" && wait_port_closed "$CLASH_PORT"
    return $?
  fi
  pid="$(cat "$CORE_PID_FILE" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    return 1
  fi
  wait_port_closed "$MIXED_PORT" && wait_port_closed "$CLASH_PORT"
}

wait_for_stop_pre_cleanup() {
  seconds="$1"
  loops=$((seconds * 2))
  [ "$loops" -lt 1 ] && loops=1
  for _ in $(seq 1 "$loops"); do
    if core_stopped; then
      meta "stop_core_exited_pre_cleanup" "true"
      meta "stop_ports_released_pre_cleanup" "true"
      meta "package07_closure_eligible" "true"
      stage "stop_cleanup" "pass_ports_released_pre_cleanup"
      dump_ax_tree "$WORK/ui_tree_after_stop.txt" || true
      screenshot "$WORK/screenshot_after_stop.png"
      artifact "ui_tree_after_stop" "ui_tree_after_stop.txt"
      artifact "screenshot_after_stop" "screenshot_after_stop.png"
      crop_stop_toolbar "$WORK/screenshot_after_stop.png" "$WORK/stop_toolbar_after.png" || true
      artifact "stop_toolbar_after" "stop_toolbar_after.png"
      return 0
    fi
    sleep 0.5
  done
  meta "stop_core_exited_pre_cleanup" "false"
  meta "stop_ports_released_pre_cleanup" "false"
  meta "package07_closure_eligible" "false"
  return 1
}

mark_stop_event_sent() {
  backend="$1"
  meta "stop_event_sent" "true"
  meta "stop_backend" "$backend"
  if [ "$backend" = "$EXTERNAL_DRIVE_LABEL" ]; then
    meta "drive_method" "$EXTERNAL_DRIVE_LABEL"
  fi
  stage "stop_click" "${backend}_sent"
  log "Stop event sent via $backend"
}

click_stop() {
  stage "stop_click" "source_informed_attempting"
  meta "stop_event_sent" "false"
  meta "stop_backend" ""
  meta "stop_core_exited_pre_cleanup" "false"
  meta "stop_ports_released_pre_cleanup" "false"
  meta "package07_closure_eligible" "false"
  screenshot "$WORK/screenshot_before_stop.png"
  artifact "screenshot_before_stop" "screenshot_before_stop.png"
  if ! write_stop_geometry; then
    artifact "stop_geometry_err" "stop_geometry.err"
    stage "stop_geometry" "failed"
    set_status "BLOCKED_WINDOW_GEOMETRY" "could not read Wails window bounds for source-informed Stop click"
    finish 0
  fi
  stage "stop_geometry" "pass"
  crop_stop_toolbar "$WORK/screenshot_before_stop.png" "$WORK/stop_toolbar_before.png" || true
  artifact "stop_toolbar_before" "stop_toolbar_before.png"

  if ensure_swift_helper && "$(swift_helper_bin)" axpress-stop "$(current_gui_pid)" "$WORK/window_bounds.json" "$WORK/stop_toolbar_candidates.json" "$WORK/stop_coordinates.json" >"$WORK/stop_click_axpress.log" 2>&1; then
    cat "$WORK/stop_click_axpress.log" >"$WORK/stop_click.log"
    mark_stop_event_sent "swift_axpress_candidate"
    artifact "stop_click_axpress" "stop_click_axpress.log"
    artifact "stop_click_log" "stop_click.log"
    if wait_for_stop_pre_cleanup 20; then
      return 0
    fi
  else
    cat "$WORK/stop_click_axpress.log" >"$WORK/stop_click.log" 2>/dev/null || true
    artifact "stop_click_axpress" "stop_click_axpress.log"
  fi

  if [ "$ALLOW_EXTERNAL_CLICK" = "1" ]; then
    stage "stop_click" "waiting_computer_use_optional"
    printf 'Computer-use assist requested: click the real Wails Stop icon now. Coordinates: %s.\n' "$(cat "$WORK/stop_coordinates.json" 2>/dev/null || true)" >"$WORK/assist_stop_computer_use_needed.txt"
    printf 'waiting for computer-use Stop click; script will verify pid/ports only\n' >"$WORK/stop_click_computer_use.log"
    artifact "assist_stop_computer_use_needed" "assist_stop_computer_use_needed.txt"
    artifact "stop_click_computer_use" "stop_click_computer_use.log"
    for _ in $(seq 1 20); do
      if core_stopped; then
        mark_stop_event_sent "computer_use_mcp"
        if wait_for_stop_pre_cleanup 1; then
          return 0
        fi
      fi
      sleep 0.5
    done
  fi

  if ensure_swift_helper && "$(swift_helper_bin)" click "$(current_gui_pid)" "$STOP_X" "$STOP_Y" >"$WORK/stop_click_swift.log" 2>&1; then
    cat "$WORK/stop_click_swift.log" >>"$WORK/stop_click.log" 2>/dev/null || true
    mark_stop_event_sent "swift_cgevent_window_relative"
    artifact "stop_click_swift" "stop_click_swift.log"
    artifact "stop_click_log" "stop_click.log"
    if wait_for_stop_pre_cleanup 20; then
      return 0
    fi
  else
    artifact "stop_click_swift" "stop_click_swift.log"
    if grep -qi "not trusted\\|not authorized\\|permission" "$WORK/stop_click_swift.log" "$WORK/swift_helper_build.log" 2>/dev/null; then
      stage "stop_click" "swift_blocked_accessibility"
    else
      stage "stop_click" "swift_failed"
    fi
  fi

  if command -v cliclick >/dev/null 2>&1; then
    if cliclick c:"$STOP_X","$STOP_Y" >"$WORK/stop_click_cliclick.log" 2>&1; then
      mark_stop_event_sent "cliclick_window_relative"
      artifact "stop_click_cliclick" "stop_click_cliclick.log"
      if wait_for_stop_pre_cleanup 20; then
        return 0
      fi
    else
      artifact "stop_click_cliclick" "stop_click_cliclick.log"
    fi
  else
    printf 'cliclick not installed\n' >"$WORK/stop_click_cliclick.log"
    artifact "stop_click_cliclick" "stop_click_cliclick.log"
  fi

  if osascript -e "tell application \"System Events\" to click at {$STOP_X,$STOP_Y}" >"$WORK/stop_click_system_events.log" 2>&1; then
    mark_stop_event_sent "system_events_click_at"
    artifact "stop_click_system_events" "stop_click_system_events.log"
    if wait_for_stop_pre_cleanup 20; then
      return 0
    fi
  else
    artifact "stop_click_system_events" "stop_click_system_events.log"
    if grep -q -- "-25211\\|assistive access\\|not allowed" "$WORK/stop_click_system_events.log"; then
      stage "stop_click" "system_events_blocked_accessibility"
    else
      stage "stop_click" "system_events_failed"
    fi
  fi

  artifact "stop_click_log" "stop_click.log"

  if [ "$(grep -c '^stop_event_sent=true$' "$META" 2>/dev/null || true)" -gt 0 ]; then
    stage "stop_cleanup" "failed_after_event"
    set_status "BLOCKED_STOP_COORDINATE_MISS" "Stop click event was sent, but GUI core pid/ports did not stop before cleanup"
  elif grep -qi -- "-25211\\|assistive access\\|not allowed\\|not trusted\\|not authorized\\|permission" "$WORK"/stop_click_*.log "$WORK/swift_helper_build.log" 2>/dev/null; then
    stage "stop_cleanup" "blocked_accessibility"
    set_status "BLOCKED_ACCESSIBILITY" "Stop automation was blocked by macOS accessibility/event permissions"
  elif [ ! -s "$WORK/stop_click_swift.log" ]; then
    stage "stop_cleanup" "blocked_cgevent"
    set_status "BLOCKED_CGEVENT" "Swift/CGEvent Stop backend did not emit a usable click event"
  else
    stage "stop_cleanup" "no_event"
    set_status "BLOCKED_STOP_NO_EVENT" "no Stop click backend could send a real GUI event"
  fi
  finish 0
}

preflight
build_phase
seed_app_support
start_origin
launch_wails
wait_seed_visible
click_start
verify_api_and_traffic
click_stop

set_status "PASS" "real Wails desktop Start -> core/API/traffic -> Stop flow passed"
finish 0
