#!/usr/bin/env sh
# Detect a usable bash executable with major version >= 4.
# Echo the discovered path and exit 0 on success; otherwise exit 1.
set -eu

check_bash() {
  candidate="$1"
  [ -n "$candidate" ] || return 1
  if ! command -v "$candidate" >/dev/null 2>&1; then
    [ -x "$candidate" ] || return 1
  fi
  version=$("$candidate" -c 'echo ${BASH_VERSINFO[0]:-0}' 2>/dev/null || echo 0)
  case "$version" in
    '' ) return 1 ;;
    *[!0-9]* ) return 1 ;;
  esac
  [ "$version" -ge 4 ] || return 1
  printf '%s\n' "$candidate"
  return 0
}

# Build a candidate list. We explicitly keep command -v first, then well-known paths.
candidate_list=$(command -v bash 2>/dev/null || true)
candidate_list="$candidate_list\n/bin/bash\n/usr/bin/bash\n/usr/local/bin/bash\n/opt/homebrew/bin/bash\n/usr/local/opt/bash/bin/bash"

printf '%s\n' "$candidate_list" | while IFS= read -r path; do
  if check_bash "$path"; then
    exit 0
  fi
done

exit 1
