#!/usr/bin/env bash
# Shared env-limited failure classification helpers.
# Sourced by: run_case_trend_gate.sh, aggregate_trend_report.sh
#
# NOTE: The classification rules here mirror attribution.rs::classify_detail().
# If you change the rules in one place, update the other to stay in sync.

_to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

_classify_env_limited_category() {
  local text_lc
  text_lc="$(_to_lower "$1")"

  if [[ "${text_lc}" == *'"status":403'* || "${text_lc}" == *'"status":429'* || "${text_lc}" == *'"status":503'* || \
        "${text_lc}" == *'status=403'* || "${text_lc}" == *'status=429'* || "${text_lc}" == *'status=503'* || \
        "${text_lc}" == *'rate limit'* || "${text_lc}" == *'too many requests'* ]]; then
    printf 'rate_limit'
    return
  fi

  if [[ "${text_lc}" == *'tls'* || "${text_lc}" == *'handshake'* || "${text_lc}" == *'certificate'* || "${text_lc}" == *'ssl'* ]]; then
    printf 'tls'
    return
  fi

  # Keep launch-kernel readiness failures as functional by default.
  if [[ "${text_lc}" == *'kernel not ready'* ]]; then
    printf 'unknown'
    return
  fi

  if [[ "${text_lc}" == *'connection refused'* || "${text_lc}" == *'connect error'* || \
        "${text_lc}" == *'network unreachable'* || "${text_lc}" == *'no route to host'* || \
        "${text_lc}" == *'connection reset'* || "${text_lc}" == *'timeout'* || "${text_lc}" == *'timed out'* ]]; then
    printf 'network'
    return
  fi

  printf 'unknown'
}

_collect_env_limited_counts() {
  local snapshot="$1"
  local env_error_count=0
  local env_traffic_count=0
  local unknown_count=0
  local categories_csv=""

  while IFS= read -r msg; do
    [[ -z "${msg}" ]] && continue
    local category
    category="$(_classify_env_limited_category "${msg}")"
    case "${category}" in
      rate_limit|network|tls)
        env_error_count=$((env_error_count + 1))
        categories_csv="${categories_csv}${category},"
        ;;
      *)
        unknown_count=$((unknown_count + 1))
        ;;
    esac
  done < <(jq -r '.errors[]?.message // empty' "${snapshot}")

  while IFS= read -r detail; do
    [[ -z "${detail}" ]] && continue
    local category
    category="$(_classify_env_limited_category "${detail}")"
    case "${category}" in
      rate_limit|network|tls)
        env_traffic_count=$((env_traffic_count + 1))
        categories_csv="${categories_csv}${category},"
        ;;
      *)
        unknown_count=$((unknown_count + 1))
        ;;
    esac
  done < <(jq -rc '.traffic_results[]? | select(.success != true) | .detail' "${snapshot}")

  categories_csv="${categories_csv%,}"
  printf '%s\t%s\t%s\t%s\n' "${env_error_count}" "${env_traffic_count}" "${unknown_count}" "${categories_csv}"
}
