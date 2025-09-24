#!/usr/bin/env bash
set -euo pipefail

# RC package verification script for singbox-rust
# Validates version metadata completeness and consistency

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RC_DIR="${ROOT}/target/rc"

log() {
    echo "[RC-VERIFY $(date +%H:%M:%S)] $*" >&2
}

error() {
    echo "[RC-VERIFY ERROR] $*" >&2
    exit 1
}

# Function to verify JSON schema structure
verify_json_schema() {
    local file="$1"
    local schema_type="$2"

    log "Verifying JSON schema for $schema_type: $(basename "$file")"

    if [[ ! -f "$file" ]]; then
        error "File not found: $file"
    fi

    # Validate JSON format
    if ! jq . "$file" >/dev/null 2>&1; then
        error "Invalid JSON format in $file"
    fi

    case "$schema_type" in
        "version")
            # Verify version file structure
            local required_fields=("version" "commit" "build_time" "features" "platform" "timestamp" "rc_metadata")
            for field in "${required_fields[@]}"; do
                if ! jq -e ".$field" "$file" >/dev/null 2>&1; then
                    error "Missing required field '$field' in version file: $file"
                fi
            done

            # Verify platform subfields
            local platform_fields=("os" "arch" "target")
            for field in "${platform_fields[@]}"; do
                if ! jq -e ".platform.$field" "$file" >/dev/null 2>&1; then
                    error "Missing platform field '$field' in version file: $file"
                fi
            done

            # Verify rc_metadata subfields
            local rc_fields=("git" "build_environment")
            for field in "${rc_fields[@]}"; do
                if ! jq -e ".rc_metadata.$field" "$file" >/dev/null 2>&1; then
                    error "Missing rc_metadata field '$field' in version file: $file"
                fi
            done
            ;;

        "ci_metadata")
            # Verify CI metadata structure
            local required_fields=("ci_metadata")
            for field in "${required_fields[@]}"; do
                if ! jq -e ".$field" "$file" >/dev/null 2>&1; then
                    error "Missing required field '$field' in CI metadata file: $file"
                fi
            done

            # Verify ci_metadata subfields
            local ci_fields=("timestamp" "environment" "validation")
            for field in "${ci_fields[@]}"; do
                if ! jq -e ".ci_metadata.$field" "$file" >/dev/null 2>&1; then
                    error "Missing ci_metadata field '$field' in CI metadata file: $file"
                fi
            done
            ;;

        "manifest")
            # Verify manifest structure
            local required_fields=("timestamp" "files" "validation_status")
            for field in "${required_fields[@]}"; do
                if ! jq -e ".$field" "$file" >/dev/null 2>&1; then
                    error "Missing required field '$field' in manifest file: $file"
                fi
            done
            ;;
    esac

    log "JSON schema verification passed for $schema_type"
}

# Function to verify version consistency
verify_version_consistency() {
    local version_file="$1"
    log "Verifying version consistency..."

    # Extract version from different sources
    local json_version=$(jq -r '.version' "$version_file" 2>/dev/null || echo "unknown")
    local project_version=""

    if [[ -f "${ROOT}/Cargo.toml" ]]; then
        project_version=$(grep '^version' "${ROOT}/Cargo.toml" | head -1 | cut -d'"' -f2 2>/dev/null || echo "unknown")
    fi

    # Check if versions match
    if [[ "$json_version" != "unknown" && "$project_version" != "unknown" && "$json_version" != "$project_version" ]]; then
        error "Version mismatch: JSON version ($json_version) != Project version ($project_version)"
    fi

    log "Version consistency check passed"
}

# Function to verify commit hash
verify_commit_hash() {
    local version_file="$1"
    log "Verifying commit hash..."

    local json_commit=$(jq -r '.rc_metadata.git.commit' "$version_file" 2>/dev/null || echo "unknown")
    local actual_commit=""

    if command -v git >/dev/null 2>&1 && [[ -d "${ROOT}/.git" ]]; then
        actual_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    fi

    # Check if commit hashes match (allow short form)
    if [[ "$json_commit" != "unknown" && "$actual_commit" != "unknown" ]]; then
        if [[ ! "$actual_commit" =~ ^${json_commit} ]]; then
            error "Commit hash mismatch: JSON commit ($json_commit) != Actual commit ($actual_commit)"
        fi
    fi

    log "Commit hash verification passed"
}

# Function to verify file integrity
verify_file_integrity() {
    local file="$1"
    log "Verifying file integrity: $(basename "$file")"

    # Check file size
    local file_size=""
    if command -v stat >/dev/null 2>&1; then
        file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
    fi

    if [[ "$file_size" -eq 0 ]]; then
        error "File is empty: $file"
    fi

    # Check if file is readable
    if [[ ! -r "$file" ]]; then
        error "File is not readable: $file"
    fi

    log "File integrity verification passed"
}

# Function to verify timestamp validity
verify_timestamps() {
    local version_file="$1"
    local ci_metadata_file="$2"

    log "Verifying timestamp validity..."

    local version_timestamp=$(jq -r '.timestamp' "$version_file" 2>/dev/null || echo "0")
    local ci_timestamp=$(jq -r '.ci_metadata.timestamp' "$ci_metadata_file" 2>/dev/null || echo "0")
    local current_timestamp=$(date +%s)

    # Check if timestamps are valid epoch times
    if [[ ! "$version_timestamp" =~ ^[0-9]+$ ]] || [[ "$version_timestamp" -eq 0 ]]; then
        error "Invalid timestamp in version file: $version_timestamp"
    fi

    if [[ ! "$ci_timestamp" =~ ^[0-9]+$ ]] || [[ "$ci_timestamp" -eq 0 ]]; then
        error "Invalid timestamp in CI metadata file: $ci_timestamp"
    fi

    # Check if timestamps are reasonable (within last hour and not in future)
    local hour_ago=$((current_timestamp - 3600))
    local future_limit=$((current_timestamp + 60))

    if [[ "$version_timestamp" -lt "$hour_ago" ]] || [[ "$version_timestamp" -gt "$future_limit" ]]; then
        log "Warning: Version timestamp seems unusual: $version_timestamp (current: $current_timestamp)"
    fi

    if [[ "$ci_timestamp" -lt "$hour_ago" ]] || [[ "$ci_timestamp" -gt "$future_limit" ]]; then
        log "Warning: CI timestamp seems unusual: $ci_timestamp (current: $current_timestamp)"
    fi

    log "Timestamp verification passed"
}

# Main verification function
main() {
    log "Starting RC package verification"

    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        error "jq is required for verification but not found"
    fi

    # Check if RC directory exists
    if [[ ! -d "$RC_DIR" ]]; then
        error "RC directory not found: $RC_DIR"
    fi

    # Find latest files
    local version_file=""
    local ci_metadata_file=""
    local manifest_file=""

    if [[ -f "$RC_DIR/version-latest.json" ]]; then
        version_file="$RC_DIR/$(readlink "$RC_DIR/version-latest.json")"
    else
        # Find most recent version file
        version_file=$(ls "$RC_DIR"/version-*.json 2>/dev/null | sort | tail -1 || echo "")
    fi

    if [[ -f "$RC_DIR/ci-metadata-latest.json" ]]; then
        ci_metadata_file="$RC_DIR/$(readlink "$RC_DIR/ci-metadata-latest.json")"
    else
        # Find most recent ci-metadata file
        ci_metadata_file=$(ls "$RC_DIR"/ci-metadata-*.json 2>/dev/null | sort | tail -1 || echo "")
    fi

    # Find most recent manifest file
    manifest_file=$(ls "$RC_DIR"/manifest-*.json 2>/dev/null | sort | tail -1 || echo "")

    # Verify files exist
    if [[ -z "$version_file" || ! -f "$version_file" ]]; then
        error "No version file found in RC directory"
    fi

    if [[ -z "$ci_metadata_file" || ! -f "$ci_metadata_file" ]]; then
        error "No CI metadata file found in RC directory"
    fi

    log "Verifying files:"
    log "  Version: $(basename "$version_file")"
    log "  CI Metadata: $(basename "$ci_metadata_file")"
    if [[ -n "$manifest_file" && -f "$manifest_file" ]]; then
        log "  Manifest: $(basename "$manifest_file")"
    fi

    # Perform verification checks
    verify_file_integrity "$version_file"
    verify_file_integrity "$ci_metadata_file"

    verify_json_schema "$version_file" "version"
    verify_json_schema "$ci_metadata_file" "ci_metadata"

    if [[ -n "$manifest_file" && -f "$manifest_file" ]]; then
        verify_file_integrity "$manifest_file"
        verify_json_schema "$manifest_file" "manifest"
    fi

    verify_version_consistency "$version_file"
    verify_commit_hash "$version_file"
    verify_timestamps "$version_file" "$ci_metadata_file"

    log "RC package verification completed successfully"
    log "All validation checks passed"

    # Output summary
    echo "RC_VERIFICATION_STATUS=PASSED"
    echo "RC_VERSION_FILE=$(basename "$version_file")"
    echo "RC_CI_METADATA_FILE=$(basename "$ci_metadata_file")"
    if [[ -n "$manifest_file" && -f "$manifest_file" ]]; then
        echo "RC_MANIFEST_FILE=$(basename "$manifest_file")"
    fi
}

# Check for help flag
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: $0"
    echo "Verifies RC package metadata completeness and consistency."
    echo ""
    echo "This script validates:"
    echo "  - JSON schema structure"
    echo "  - Version consistency"
    echo "  - Commit hash accuracy"
    echo "  - File integrity"
    echo "  - Timestamp validity"
    exit 0
fi

# Run main verification
main "$@"