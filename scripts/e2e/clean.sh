#!/usr/bin/env bash
# Enhanced E2E cleanup script with smart cleaning capabilities
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/.e2e"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Enhanced E2E cleanup script with multiple cleaning modes.

OPTIONS:
  --help                   Show this help message
  --logs-only              Clean only log files
  --reports-only           Clean only report files (JSON)
  --visualizations-only    Clean only visualization files (SVG, DOT)
  --artifacts-only         Clean only build artifacts (checksums)
  --pids-only              Clean only PID files
  --soak-only              Clean only soak test results
  --older-than DAYS        Clean files older than N days (e.g., 7d)
  --keep-last N            Keep only the N most recent files in each category
  --smart                  Smart clean: remove temp files, keep important reports
  --dry-run                Show what would be deleted without actually deleting
  --verbose                Show detailed information about each deletion
  (no options)             Clean all generated files (preserves README, config, .gitignore)

EXAMPLES:
  $(basename "$0")                         # Full clean
  $(basename "$0") --smart                 # Clean temp files, keep reports
  $(basename "$0") --logs-only             # Clean only logs
  $(basename "$0") --older-than 7d         # Clean files older than 7 days
  $(basename "$0") --keep-last 5           # Keep only 5 most recent files
  $(basename "$0") --dry-run --verbose     # Preview what would be deleted

EOF
  exit 0
}

# Parse arguments
MODE="all"
DRY_RUN=0
VERBOSE=0
OLDER_THAN_DAYS=""
KEEP_LAST=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --help|-h)
      usage
      ;;
    --logs-only)
      MODE="logs"
      shift
      ;;
    --reports-only)
      MODE="reports"
      shift
      ;;
    --visualizations-only)
      MODE="visualizations"
      shift
      ;;
    --artifacts-only)
      MODE="artifacts"
      shift
      ;;
    --pids-only)
      MODE="pids"
      shift
      ;;
    --soak-only)
      MODE="soak"
      shift
      ;;
    --smart)
      MODE="smart"
      shift
      ;;
    --older-than)
      OLDER_THAN_DAYS="$2"
      shift 2
      ;;
    --keep-last)
      KEEP_LAST="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --verbose|-v)
      VERBOSE=1
      shift
      ;;
    *)
      echo -e "${RED}Error: Unknown option: $1${NC}" >&2
      echo "Run with --help for usage information" >&2
      exit 1
      ;;
  esac
done

# Ensure .e2e directory exists
mkdir -p "$OUT"

# Helper functions
log_info() {
  echo -e "${GREEN}[e2e-clean]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[e2e-clean]${NC} $1"
}

log_verbose() {
  if [[ $VERBOSE -eq 1 ]]; then
    echo -e "${GREEN}[e2e-clean]${NC} $1"
  fi
}

# Count and display file statistics
count_files() {
  local dir="$1"
  if [[ -d "$dir" ]]; then
    find "$dir" -type f ! -name '.gitkeep' 2>/dev/null | wc -l | tr -d ' '
  else
    echo "0"
  fi
}

# Remove files with optional dry-run
remove_files() {
  local pattern="$1"
  local description="$2"
  
  if [[ -z "$pattern" ]]; then
    return
  fi
  
  local count=0
  while IFS= read -r -d '' file; do
    count=$((count + 1))
    if [[ $DRY_RUN -eq 1 ]]; then
      log_verbose "Would delete: $file"
    else
      log_verbose "Deleting: $file"
      rm -f "$file"
    fi
  done < <(eval "find $pattern -print0 2>/dev/null || true")
  
  if [[ $count -gt 0 ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      log_info "Would delete $count $description file(s)"
    else
      log_info "Deleted $count $description file(s)"
    fi
  fi
}

# Remove directory contents while preserving .gitkeep
clean_directory() {
  local dir="$1"
  local description="$2"
  
  if [[ ! -d "$dir" ]]; then
    return
  fi
  
  local count=$(count_files "$dir")
  if [[ $count -eq 0 ]]; then
    log_verbose "No files to clean in $description"
    return
  fi
  
  if [[ $DRY_RUN -eq 1 ]]; then
    log_info "Would delete $count file(s) from $description"
    if [[ $VERBOSE -eq 1 ]]; then
      find "$dir" -type f ! -name '.gitkeep' -exec echo "  - {}" \;
    fi
  else
    find "$dir" -type f ! -name '.gitkeep' -delete
    log_info "Deleted $count file(s) from $description"
  fi
}

# Clean files older than specified days
clean_older_than() {
  local days="${OLDER_THAN_DAYS%d}"  # Remove 'd' suffix if present
  
  if [[ ! "$days" =~ ^[0-9]+$ ]]; then
    log_warn "Invalid days format: $OLDER_THAN_DAYS (expected number or number with 'd')"
    exit 1
  fi
  
  log_info "Cleaning files older than $days days..."
  
  local count=0
  while IFS= read -r -d '' file; do
    # Skip protected files
    if [[ "$(basename "$file")" == "README.md" ]] || \
       [[ "$(basename "$file")" == "config.yaml" ]] || \
       [[ "$(basename "$file")" == ".gitignore" ]] || \
       [[ "$(basename "$file")" == ".gitkeep" ]]; then
      continue
    fi
    
    count=$((count + 1))
    if [[ $DRY_RUN -eq 1 ]]; then
      log_verbose "Would delete: $file"
    else
      log_verbose "Deleting: $file"
      rm -f "$file"
    fi
  done < <(find "$OUT" -type f -mtime "+$days" -print0 2>/dev/null || true)
  
  if [[ $count -gt 0 ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
      log_info "Would delete $count file(s) older than $days days"
    else
      log_info "Deleted $count file(s) older than $days days"
    fi
  else
    log_info "No files older than $days days found"
  fi
}

# Keep only the N most recent files
clean_keep_last() {
  local keep_n="$KEEP_LAST"
  
  if [[ ! "$keep_n" =~ ^[0-9]+$ ]]; then
    log_warn "Invalid number: $keep_n"
    exit 1
  fi
  
  log_info "Keeping only the $keep_n most recent file(s) in each category..."
  
  for dir in logs reports visualizations artifacts soak; do
    local full_dir="$OUT/$dir"
    if [[ ! -d "$full_dir" ]]; then
      continue
    fi
    
    local total=$(count_files "$full_dir")
    if [[ $total -le $keep_n ]]; then
      log_verbose "Directory $dir has $total file(s), keeping all"
      continue
    fi
    
    local to_delete=$((total - keep_n))
    log_info "Directory $dir: keeping $keep_n, removing $to_delete file(s)"
    
    # Find oldest files and delete them
    if [[ $DRY_RUN -eq 1 ]]; then
      find "$full_dir" -type f ! -name '.gitkeep' -printf '%T@ %p\n' 2>/dev/null | \
        sort -n | head -n "$to_delete" | cut -d' ' -f2- | while read -r file; do
          log_verbose "Would delete: $file"
        done
    else
      find "$full_dir" -type f ! -name '.gitkeep' -printf '%T@ %p\n' 2>/dev/null | \
        sort -n | head -n "$to_delete" | cut -d' ' -f2- | while read -r file; do
          log_verbose "Deleting: $file"
          rm -f "$file"
        done
    fi
  done
}

# Smart clean: remove temporary files, keep important reports
smart_clean() {
  log_info "Smart clean: removing temporary files, keeping important reports..."
  
  # Always clean: logs and PIDs
  clean_directory "$OUT/logs" "logs"
  clean_directory "$OUT/pids" "PIDs"
  
  # Clean old visualizations (keep if modified in last 7 days)
  if [[ $DRY_RUN -eq 1 ]]; then
    local count=$(find "$OUT/visualizations" -type f -mtime +7 ! -name '.gitkeep' 2>/dev/null | wc -l | tr -d ' ')
    if [[ $count -gt 0 ]]; then
      log_info "Would delete $count old visualization file(s) (>7 days)"
    fi
  else
    find "$OUT/visualizations" -type f -mtime +7 ! -name '.gitkeep' -delete 2>/dev/null || true
    log_info "Deleted old visualization files (>7 days)"
  fi
  
  # Keep recent reports (last 3), remove older
  local reports_dir="$OUT/reports"
  if [[ -d "$reports_dir" ]]; then
    local total=$(count_files "$reports_dir")
    if [[ $total -gt 3 ]]; then
      local to_delete=$((total - 3))
      log_info "Keeping 3 most recent reports, removing $to_delete older report(s)"
      
      if [[ $DRY_RUN -eq 1 ]]; then
        find "$reports_dir" -type f ! -name '.gitkeep' -printf '%T@ %p\n' 2>/dev/null | \
          sort -n | head -n "$to_delete" | cut -d' ' -f2- | while read -r file; do
            log_verbose "Would delete: $file"
          done
      else
        find "$reports_dir" -type f ! -name '.gitkeep' -printf '%T@ %p\n' 2>/dev/null | \
          sort -n | head -n "$to_delete" | cut -d' ' -f2- | while read -r file; do
            log_verbose "Deleting: $file"
            rm -f "$file"
          done
      fi
    fi
  fi
  
  # Clean old artifacts
  clean_directory "$OUT/artifacts" "artifacts"
  
  log_info "Smart clean completed"
}

# Main cleaning logic
if [[ -n "$OLDER_THAN_DAYS" ]]; then
  clean_older_than
  exit 0
fi

if [[ -n "$KEEP_LAST" ]]; then
  clean_keep_last
  exit 0
fi

if [[ $DRY_RUN -eq 1 ]]; then
  log_warn "DRY RUN MODE - No files will be deleted"
fi

case $MODE in
  logs)
    clean_directory "$OUT/logs" "logs"
    ;;
  reports)
    clean_directory "$OUT/reports" "reports"
    ;;
  visualizations)
    clean_directory "$OUT/visualizations" "visualizations"
    ;;
  artifacts)
    clean_directory "$OUT/artifacts" "artifacts"
    ;;
  pids)
    clean_directory "$OUT/pids" "PIDs"
    ;;
  soak)
    clean_directory "$OUT/soak" "soak test results"
    ;;
  smart)
    smart_clean
    ;;
  all)
    log_info "Full clean mode: removing all generated files..."
    
    # Show statistics before cleaning
    if [[ $VERBOSE -eq 1 ]]; then
      log_info "Current file counts:"
      echo "  - Logs: $(count_files "$OUT/logs")"
      echo "  - Reports: $(count_files "$OUT/reports")"
      echo "  - Visualizations: $(count_files "$OUT/visualizations")"
      echo "  - Artifacts: $(count_files "$OUT/artifacts")"
      echo "  - PIDs: $(count_files "$OUT/pids")"
      echo "  - Soak: $(count_files "$OUT/soak")"
    fi
    
    # Clean all subdirectories
    clean_directory "$OUT/logs" "logs"
    clean_directory "$OUT/reports" "reports"
    clean_directory "$OUT/visualizations" "visualizations"
    clean_directory "$OUT/artifacts" "artifacts"
    clean_directory "$OUT/pids" "PIDs"
    clean_directory "$OUT/soak" "soak test results"
    
    # Clean any stray files in root (preserving protected files)
    if [[ $DRY_RUN -eq 1 ]]; then
      find "$OUT" -maxdepth 1 -type f \
        ! -name 'README.md' \
        ! -name 'config.yaml' \
        ! -name '.gitignore' \
        -print0 2>/dev/null | while IFS= read -r -d '' file; do
          log_verbose "Would delete: $file"
        done
    else
      find "$OUT" -maxdepth 1 -type f \
        ! -name 'README.md' \
        ! -name 'config.yaml' \
        ! -name '.gitignore' \
        -delete 2>/dev/null || true
    fi
    
    if [[ $DRY_RUN -eq 0 ]]; then
      log_info "Cleaned $OUT (preserved README.md, config.yaml, .gitignore)"
    fi
    ;;
esac

if [[ $DRY_RUN -eq 1 ]]; then
  log_warn "Dry run completed. Run without --dry-run to actually delete files."
fi
