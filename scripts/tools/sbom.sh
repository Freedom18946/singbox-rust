#!/bin/bash
set -e

# SBOM (Software Bill of Materials) generation script
# Generates CycloneDX format SBOM for supply chain security and compliance

echo "🔍 Generating Software Bill of Materials (SBOM)"

# Configuration
OUTPUT_JSON="sbom.json"
OUTPUT_XML="sbom.xml"
METADATA_FILE="sbom-metadata.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
check_prerequisites() {
    echo "🔧 Checking prerequisites..."

    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}❌ cargo not found. Please install Rust.${NC}"
        exit 1
    fi

    # Check if cyclonedx-bom is available
    if ! command -v cyclonedx-bom &> /dev/null; then
        echo -e "${YELLOW}⚠️ cyclonedx-bom not found. Installing...${NC}"

        if ! cargo install cyclonedx-bom; then
            echo -e "${RED}❌ Failed to install cyclonedx-bom${NC}"
            exit 1
        fi
    fi

    echo -e "${GREEN}✅ Prerequisites OK${NC}"
    echo "cyclonedx-bom version: $(cyclonedx-bom --version)"
}

# Generate build metadata
generate_metadata() {
    echo "📊 Generating build metadata..."

    # Get git information
    GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")
    GIT_DIRTY=$(git diff --quiet 2>/dev/null || echo "dirty")

    # Get Rust information
    RUST_VERSION=$(rustc --version)
    CARGO_VERSION=$(cargo --version)

    # Get project information
    PROJECT_NAME=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].name' 2>/dev/null || echo "singbox-rust")
    PROJECT_VERSION=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version' 2>/dev/null || echo "unknown")

    # Get system information
    BUILD_OS=$(uname -s)
    BUILD_ARCH=$(uname -m)
    BUILD_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Create metadata file
    cat > "$METADATA_FILE" << EOF
{
  "generator": "sbom.sh",
  "generated_at": "$BUILD_TIMESTAMP",
  "project": {
    "name": "$PROJECT_NAME",
    "version": "$PROJECT_VERSION"
  },
  "git": {
    "commit": "$GIT_COMMIT",
    "branch": "$GIT_BRANCH",
    "tag": "$GIT_TAG",
    "dirty": "$GIT_DIRTY"
  },
  "build_environment": {
    "os": "$BUILD_OS",
    "architecture": "$BUILD_ARCH",
    "rust_version": "$RUST_VERSION",
    "cargo_version": "$CARGO_VERSION"
  },
  "sbom_files": {
    "json": "$OUTPUT_JSON",
    "xml": "$OUTPUT_XML"
  }
}
EOF

    echo -e "${GREEN}✅ Metadata generated: $METADATA_FILE${NC}"
}

# Generate SBOM using cyclonedx-bom
generate_sbom() {
    echo "🏗️ Generating SBOM with cyclonedx-bom..."

    # Generate JSON format SBOM
    echo "Generating JSON SBOM..."
    if cyclonedx-bom --output-format json --output-file "$OUTPUT_JSON"; then
        echo -e "${GREEN}✅ JSON SBOM generated: $OUTPUT_JSON${NC}"
    else
        echo -e "${RED}❌ Failed to generate JSON SBOM${NC}"
        return 1
    fi

    # Generate XML format SBOM if requested
    echo "Generating XML SBOM..."
    if cyclonedx-bom --output-format xml --output-file "$OUTPUT_XML" 2>/dev/null; then
        echo -e "${GREEN}✅ XML SBOM generated: $OUTPUT_XML${NC}"
    else
        echo -e "${YELLOW}⚠️ XML SBOM generation failed or not supported${NC}"
        # This is not critical, continue
    fi

    return 0
}

# Validate and enhance SBOM
validate_sbom() {
    echo "✅ Validating SBOM..."

    if [ ! -f "$OUTPUT_JSON" ]; then
        echo -e "${RED}❌ JSON SBOM file not found${NC}"
        return 1
    fi

    # Check if it's valid JSON
    if ! jq . "$OUTPUT_JSON" >/dev/null 2>&1; then
        echo -e "${RED}❌ Generated SBOM is not valid JSON${NC}"
        return 1
    fi

    # Get basic statistics
    COMPONENT_COUNT=$(jq '.components | length // 0' "$OUTPUT_JSON" 2>/dev/null || echo "0")
    SBOM_VERSION=$(jq -r '.specVersion // "unknown"' "$OUTPUT_JSON" 2>/dev/null || echo "unknown")
    SBOM_FORMAT=$(jq -r '.bomFormat // "unknown"' "$OUTPUT_JSON" 2>/dev/null || echo "unknown")

    echo "📋 SBOM Statistics:"
    echo "  Format: $SBOM_FORMAT"
    echo "  Spec Version: $SBOM_VERSION"
    echo "  Components: $COMPONENT_COUNT"
    echo "  File Size: $(stat -c%s "$OUTPUT_JSON" 2>/dev/null || stat -f%z "$OUTPUT_JSON" 2>/dev/null || echo "unknown") bytes"

    # Show sample of components
    if [ "$COMPONENT_COUNT" -gt 0 ] && command -v jq &> /dev/null; then
        echo ""
        echo "📦 Sample Components:"
        jq -r '.components[:10] | .[] | "  - \(.name) \(.version // "unknown") (\(.type // "library"))"' "$OUTPUT_JSON" 2>/dev/null || true

        if [ "$COMPONENT_COUNT" -gt 10 ]; then
            echo "  ... and $((COMPONENT_COUNT - 10)) more"
        fi
    fi

    echo -e "${GREEN}✅ SBOM validation passed${NC}"
    return 0
}

# Check for known security vulnerabilities (if tools available)
security_scan() {
    echo "🔒 Running security scan..."

    # Try cargo-audit if available
    if command -v cargo-audit &> /dev/null; then
        echo "Running cargo-audit..."
        if cargo audit --json > audit-report.json 2>/dev/null; then
            VULN_COUNT=$(jq '.vulnerabilities.count // 0' audit-report.json 2>/dev/null || echo "unknown")
            echo "  Security vulnerabilities found: $VULN_COUNT"

            if [ "$VULN_COUNT" != "0" ] && [ "$VULN_COUNT" != "unknown" ]; then
                echo -e "${YELLOW}⚠️ Security vulnerabilities detected. See audit-report.json${NC}"
            fi
        else
            echo "  cargo-audit scan failed or no issues found"
        fi
    else
        echo "  cargo-audit not available, skipping vulnerability scan"
    fi

    # Try cargo-deny if available
    if command -v cargo-deny &> /dev/null; then
        echo "Running cargo-deny..."
        if cargo deny check --format json > deny-report.json 2>/dev/null; then
            echo "  cargo-deny check passed"
        else
            echo "  cargo-deny found issues or is not configured"
        fi
    fi

    echo -e "${GREEN}✅ Security scan complete${NC}"
}

# Generate summary report
generate_summary() {
    echo "📄 Generating summary report..."

    # Create a human-readable summary
    cat > sbom-summary.txt << EOF
SBOM Generation Summary
======================
Generated: $(date -u +%Y-%m-%d\ %H:%M:%S\ UTC)
Project: $(jq -r '.metadata.component.name // "unknown"' "$OUTPUT_JSON" 2>/dev/null || echo "unknown")
Version: $(jq -r '.metadata.component.version // "unknown"' "$OUTPUT_JSON" 2>/dev/null || echo "unknown")

Files Generated:
- $OUTPUT_JSON ($(stat -c%s "$OUTPUT_JSON" 2>/dev/null || stat -f%z "$OUTPUT_JSON" 2>/dev/null || echo "?") bytes)
EOF

    if [ -f "$OUTPUT_XML" ]; then
        echo "- $OUTPUT_XML ($(stat -c%s "$OUTPUT_XML" 2>/dev/null || stat -f%z "$OUTPUT_XML" 2>/dev/null || echo "?") bytes)" >> sbom-summary.txt
    fi

    cat >> sbom-summary.txt << EOF
- $METADATA_FILE ($(stat -c%s "$METADATA_FILE" 2>/dev/null || stat -f%z "$METADATA_FILE" 2>/dev/null || echo "?") bytes)
- sbom-summary.txt (this file)

Component Summary:
EOF

    if command -v jq &> /dev/null && [ -f "$OUTPUT_JSON" ]; then
        echo "Total Components: $(jq '.components | length // 0' "$OUTPUT_JSON")" >> sbom-summary.txt

        # Count by type
        jq -r '.components | group_by(.type) | .[] | "\(.[0].type // "unknown"): \(length)"' "$OUTPUT_JSON" >> sbom-summary.txt 2>/dev/null || true

        echo "" >> sbom-summary.txt
        echo "Top Dependencies:" >> sbom-summary.txt
        jq -r '.components[:10] | .[] | "- \(.name) \(.version // "unknown")"' "$OUTPUT_JSON" >> sbom-summary.txt 2>/dev/null || true
    fi

    echo -e "${GREEN}✅ Summary report generated: sbom-summary.txt${NC}"
}

# Clean up old files
cleanup_old() {
    echo "🧹 Cleaning up old SBOM files..."

    # Remove old SBOM files to avoid confusion
    rm -f sbom-*.json sbom-*.xml audit-report-*.json deny-report-*.json

    echo "Old SBOM files cleaned up"
}

# Main execution
main() {
    echo -e "${BLUE}🔍 SBOM Generation Script${NC}"
    echo "=========================="
    echo "This script generates a Software Bill of Materials (SBOM) for supply chain security"
    echo ""

    # Cleanup first
    cleanup_old

    # Run all steps
    check_prerequisites
    generate_metadata
    generate_sbom
    validate_sbom
    security_scan
    generate_summary

    echo ""
    echo -e "${GREEN}🎉 SBOM generation completed successfully!${NC}"
    echo ""
    echo "Generated files:"
    ls -la sbom*.* *.json *.txt audit-report.json deny-report.json 2>/dev/null || true

    echo ""
    echo "📋 Next steps:"
    echo "- Review the generated SBOM files"
    echo "- Upload to your dependency tracking system"
    echo "- Include in release artifacts"
    echo "- Use for compliance and security monitoring"
}

# Error handling
trap 'echo -e "${RED}❌ SBOM generation failed${NC}"; exit 1' ERR

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h    Show this help message"
        echo "  --clean       Only clean up old files"
        echo ""
        echo "This script generates CycloneDX format SBOM files for the project."
        echo "Requires: cargo, cyclonedx-bom (will be installed if missing)"
        exit 0
        ;;
    --clean)
        cleanup_old
        exit 0
        ;;
esac

# Run main function
main