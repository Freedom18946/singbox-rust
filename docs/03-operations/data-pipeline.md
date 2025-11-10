Data Pipeline — Rules & Geodata
================================

Repository Layout (suggested)
- rules/: Source rule-sets in JSON (sing-box rule-set source format)
- out/: Compiled binary rule-sets (.srs)
- data/: GeoIP/Geosite databases (geoip.db, geosite.db)
- bundle/: Release bundles (tar.gz + sha256)

Local Workflow
- Compile rules:
  - cargo build -q
  - scripts/tools/compile-rulesets.sh --in ./rules --out ./out --bin target/debug/app
- Fetch geodata:
  - scripts/tools/update-geodata.sh --dest ./data
- Bundle:
  - scripts/tools/make-data-bundle.sh --data ./data --rules ./out --out ./bundle
 - Manifest (checksums and sizes):
   - scripts/tools/gen-data-manifest.sh --data ./data --rules ./out --out ./bundle

CI Workflow (GitHub Actions)
- File: .github/workflows/data-bundle.yml
- Trigger: push (rules/**.json) or manual dispatch
- Inputs (workflow_dispatch):
  - geoip_url / geosite_url: pin specific release URLs
  - geoip_sha256 / geosite_sha256: integrity checks
  - features: override cargo features (default: router,explain)
  - artifact_suffix: override artifact name suffix
- Steps:
  - Build CLI with features router,explain
  - Compile rules into ./out
  - Fetch geodata into ./data
  - Produce bundle in ./bundle
  - Generate manifest.txt and manifest.json in ./bundle
  - Upload ./bundle as artifacts
  - Artifact name defaults to: singbox-data-bundle-<ref>-<shortsha>

Integrity & Rollback
- You may pin checksums for geodata via env (used by update-geodata.sh):
  - GEOIP_SHA256, GEOSITE_SHA256
- If checksum fails, the CI job aborts and previous bundles remain intact.

Verification
- Verify a manifest (text or JSON):
  - scripts/tools/verify-data-manifest.sh --manifest ./bundle/manifest.txt --root .
  - scripts/tools/verify-data-manifest.sh --manifest ./bundle/manifest.json --root .

Pinned Example (manual dispatch)
- geoip_url: https://github.com/SagerNet/sing-geoip/releases/download/2024-10-01/geoip.db
- geosite_url: https://github.com/SagerNet/sing-geosite/releases/download/2024-10-01/geosite.db
- geoip_sha256: <paste expected sha256>
- geosite_sha256: <paste expected sha256>

Notes
- Source format version is kept in JSON (`version` field). When compiling, you can force a target version with `--version`.
- Rule-set conversion/merge/upgrade are available via `app rule-set ...` CLI for ad-hoc tasks.
