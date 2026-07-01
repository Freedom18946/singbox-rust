# Data Pipeline: Rules And Geodata

Workflow automation is disabled in this repository. Build, fetch, bundle, and
verification steps are local/manual operations.

## Repository Layout

- `rules/`: source rule sets in sing-box JSON rule-set format
- `out/`: compiled binary rule sets (`.srs`)
- `data/`: GeoIP/Geosite databases (`geoip.db`, `geosite.db`)
- `bundle/`: local release bundle outputs and checksums

## Local Workflow

Build the current CLI:

```bash
cargo build -p app
```

Compile rule sets:

```bash
scripts/tools/compile-rulesets.sh --in ./rules --out ./out --bin target/debug/app
```

Fetch geodata:

```bash
scripts/tools/update-geodata.sh --dest ./data
```

Create the bundle and manifest:

```bash
scripts/tools/make-data-bundle.sh --data ./data --rules ./out --out ./bundle
scripts/tools/gen-data-manifest.sh --data ./data --rules ./out --out ./bundle
```

## Integrity And Rollback

You may pin checksums for geodata with `update-geodata.sh` arguments:

- `--geoip-sha256`
- `--geosite-sha256`

If checksum verification fails, stop and keep the previous bundle in place.

## Verification

Verify the generated manifest before publishing or copying the bundle:

```bash
scripts/tools/verify-data-manifest.sh --manifest ./bundle/manifest.txt --root .
scripts/tools/verify-data-manifest.sh --manifest ./bundle/manifest.json --root .
```

## Pinned Source Example

```bash
scripts/tools/update-geodata.sh \
  --dest ./data \
  --geoip-url https://github.com/SagerNet/sing-geoip/releases/download/2024-10-01/geoip.db \
  --geosite-url https://github.com/SagerNet/sing-geosite/releases/download/2024-10-01/geosite.db \
  --geoip-sha256 <expected-geoip-sha256> \
  --geosite-sha256 <expected-geosite-sha256>
```

## Notes

- Source format version is kept in JSON (`version` field). When compiling, you
  can force a target version with `--version`.
- Rule-set conversion, merge, and upgrade are available via `app ruleset ...`
  for ad-hoc tasks.
