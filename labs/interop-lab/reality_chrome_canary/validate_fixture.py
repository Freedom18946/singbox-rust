#!/usr/bin/env python3
"""Validate sanitized Chrome-current fixture and REALITY transform contract."""
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_FIXTURE = HERE / "fixtures/chrome_150_stable_mac_arm64.json"


def validate(fixture):
    errors = []
    provenance = fixture.get("provenance", {})
    observed = fixture.get("browser_observed", {})
    expected = fixture.get("reality_expected_shape", {})
    transform = fixture.get("transform", {})
    group = transform.get("removed_supported_group")
    key_group = transform.get("removed_key_share_group")
    if provenance.get("raw_committed") is not False:
        errors.append("raw_committed must be false")
    if provenance.get("product", "").lower().find("full browser") < 0:
        errors.append("fixture must identify full-browser product surface")
    if group not in observed.get("supported_groups", []):
        errors.append("removed supported group absent from browser observation")
    if group in expected.get("supported_groups", []):
        errors.append("removed supported group remains in REALITY shape")
    observed_key_groups = [x.get("group") for x in observed.get("key_share_groups", [])]
    expected_key_groups = [x.get("group") for x in expected.get("key_share_groups", [])]
    if key_group not in observed_key_groups or key_group in expected_key_groups:
        errors.append("key-share transform mismatch")
    if expected.get("trust_anchors") != {"list_length": 0, "payload_length": 2}:
        errors.append("trust_anchors payload mismatch")
    if expected.get("signature_algorithms_in_order", [])[:3] != ["0x0904", "0x0905", "0x0906"]:
        errors.append("Chrome 150 ML-DSA signature algorithms missing")
    if fixture.get("reality_record_length_ladder_spacing") != 32:
        errors.append("REALITY record-length ladder spacing must be 32")
    if fixture.get("reality_from_spec_ja4") != observed.get("from_spec_ja4"):
        errors.append("REALITY JA4 must match Chrome after MLKEM removal")
    return errors


def main():
    fixture = json.loads(DEFAULT_FIXTURE.read_text())
    errors = validate(fixture)
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"PASS chrome-current fixture {provenance_label(fixture)}")


def provenance_label(fixture):
    p = fixture["provenance"]
    return f"{p['version']} {p['platform']} samples={p['sample_count']}"


if __name__ == "__main__":
    main()
