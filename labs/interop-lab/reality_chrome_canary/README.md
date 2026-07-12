# REALITY Chrome-current canary

Offline, sanitized drift oracle for production Chrome ClientHello shape. Current fixture targets
full Chrome for Testing 150.0.7871.115 mac-arm64. Raw ClientHello records stay outside repository;
fixture retains structural fields, JA4, record buckets, product surface, version, source.

Two lanes remain distinct:

- Chrome-current lane: Rust REALITY shape must match `reality_expected_shape`; X25519MLKEM768
  group/key share are removed by documented REALITY transform.
- Go compatibility lane: pinned `metacubex/utls v1.8.4` / `HelloChrome_133` remains functional
  compatibility oracle, not current-browser camouflage oracle.

Run:

```sh
python3 labs/interop-lab/reality_chrome_canary/validate_fixture.py
python3 -m unittest discover -s labs/interop-lab/reality_chrome_canary/tests
```

Refreshing fixture requires full Chrome product capture, parser redaction, provenance update, local
review. Headless-shell observations cannot replace full-browser fixture because Chrome 150 surfaces
different extension set (`trust_anchors` absent in headless-shell).

Known boundary: ML-DSA schemes are advertised for Chrome wire parity, but current rustls crypto
provider cannot verify ML-DSA certificates. Conventional WebPKI certificate paths are locally gated;
ML-DSA-certificate interoperability remains unsupported until provider support exists.
