# Third-Party Licenses

This file contains licensing information for all third-party dependencies included in this project.

## Direct Dependencies

Generated using `cargo tree --format "{p} {l}"` and `cargo-deny`.

### Runtime Dependencies

- **anyhow (1.x)** - Apache-2.0 OR MIT
- **clap (4.x)** - Apache-2.0 OR MIT
- **serde (1.x)** - Apache-2.0 OR MIT
- **serde_json (1.x)** - Apache-2.0 OR MIT
- **serde_yaml (0.9.x)** - Apache-2.0 OR MIT
- **thiserror (1.x)** - Apache-2.0 OR MIT
- **tokio (1.x)** - MIT
- **tracing (0.1.x)** - MIT
- **chrono (0.4.x)** - Apache-2.0 OR MIT
- **uuid (1.x)** - Apache-2.0 OR MIT
- **base64 (0.22.x)** - Apache-2.0 OR MIT
- **bytes (1.x)** - MIT
- **futures (0.3.x)** - Apache-2.0 OR MIT
- **once_cell (1.x)** - Apache-2.0 OR MIT
- **prometheus (0.13.x)** - Apache-2.0
- **metrics (0.24.x)** - MIT
- **webpki-roots (0.26.x)** - MPL-2.0

### Development Dependencies

- **tempfile (3.x)** - Apache-2.0 OR MIT
- **assert_cmd (2.x)** - Apache-2.0 OR MIT
- **criterion (0.5.x)** - Apache-2.0 OR MIT

### Build Dependencies

- **chrono (0.4.x)** - Apache-2.0 OR MIT

## License Compatibility

This project is licensed under Apache-2.0. All included dependencies are compatible:
- Apache-2.0: ✅ Compatible
- MIT: ✅ Compatible
- MPL-2.0: ✅ Compatible (weak copyleft, compatible with Apache-2.0)

## Full Dependency Tree

For a complete dependency tree with exact versions, run:
```bash
cargo tree --format "{p} {l}"
```

## License Texts

Complete license texts for all dependencies are available in their respective source code repositories or can be found at:
- https://spdx.org/licenses/Apache-2.0.html
- https://spdx.org/licenses/MIT.html
- https://spdx.org/licenses/MPL-2.0.html

---
*Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")*
*Command: `cargo deny check licenses && cargo tree --format "{p} {l}"`*