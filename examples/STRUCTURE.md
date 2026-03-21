# Examples Structure

`examples/` is split by purpose rather than by historical phase.

- `quick-start/`
  Minimal runnable configs. These are the safest entry point for manual testing.
- `configs/`
  Curated protocol-specific and scenario-specific configs that still validate today.
- `misc/`
  Helper inputs, compatibility samples, and negative fixtures.
- `rules/`
  Rule fragments only. Do not pass this directory directly to `app run` unless a file is documented as a full config.
- `dsl/`
  DSL syntax references.
- `schemas/`
  Exported schemas and schema maps.
- `code-examples/`
  Rust code snippets and test fixture data.

Maintenance rules:

- `cargo run -p app -- check -c ...` is the acceptance gate for every runnable config here.
- Intentionally invalid inputs must live under `misc/` and be called out explicitly.
- Historical or obsolete examples are deleted instead of being left in place with stale claims.
