# `rule-set` Command

Compile, validate, convert, and merge rule-set files.

## Usage

```bash
cargo run -p app -- ruleset compile rules.json --out rules.srs
cargo run -p app -- ruleset validate rules.srs
cargo run -p app -- ruleset merge a.srs b.srs --out merged.srs
```
