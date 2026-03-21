# Examples

This directory now tracks only examples that match the current CLI and schema surface.

Validation rule:

```bash
cargo run -p app -- check -c <path>
```

What is kept:

- `quick-start/`: minimal runnable configs validated against the current implementation
- `configs/`: curated protocol and routing examples that still pass `app check`
- `misc/`: helper inputs plus explicitly invalid negative fixtures
- `rules/`: rule fragments and snippets, not full `app run` configs
- `dsl/`, `schemas/`, `code-examples/`: reference material and source examples

What was removed:

- stale validation reports
- configs that only documented obsolete fields
- files that no longer matched the live route or admin schema

Recommended starting points:

- `examples/quick-start/01-minimal.yaml`
- `examples/quick-start/02-socks5-direct.yaml`
- `examples/quick-start/05-basic-routing.yaml`
- `examples/configs/inbounds/minimal_http.json`
- `examples/configs/routing/rules_demo.json`

Negative fixtures:

- `examples/misc/config.bad.json`

`examples/misc/subs.bad.json` is still kept as malformed subscription input, but it is not part of the `app check` passing or failing set.
