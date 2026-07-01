# Misc Examples

This directory contains helper inputs and intentionally invalid fixtures.

## Intentionally Invalid

- `config.bad.json`
  Invalid config used to confirm that `app check` reports schema errors.

## Valid Helper Inputs

- `subs.nodes.sample.json`
  Valid subscription node-list sample for `examples/schemas/subs.schema.json`.
- `v1_dns.yml`
- `v1_minimal.yml`
- `v1_proxy.yml`
- `v2_proxy.yml`

## Non-config Helper Data

- `dns_pool_example.env`
- `targets.auto.txt`
- `targets.sample.txt`

Do not treat every file in this directory as a runnable `app run` config.

`subs.bad.json` is intentionally invalid against `examples/schemas/subs.schema.json`.
