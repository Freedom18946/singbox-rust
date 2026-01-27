# Troubleshooting (User Guide)

This page provides quick triage steps and links to the main troubleshooting guide.

## Quick checks

1. Validate config
   ```bash
   singbox-rust check -c config.yaml
   ```
2. Test routing
   ```bash
   singbox-rust route -c config.yaml --dest example.com:443 --explain
   ```
3. Enable debug logs
   ```bash
   RUST_LOG=debug singbox-rust run -c config.yaml
   ```

## Main guide

- [Troubleshooting](../TROUBLESHOOTING.md)
