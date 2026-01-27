# Feature Flags

Overview of feature flag usage across the workspace.

## Notes

- Features are defined in workspace and crate `Cargo.toml` files
- App features gate optional protocols and services

## Examples

```bash
cargo build -p app --features "acceptance,metrics"
cargo build -p app --no-default-features --features "router"
```

## References

- App manifest: `app/Cargo.toml`
- Workspace manifest: `Cargo.toml`
