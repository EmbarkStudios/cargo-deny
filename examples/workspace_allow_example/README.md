# Workspace Allow Example

This example demonstrates the `allow-workspace` feature that enables a "deny external dependencies by default, but allow workspace crates" policy.

## Configuration

The `deny.toml` file shows how to:

1. **Deny all external dependencies by default**: `deny = [{ name = "*" }]`
2. **Automatically allow workspace members**: `allow-workspace = true`
3. **Explicitly allow blessed external dependencies**: List approved crates in the `allow` section

## Benefits

This configuration pattern is useful for organizations that want to:

- Maintain strict control over external dependencies
- Avoid having to manually list every workspace crate in the allow list
- Ensure consistent dependency policies across all Rust projects
- Reduce configuration maintenance overhead

## How it works

When `allow-workspace = true`:

- All workspace members are automatically treated as allowed
- Workspace members take precedence over explicit `deny` entries
- External dependencies still require explicit allowlisting
- Works for both single-crate and multi-crate workspaces

## Example scenarios

### ✅ Allowed
- Workspace crates (automatically allowed)
- External crates in the `allow` list (e.g., `serde`, `tokio`, `clap`)

### ❌ Blocked
- External crates not in the `allow` list
- Any dependency that would normally be denied

This approach eliminates the need for complex workarounds like dynamically modifying deny.toml files or using fragile sed/awk scripts to handle workspace crates.
