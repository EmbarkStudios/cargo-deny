# 08_target_filtering

This example shows how to filter dependencies based upon their target configuration.

## Config

```ini
targets = [
    { triple = "x86_64-unknown-linux-gnu" },
    { triple = "wasm32-unknown-unknown", features = ["atomics"] },
]
```

## Description

By default, cargo resolves every single dependency, including for target specific dependencies. However, it's unlikely that your project is actually built for all (143 at the time of this writing) targets that are built in to rustc itself, which means that there may be crates in your graph that are never actually compiled or used in any way. By specifying the `targets = []` configuration in your `deny.toml`, you can specify a list of targets you _actually_ are targeting, removing any crates that don't match at least 1 of the targets you specify.
