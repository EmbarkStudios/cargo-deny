# The init command

cargo-deny's configuration is a little bit complicated, so we provide the `init` command to create a configuration file from a template for you to give you a starting point for configuring how you want cargo-deny to lint your project.

The `init` command is used like this:

```bash
cargo deny init
```

## Specify a path

Using the root `--config` option can be used to change the default path (`<cwd>/deny.toml`) of the config file created.

```bash
cargo deny --config path/to/config.toml init
```

## Template

A `deny.toml` file will be created in the current working directory that is a direct copy of [this template](https://github.com/EmbarkStudios/cargo-deny/blob/main/deny.template.toml).

```ini
{{#include ../../../deny.template.toml}}
```
