# The init command

cargo-deny's configuration is a little bit complicated, so we provide the `init`
command to create a configuration file from a template for you to give you a
starting point for configuring how you want cargo-deny to lint your project.

The `init` command is used like this:

```bash
cargo deny init
```

### Specify a path

The `init` command can take a path as an argument to use as path of the config
instead of the default which is `<cwd>/deny.toml`.

```bash
cargo deny init path/to/config.toml
```

### Template

A `deny.toml` file will be created in the current working directory that is a
direct copy of [this template](https://github.com/EmbarkStudios/cargo-deny/blob/main/deny.template.toml).

```ini
{{#include ../../../deny.template.toml}}
```
