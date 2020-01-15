# The init command

cargo-deny's configuration is a little bit complicated, so we provide the `init`
command to create a configuration file from a template for you to give you a
starting point for configuring how you want cargo-deny to lint your project.

The `init` command is used like this:

```bash
cargo deny init
```

A `deny.toml` file will be created in the current working directory which gives
you a skeleton of a configuration file with comments about what certain values
mean.

#### Specify a path

The `init` command can take a path as an argument to use as path of the config
instead of the default which is `<cwd>/deny.toml`.

```bash
cargo deny init path/to/config.toml
```
