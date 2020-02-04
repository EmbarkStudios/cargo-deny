# Command Line Tool

cargo-deny can be used either as a command line tool or as a
[Rust crate](https://crates.io/crates/cargo-deny). Let's focus on the command 
line tool capabilities first.

## Install From Binaries

Precompiled binaries are provided for major platforms on a best-effort basis.
Visit [the releases page](https://github.com/EmbarkStudios/cargo-deny/releases)
to download the appropriate version for your platform.

## Install From Source

cargo-deny can also be installed from source.

### Pre-requisites

cargo-deny is written in **[Rust](https://www.rust-lang.org/)** and therefore 
needs to be compiled with **Cargo**. If you haven't already installed Rust, 
please go ahead and [install it](https://www.rust-lang.org/tools/install) now.

cargo-deny depends on some crates that use C code, so you will also need to have
a C toolchain available on your machine, such as gcc, clang, or msvc.

### Install Crates.io version

Installing cargo-deny is relatively easy if you already have Rust and Cargo
installed. You just have to type this snippet in your terminal:

```bash
cargo install cargo-deny
```

This will fetch the source code for the latest release from
[Crates.io](https://crates.io/) and compile it. You will have to add Cargo's
`bin` directory to your `PATH` if you have not done so already.

Run `cargo deny help` in your terminal to verify if it works. Congratulations,
you have installed cargo-deny!

### Install Git version

The **[git version](https://github.com/EmbarkStudios/cargo-deny)** contains all
the latest bug-fixes and features, that will be released in the next version on
**Crates.io**, if you can't wait until the next release. You can build the git
version yourself.

```bash
cargo install --git https://github.com/EmbarkStudios/cargo-deny cargo-deny
```

Run `cargo deny help` in your terminal to verify if it works. Congratulations,
you have installed cargo-deny!

## CI Usage

We now have a Github Action for running cargo-deny on your Github repositories, 
check it out [here](https://github.com/EmbarkStudios/cargo-deny-action).

If you don't want to use the action, you can manually download (or install)
cargo-deny as described above, but here's an example script that you can copy
to get you started.

```bash
#!/bin/bash
set -eu

NAME="cargo-deny"
VS="0.5.2"
DIR="/tmp/$NAME"

mkdir $DIR

# Download the tarball
curl -L -o $DIR/archive.tar.gz https://github.com/EmbarkStudios/$NAME/releases/download/$VS/$NAME-$VS-x86_64-unknown-linux-musl.tar.gz

# Unpack the tarball into the temp directory
tar -xzvf $DIR/archive.tar.gz --strip-components=1 -C $DIR

# Run cargo deny check in our current directory
$DIR/$NAME --context . -L debug check bans licenses advisories
```
