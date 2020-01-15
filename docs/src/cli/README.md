# Command Line Tool

cargo-deny can be used either as a command line tool or a [Rust
crate](https://crates.io/crates/cargo-deny). Let's focus on the command line 
tool capabilities first.

## Install From Binaries

Precompiled binaries are provided for major platforms on a best-effort basis.
Visit [the releases page](https://github.com/EmbarkStudios/cargo-deny/releases)
to download the appropriate version for your platform.

## Install From Source

cargo-deny can also be installed from source

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
version yourself. Open your terminal and navigate to the directory of your
choice. We need to clone the git repository and then build it with Cargo.

```bash
cargo install --git https://github.com/EmbarkStudios/cargo-deny cargo-deny
```

Run `cargo deny help` in your terminal to verify if it works. Congratulations,
you have installed cargo-deny!
