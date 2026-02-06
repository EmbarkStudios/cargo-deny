# The `list` command

Similarly to [cargo-license](https://github.com/onur/cargo-license), `list` prints out the license information for each crate.

## Options

### `-c, --config <CONFIG>`

Path to the config to use

Defaults to `<cwd>/deny.toml` if not specified

### `-f, --format`

The format of the output

* `human` (default) - Simple format where each crate or license is its own line
* `json`
* `markdown`
* `tsv`

### [`--color`](../cli/common.md#--color)

Colors:

* SPDX identifier - ![blue](https://placehold.it/15/5dade2/000000?text=+)
* Crate with 1 license - ![white](https://placehold.it/15/717d7e/000000?text=+)
* Crate with 2 or more licenses - ![yellow](https://placehold.it/15/f1c40f/000000?text=+)
* Crate with 0 licenses - ![yellow](https://placehold.it/15/e74c3c/000000?text=+)

### `-l, --layout`

The layout of the output. Does not apply to the `tsv` format.

* `license` (default) - Each license acts as the key, and the values are all of the crates that use that license
* `crate` - Each crate is a key, and the values are the list of licenses it uses.

### `-t, --threshold`

The confidence threshold required for assigning a license identifier to a license text file. See the [license configuration](../checks/licenses/cfg.md#the-confidence-threshold-field-optional) for more information.

* `layout = license, format = human` (default)

![Imgur](https://i.imgur.com/Iejfc7h.png)

* `layout = crate, format = human`

![Imgur](https://i.imgur.com/zZdcFXI.png)

* `layout = license, format = json`

![Imgur](https://i.imgur.com/wC2R0ym.png)

* `layout = license, format = tsv`

![Imgur](https://i.imgur.com/14l8a5K.png)
