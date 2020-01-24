# The `[licenses]` section

Contains all of the configuration for `cargo deny check license`.

## Example

```ini
{{#include ../../../../tests/cfg/licenses.toml}}
```

### The `unlicensed` field (optional)

Determines what happens when a crate has not explicitly specified its license 
terms, and no license information could be easily detected via `LICENSE*` files 
in the crate's source.

* `deny` (default) - All unlicensed crates will emit an error and fail the 
license check
* `allow` - All unlicensed crates will show a note, but will not fail the 
license check
* `warn` - All unlicensed crates will show a warning, but will not fail the 
license check

### The `allow` and `deny` fields (optional)

The licenses that should be allowed or denied. The license must be a valid 
SPDX v2.1 identifier, which must either be in version 3.7 of the 
[SPDX License List](https://spdx.org/licenses/), with an optional 
[exception](https://spdx.org/licenses/exceptions-index.html) specified by 
`WITH <exception-id>`, or else a user defined license reference denoted by 
`LicenseRef-<idstring>` for a license not in the SPDX License List.

**NOTE:** The same license cannot appear in both the `allow` and `deny` lists.

#### GNU licenses

* GPL
* AGPL
* LGPL
* GFDL

The GNU licenses are, of course, different from all the other licenses in the 
SPDX list which makes them annoying to deal with. When supplying one of the 
above licenses, to either `allow` or `deny`, you **must not** use the suffixes 
`-only` or `-or-later`, as they can only be used by the license holder 
themselves to decide under which terms to license their code.

So, for example, if you we wanted to disallow `GPL-2.0` licenses, but allow 
`GPL-3.0` licenses, we could use the following configuration.

```toml
[licenses]
allow = [ "GPL-3.0" ]
deny = [ "GPL-2.0" ]
```

### The `exceptions` field (optional)

The license configuration generally applies the entire crate graph, but this 
means that allowing a specific license applies to all possible crates, even if 
only 1 crate actually uses that license. The `exceptions` field is meant to 
allow licenses only for particular crates, to make a clear distinction between 
licenses which you are fine with everywhere, versus ones which you want to be 
more selective about, and not have implicitly allowed in the future.

#### The `name` field

The name of the crate that you are adding an exception for

#### The `version` field (optional)

An optional version constraint specifying the range of crate versions you are 
excepting. Defaults to all versions (`*`).

#### The `allow` field

This is the exact same as the general `allow` field.

```toml
[licenses]
allow = [
    "Apache-2.0",
    "MIT",
]
exceptions = [
    # This is the only crate that cannot be licensed with either Apache-2.0
    # or MIT, so we just add an exception for it, meaning we'll get a warning
    # if we add another crate that also requires this license
    { name = "cloudabi", allow = ["BSD-2-Clause"] },
]
```

### The `copyleft` field (optional)

Determines what happens when a license that is considered
[copyleft](https://en.wikipedia.org/wiki/Copyleft) is encountered.

* `warn` (default) - Will emit a warning that a copyleft license was detected, 
but will not fail the license check
* `deny` - The license is not accepted if it is copyleft, but the license check
might not fail if the expression still evaluates to true
* `allow` - The license is accepted if it is copyleft

### The `allow-osi-fsf-free` field (optional)

Determines what happens when licenses aren't explicitly allowed or denied, but 
**are** marked as [OSI Approved](https://opensource.org/licenses) or 
[FSF Free/Libre](https://www.gnu.org/licenses/license-list.en.html) in version
3.7 of the [SPDX License List](https://spdx.org/licenses/).

* `both` - The license is accepted if it is both OSI approved and FSF Free
* `either` - The license is accepted if it is either OSI approved or FSF Free
* `osi-only` - The license is accepted if it is OSI approved and not FSF Free
* `fsf-only` - The license is accepted if it is FSF Free and not OSI approved
* `neither` (default) - No special consideration is given the license

### The `confidence-threshold` field (optional)

`cargo-deny` uses [askalono](https://github.com/amzn/askalono) to determine the 
license of a license file. Due to variability in license texts due to things
like authors, copyright year, and so forth, askalano assigns a confidence score
to its determination, from `0.0` (no confidence) to `1.0` (perfect match). The 
confidence threshold value is used to reject the license determination if the
score does not match or exceed the threshold.

`0.0` - `1.0` (default `0.8`)

### The `clarify` field (optional)

In some exceptional cases, the crates do not have easily machine readable 
license information, and would by default be considered "unlicensed" by 
cargo-deny. As a (hopefully) temporary patch for using the crate, you can 
specify a clarification for the crate by manually assigning its SPDX expression,
based on one or more files in the crate's source. cargo-deny will use that
expression as long as the source files in the crate don't change.

#### The `name` field

The name of the crate that you are clarifying

#### The `version` field (optional)

An optional version constraint specifying the range of crate versions you are
clarifying. Defaults to all versions (`*`).

#### The `expression` field

The [SPDX license expression][SPDX-expr] you are specifying as the license 
requirements for the crate.

#### The `license-files` field

Contains one or more files that will be checked to ensure the license 
expression still applies to a version of the crate. 

##### The `path` field

The crate relative path to a file to be used as a source of truth.

##### The `hash` field

An opaque hash calculated from the file contents. This hash can be obtained
from the output of the license check when cargo-deny can't determine the license
of the file in question.

### The `private` field

It's often not useful or wanted to check for licenses in your own private
workspace crates. So the private field allows you to do so.

#### The `ignore` field

If `true`, workspace members will not have their license expression checked if
they are not published.

```ini
[package]
name = "sekret"
license = "¯\_(ツ)_/¯"
publish = false # "private"!
```

```ini
[licenses]
# The sekret package would be ignored now
private = { ignore = true }
```

### The `registries` field

A list of private registries you may publish your workspace crates to. If a
workspace member **only** publishes to private registries, it will also be 
ignored if `privite.ignore = true`

```ini
[package]
name = "sekret"
license = "¯\_(ツ)_/¯"
publish = ["sauce"]
```

```ini
[licenses]
# Still ignored!
private = { ignore = true, registries = ["sauce"] }
```

[SPDX-expr]: https://spdx.org/spdx-specification-21-web-version#h.jxpfx0ykyb60
