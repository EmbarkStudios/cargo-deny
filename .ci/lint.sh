#!/bin/bash
set -e

travis_fold start "rustup.component.install"
    travis_time_start
        rustup component add rustfmt clippy
    travis_time_finish
travis_fold end "rustup.component.install"

# Ensure everything has been rustfmt'ed
travis_fold start "rustfmt"
    travis_time_start
        cargo fmt -- --check
    travis_time_finish
travis_fold end "rustfmt"

# Download in a separate step to separate
# building from fetching dependencies
travis_fold start "cargo.fetch"
    travis_time_start
        cargo fetch
    travis_time_finish
travis_fold end "cargo.fetch"

# Because rust isn't brutal enough itself
travis_fold start "clippy"
    travis_time_start
        cargo clippy -- -D warnings
    travis_time_finish
travis_fold end "clippy"
