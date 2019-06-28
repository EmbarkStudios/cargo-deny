#!/bin/bash
set -e

travis_fold start "apt-get.musl"
    travis_time_start
        sudo apt-get update && sudo -E apt-get -yq --no-install-suggests --no-install-recommends install musl-tools
    travis_time_finish
travis_fold end "apt-get.musl"

travis_fold start "rustup.target.musl"
    travis_time_start
        rustup target add x86_64-unknown-linux-musl
    travis_time_finish
travis_fold end "rustup.target.musl"
