#!/bin/bash
set -e

HOST_OS_NAME=$(uname -s)
TARGET=""

if [ "$(uname)" == "Darwin" ]; then
    TARGET="apple-darwin"
elif [ "${HOST_OS_NAME::5}" == "Linux" ]; then
    # If we're on linux, always build for musl
    TARGET="unknown-linux-musl"
    .ci/install_musl.sh
elif [ "${HOST_OS_NAME::10}" == "MINGW64_NT" ]; then
    TARGET="pc-windows-msvc"
elif [ "${HOST_OS_NAME::7}" == "MSYS_NT" ]; then # travis uses msys
    TARGET="pc-windows-msvc"
elif [ "${HOST_OS_NAME::10}" == "MINGW32_NT" ]; then
    echo "Why are you on a 32-bit machine?"
    exit 1
else
    echo "Unknown host platform! '$HOST_OS_NAME'"
    exit 1
fi

TARGET="x86_64-$TARGET"

# Fetch dependencies in a different step to clearly
# delineate between downloading and building
travis_fold start "cargo.fetch"
    travis_time_start
        cargo fetch
    travis_time_finish
travis_fold end "cargo.fetch"

# Build without running to clearly delineate between
# building and running the tests
travis_fold start "cargo.build"
    travis_time_start
        cargo test --no-run --target $TARGET
    travis_time_finish
travis_fold end "cargo.build"

travis_fold start "cargo.test"
    travis_time_start
        cargo test --target $TARGET
    travis_time_finish
travis_fold end "cargo.test"
