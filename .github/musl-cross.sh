#!/bin/env bash
set -e

root="$RUNNER_TEMP/musl"
bin="$root/bin"
target="aarch64-linux-musl"
mkdir -p "$root"
curl -fsSL "https://musl.cc/$target-cross.tgz" | tar --strip-components=1 -C "$root" -xzf -

MUSL_INCLUDE="$(find "$root/lib/gcc/$target/" -maxdepth 2 -type d -name 'include' | head -n 1)"

echo "$bin" >> "$GITHUB_PATH"

{
    echo "AR_aarch64_unknown_linux_musl=$bin/$target-ar";
    echo "CC_aarch64_unknown_linux_musl=$bin/$target-gcc";
    echo "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$bin/$target-ld";
    echo "CFLAGS_aarch64_unknown_linux_musl=-nostdinc -nostdlib -isystem$root/$target/include -I ${MUSL_INCLUDE}";
} >> "$GITHUB_ENV"

unset CFLAGS MUSL_INCLUDE