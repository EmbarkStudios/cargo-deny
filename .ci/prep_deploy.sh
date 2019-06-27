#!/bin/bash
set -e

# Fetch dependencies in a different step to clearly
# delineate between downloading and building
travis_fold start "cargo.fetch"
    travis_time_start
        cargo fetch --target "$TARGET"
    travis_time_finish
travis_fold end "cargo.fetch"

# Build without running to clearly delineate between
# building and packaging
travis_fold start "cargo.build"
    travis_time_start
        cargo build --release --target "$TARGET"
    travis_time_finish
travis_fold end "cargo.build"

travis_fold start "package.release"
    travis_time_start
        name="cargo-deny"
        release_name="$name-$TRAVIS_TAG-$TARGET"
        mkdir "$release_name"

        if [ "$TARGET" == "x86_64-pc-windows-msvc" ]; then
            # We don't use name again, so just add the exe extension
            # to it and call it a day
            name="$name.exe"
        else
            # If we're not on windows, strip the binary to remove
            # debug symbols and minimize the resulting release
            # size without much effort
            strip "target/$TARGET/release/$name"
        fi

        cp "target/$TARGET/release/$name" "$release_name/"
        cp README.md LICENSE-APACHE LICENSE-MIT "$release_name/"
        tar czvf "$release_name.tar.gz" "$release_name"

        rm -r "$release_name"

        stat "$release_name.tar.gz"

        # Get the sha-256 checksum w/o filename and newline, on windows we use
        # powershell because git bash only seems to include md5/sha1sum
        if [ "$TARGET" == "x86_64-pc-windows-msvc" ]; then
            powershell -File .ci/checksum.ps1 "$release_name.tar.gz"
        else
            echo -n "$(shasum -ba 256 "$release_name.tar.gz" | cut -d " " -f 1)" > "$release_name.tar.gz.sha256"
        fi

        stat "$release_name.tar.gz.sha256"
    travis_time_finish
travis_fold end "package.release"
