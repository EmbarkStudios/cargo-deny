#!/bin/bash
set -eu

dir=$(dirname "${BASH_SOURCE[0]}")
rustc -g -o "${dir}/check" "${dir}/check_external.rs"
"${dir}/check"
