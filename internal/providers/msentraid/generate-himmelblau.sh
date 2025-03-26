#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(readlink -f "$(dirname "$0")")
cd "$SCRIPT_DIR"

GIT_DIR=$(git rev-parse --show-toplevel)

# Verify we are in a git repo and get the top-level dir
if [ -z "${GIT_DIR}" ]; then
  echo >&2 "Error: Not inside a git repository"
  exit 1
fi

cargo install cargo-c cbindgen

cd "${GIT_DIR}/third_party/libhimmelblau"

TARGET_TRIPLE=$(rustc -vV | awk '/host:/ {print $2}')

mkdir -p himmelblau
"${CARGO_HOME:-$HOME/.cargo}"/bin/cbindgen --config ./cbindgen.toml > himmelblau/himmelblau.h
cargo cbuild --release --lib --features=broker,changepassword,on_behalf_of

# Copy header and shared library
cp "target/${TARGET_TRIPLE}/release/himmelblau.h" "${SCRIPT_DIR}/"
cp "target/${TARGET_TRIPLE}/release/libhimmelblau.so" "${SCRIPT_DIR}/libhimmelblau.so.0"
ln -sf libhimmelblau.so.0 "${SCRIPT_DIR}/libhimmelblau.so"
