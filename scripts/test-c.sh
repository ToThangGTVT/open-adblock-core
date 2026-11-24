#!/usr/bin/env bash
# Builds the C ABI for the host and runs crates/ffi/tests/smoke.c against the public header.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cargo build --locked -p openadblock-ffi
OUT="$ROOT/target/c-smoke"
mkdir -p "$OUT"
case "$(uname -s)" in
    Darwin) LIB="$ROOT/target/debug/libopenadblock.dylib" ;;
    *) LIB="$ROOT/target/debug/libopenadblock.so" ;;
esac
cc -std=c11 -Wall -Wextra -Werror -I crates/ffi/include crates/ffi/tests/smoke.c "$LIB" \
    -Wl,-rpath,"$ROOT/target/debug" -o "$OUT/smoke"
c++ -std=c++17 -Wall -Wextra -Werror -fsyntax-only -x c++ -I crates/ffi/include - <<< '#include "openadblock.h"'
"$OUT/smoke"
