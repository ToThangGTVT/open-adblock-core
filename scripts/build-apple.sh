#!/usr/bin/env bash
# Builds the C ABI as a static library for macOS and packages it, with the header and a Clang
# module map (module COpenAdBlock), as bindings/swift/Artifacts/COpenAdBlock.xcframework, which
# the OpenAdBlockCore Swift package links.
#
# Env: MACOSX_DEPLOYMENT_TARGET (default 13.0). Builds a universal library when the
# x86_64-apple-darwin Rust target is installed, arm64 only otherwise.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
[[ "$(uname -s)" == Darwin ]] || { echo 'Build Apple libraries on macOS.' >&2; exit 1; }
targets=(aarch64-apple-darwin)
rustup target list --installed 2>/dev/null | grep -qx x86_64-apple-darwin && targets+=(x86_64-apple-darwin)
libraries=()
for target in "${targets[@]}"; do
    cargo build --locked -p openadblock-ffi --release --target "$target"
    libraries+=("target/$target/release/libopenadblock.a")
done
STAGE="$ROOT/target/apple"
rm -rf "$STAGE" && mkdir -p "$STAGE/macos" "$STAGE/include"
lipo -create "${libraries[@]}" -output "$STAGE/macos/libopenadblock.a"
cp crates/ffi/include/openadblock.h "$STAGE/include/"
cat > "$STAGE/include/module.modulemap" <<'MAP'
module COpenAdBlock {
    header "openadblock.h"
    link "iconv"
    export *
}
MAP
OUT="$ROOT/bindings/swift/Artifacts"
rm -rf "$OUT/COpenAdBlock.xcframework" && mkdir -p "$OUT"
xcodebuild -create-xcframework -library "$STAGE/macos/libopenadblock.a" -headers "$STAGE/include" \
    -output "$OUT/COpenAdBlock.xcframework" >/dev/null
echo "Built $OUT/COpenAdBlock.xcframework (${targets[*]})"
