#!/usr/bin/env bash
# Builds libopenadblock_jni.so for every Android ABI into OUT_DIR/<abi>/ and verifies that each
# library exports every native method of NativeBindings.java.
#
#   scripts/build-android.sh path/to/src/main/jniLibs
#
# Env: ANDROID_NDK_HOME (default: $ANDROID_HOME/ndk/28.2.13676358), ANDROID_MIN_SDK (default 33),
#      ANDROID_ABIS (default: "arm64-v8a armeabi-v7a x86_64 x86"), CARGO_PROFILE (default release).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: build-android.sh OUT_DIR}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
NDK="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/28.2.13676358}"
MIN_SDK="${ANDROID_MIN_SDK:-33}"
PROFILE="${CARGO_PROFILE:-release}"
case "$(uname -s)" in
    Darwin) NDK_HOST=darwin-x86_64 ;;
    Linux) NDK_HOST=linux-x86_64 ;;
    *) echo 'Build Android libraries on macOS or Linux.' >&2; exit 1 ;;
esac
NDK_BIN="$NDK/toolchains/llvm/prebuilt/$NDK_HOST/bin"
command -v cargo >/dev/null || { echo 'Install Rust via rustup and add cargo to PATH.' >&2; exit 1; }
[[ -d "$NDK_BIN" ]] || { echo "Missing NDK toolchain: $NDK_BIN" >&2; exit 1; }


cd "$ROOT"
built=()
for abi in ${ANDROID_ABIS:-arm64-v8a armeabi-v7a x86_64 x86}; do
    # Plain case instead of associative arrays: macOS ships bash 3.2.
    case "$abi" in
        arm64-v8a) target=aarch64-linux-android; clang_target=aarch64-linux-android ;;
        armeabi-v7a) target=armv7-linux-androideabi; clang_target=armv7a-linux-androideabi ;;
        x86_64) target=x86_64-linux-android; clang_target=x86_64-linux-android ;;
        x86) target=i686-linux-android; clang_target=i686-linux-android ;;
        *) echo "Unknown Android ABI: $abi" >&2; exit 1 ;;
    esac
    clang="$NDK_BIN/${clang_target}${MIN_SDK}-clang"
    upper="$(echo "$target" | tr '[:lower:]-' '[:upper:]_')"
    lower="$(echo "$target" | tr '-' '_')"
    # 16 KiB page alignment is required for Android 15+ devices with large pages.
    env "CC_$lower=$clang" "AR_$lower=$NDK_BIN/llvm-ar" "CARGO_TARGET_${upper}_LINKER=$clang" \
        RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384" \
        cargo build --locked -p openadblock-jni --profile "$PROFILE" --target "$target"
    dir="$PROFILE"; [[ "$PROFILE" == dev ]] && dir=debug
    mkdir -p "$OUT/$abi"
    cp "target/$target/$dir/libopenadblock_jni.so" "$OUT/$abi/libopenadblock_jni.so"
    built+=("$OUT/$abi/libopenadblock_jni.so")
done
python3 scripts/check-jni-exports.py --nm "$NDK_BIN/llvm-nm" "${built[@]}"
