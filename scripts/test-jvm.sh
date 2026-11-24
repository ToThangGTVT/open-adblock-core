#!/usr/bin/env bash
# Compiles the Java API with javac (no Gradle needed), builds the JNI library for the host and
# runs the desktop smoke test against it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cargo build --locked -p openadblock-jni
case "$(uname -s)" in
    Darwin) LIB="$ROOT/target/debug/libopenadblock_jni.dylib" ;;
    MINGW*|MSYS*|CYGWIN*) LIB="$ROOT/target/debug/openadblock_jni.dll" ;;
    *) LIB="$ROOT/target/debug/libopenadblock_jni.so" ;;
esac
OUT="$ROOT/target/jvm-smoke"
rm -rf "$OUT" && mkdir -p "$OUT"
javac --release 17 -Xlint:all -Werror -d "$OUT" \
    $(find bindings/java/src/main/java bindings/java/src/test/java -name '*.java')
java -Xcheck:jni -cp "$OUT" io.github.tothanggtvt.openadblock.core.NativeEngineSmokeTest "$LIB"
