#!/usr/bin/env python3
"""Fails when a JNI library does not export every native method NativeBindings.java declares."""
import argparse
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
BINDINGS = ROOT / "bindings/java/src/main/java/io/github/tothanggtvt/openadblock/core/NativeBindings.java"
PREFIX = "Java_io_github_tothanggtvt_openadblock_core_NativeBindings_"


def expected():
    names = re.findall(r"static\s+native\s+[\w\[\]]+\s+(\w+)\s*\(", BINDINGS.read_text())
    if not names:
        raise SystemExit(f"No native methods found in {BINDINGS}")
    return {PREFIX + name for name in names}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nm", default="nm", help="nm binary (NDK llvm-nm for Android)")
    parser.add_argument("libraries", nargs="+", type=Path)
    args = parser.parse_args()
    wanted = expected()
    for library in args.libraries:
        output = subprocess.check_output([args.nm, "-g", "--defined-only", str(library)], text=True)
        exports = {line.split()[-1].lstrip("_") for line in output.splitlines() if line.split()}
        missing = wanted - exports
        if missing:
            raise SystemExit(f"{library}: missing JNI exports: {', '.join(sorted(missing))}")
    print(f"All {len(wanted)} JNI exports present in {len(args.libraries)} libraries.")


if __name__ == "__main__":
    main()
