#!/usr/bin/env bash
# Layout-calibration sanitizer harness: synthetic CanonicalCookie
# samples (worksheet layout, shifted rebuild, corrupt) against the
# exact shipped engine_a.c calibrator, under ASan+UBSan.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
gcc -fsanitize=address,undefined -O1 -g -Iinclude \
    scripts/san_layout_harness.c src/runtime.c -o build/san_layout
ASAN_OPTIONS=detect_leaks=0 ./build/san_layout
