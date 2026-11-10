#!/bin/bash
# scripts/build-bml-test.sh — builds the test-only libbml (-DBML_TEST_CAPS — caps kinds 1 / 2, the same as denyCaps /
# unknownHelperCaps in the Go test archive) into build/bml-test/lib/libbml.a. Same flags and sources as the libbml of
# bml's build-libs.sh (bml's scripts/srcs.sh src) — none of it goes into the production build/bml/lib/libbml.a
# (the gate checks with nm). build/bml (the production archives and headers) must be built first.
#   scripts/build-bml-test.sh
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BML=$HERE/third_party/bpf-mlir-loader
OUT=$HERE/build/bml
T=$HERE/build/bml-test
[ -f "$OUT/lib/libbml.a" ] || { echo "build-bml-test: $OUT/lib/libbml.a is missing — run scripts/setup.sh first" >&2; exit 1; }
rm -rf "$T"
mkdir -p "$T/obj" "$T/lib"
CF="-O2 -g -std=gnu11 -Wall -Wextra -Werror -DBML_TEST_CAPS -ffile-prefix-map=$BML=bml -ffile-prefix-map=$OUT=out -ffunction-sections -fdata-sections -I$BML/src -I$BML/include -I$BML/third_party/libbpf/include/uapi -I$OUT/include"
# cwd under bml's dir — so DWARF's comp_dir is mapped by -ffile-prefix-map=$BML=bml and no checkout path stays in the
# archive (the same form as build-libs.sh in setup.sh)
cd "$BML/third_party/zlib"
for c in $("$BML/scripts/srcs.sh" src); do
  obj=$(printf '%s' "${c#"$BML"/src/}" | tr / _)
  gcc $CF -c "$c" -o "$T/obj/${obj%.c}.o"
done
ar crD "$T/lib/libbml.a" $(ls "$T"/obj/*.o | LC_ALL=C sort)
echo "build-bml-test: $T/lib/libbml.a"
