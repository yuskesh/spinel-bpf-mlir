#!/bin/bash
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BML=$HERE/third_party/bpf-mlir-loader
OUT=$HERE/build/bml
T=$HERE/build/bml-test
[ -f "$OUT/lib/libbml.a" ] || { echo "build-bml-test: $OUT/lib/libbml.a is missing — run scripts/setup.sh first" >&2; exit 1; }
rm -rf "$T"
mkdir -p "$T/obj" "$T/lib"
CF="-O2 -g -std=gnu11 -Wall -Wextra -Werror -DBML_TEST_CAPS -ffile-prefix-map=$BML=bml -ffile-prefix-map=$OUT=out -ffunction-sections -fdata-sections -I$BML/src -I$BML/include -I$BML/third_party/libbpf/include/uapi -I$OUT/include"
cd "$BML/third_party/zlib"
for c in $("$BML/scripts/srcs.sh" src); do
  obj=$(printf '%s' "${c#"$BML"/src/}" | tr / _)
  gcc $CF -c "$c" -o "$T/obj/${obj%.c}.o"
done
ar crD "$T/lib/libbml.a" $(ls "$T"/obj/*.o | LC_ALL=C sort)
echo "build-bml-test: $T/lib/libbml.a"
