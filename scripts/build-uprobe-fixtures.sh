#!/bin/bash
# scripts/build-uprobe-fixtures.sh — builds the C fixtures that uprobes target and writes SHA256SUMS in the same directory (copied from mojo-bpf-mlir's script of the same name).
#   scripts/build-uprobe-fixtures.sh           rebuild the fixtures and write SHA256SUMS (the binaries are committed)
#   scripts/build-uprobe-fixtures.sh --check   copy the sources to another directory, build there, and check byte equality with the committed binaries (rewrites nothing)
# For reproducibility: clang is 23.1.1 from $LLVM_PREFIX, and the source directory's path is removed from DWARF (-ffile-prefix-map, -fdebug-compilation-dir).
# -fno-inline-functions and noinline: if a call is inlined, the probe does not fire.
set -euo pipefail
cd "$(dirname "$0")/.."
LLVM_PREFIX="${LLVM_PREFIX:-/opt/llvm-23.1.1}"
CC="$LLVM_PREFIX/bin/clang"
# the fixture list: <output path>:<source path> (one SHA256SUMS per output directory)
FIXTURES="internal/frontend/testdata/uprobe/target/cfix:internal/frontend/testdata/uprobe/target/cfix.c internal/frontend/testdata/uprobe/target/gfix:internal/frontend/testdata/uprobe/target/gfix.c internal/frontend/testdata/uprobe/target/mfix:internal/frontend/testdata/uprobe/target/mfix.c internal/frontend/testdata/uprobe/target/pfix:internal/frontend/testdata/uprobe/target/pfix.c examples/greetwatch/target/greeter:examples/greetwatch/target/greeter.c"
build() { # src out
  local src=$1 out=$2 dir; dir=$(cd "$(dirname "$src")" && pwd)
  (cd "$dir" && "$CC" -g -O1 -fno-inline-functions -ffile-prefix-map="$dir"=. -fdebug-compilation-dir=. -o "$out" "$(basename "$src")")
}
if [ "${1:-}" = "--check" ]; then
  mkdir -p build/tmp
  T=$(mktemp -d "$(pwd)/build/tmp/uprobe-fixture-check.XXXXXX"); trap 'rm -rf "$T"' EXIT
  rc=0
  for e in $FIXTURES; do
    IFS=: read -r out src <<< "$e"
    mkdir -p "$T/$(dirname "$src")"; cp "$src" "$T/$src"
    build "$T/$src" "$T/$out.rebuilt"
    if cmp -s "$T/$out.rebuilt" "$out"; then echo "ok $out (rebuilt in $T — byte-identical)"; else echo "!! $out differs when rebuilt elsewhere"; rc=1; fi
  done
  exit $rc
fi
dirs=""
for e in $FIXTURES; do
  IFS=: read -r out src <<< "$e"
  build "$src" "$(pwd)/$out"
  dirs="$dirs $(dirname "$out")"
  echo "built $out $(sha256sum "$out" | cut -d' ' -f1)"
done
for d in $(echo $dirs | tr ' ' '\n' | sort -u); do
  (cd "$d" && for f in *; do if [ -f "$f" ] && [ -x "$f" ]; then sha256sum "$f"; fi; done > SHA256SUMS)
done
