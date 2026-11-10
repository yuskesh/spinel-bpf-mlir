#!/bin/bash
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
LLVM_PREFIX="${LLVM_PREFIX:-/opt/llvm-23.1.1}"
export LLVM_PREFIX

git -C "$HERE" submodule update --init third_party/bpf-mlir third_party/spinel
. "$HERE/scripts/lib/bml-submodule.sh"; bml_submodule_update "$HERE" --init
git -C "$HERE/third_party/bpf-mlir-loader" submodule update --init third_party/libbpf third_party/elfutils third_party/zlib
echo "== bpf-mlir: $(git -C "$HERE/third_party/bpf-mlir" describe --tags --always) ($(git -C "$HERE/third_party/bpf-mlir" rev-parse HEAD))"
echo "== spinel:   $(git -C "$HERE/third_party/spinel" log -1 --format='%h %s' | cut -c1-100)"
"$LLVM_PREFIX/bin/clang" --version | head -1

BUILD_DIR="$HERE/build/bpf-mlir" "$HERE/third_party/bpf-mlir/build.sh"

make -C "$HERE/third_party/spinel" deps
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.abbrev GIT_CONFIG_VALUE_0=8 make -C "$HERE/third_party/spinel" -j"$(nproc)"
"$HERE/third_party/spinel/bin/spinel" --version
if [ -n "$(git -C "$HERE/third_party/spinel" status --porcelain)" ]; then
  echo "setup: third_party/spinel is dirty (build products outside .gitignore)" >&2; exit 1
fi
(cd "$HERE/third_party/bpf-mlir-loader/third_party/zlib" && "$HERE/third_party/bpf-mlir-loader/scripts/build-libs.sh" "$HERE/build/bml")
"$HERE/scripts/build-bml-test.sh"
if [ -n "$(git -C "$HERE/third_party/bpf-mlir-loader" status --porcelain)" ]; then
  echo "setup: third_party/bpf-mlir-loader is dirty" >&2; exit 1
fi
echo "== ok: $HERE/build/bpf-mlir/bin/ebpf-compile, $HERE/third_party/spinel/bin/spinel, $HERE/build/bml/lib"
