#!/bin/bash
# scripts/setup.sh — sets up the dependencies: builds bpf-mlir (third_party/bpf-mlir — a submodule at a pinned version)
# with LLVM 23.1.1, and builds Spinel (third_party/spinel — a submodule at a pinned commit of upstream matz/spinel).
#
#   scripts/setup.sh
#   LLVM_PREFIX=/path/to/llvm scripts/setup.sh
#
# Output: build/bpf-mlir/bin/{ebpf-opt,ebpf-compile}, third_party/spinel/bin/spinel, build/bml/lib (the C loader's 5
# archives), build/bml-test/lib/libbml.a (test caps). Needs the network (submodules, lit, the libprism gem).
# When raising a submodule pointer, stage the pointer (and go.mod / go.sum) before running — submodule update follows
# the pointer in the index.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
LLVM_PREFIX="${LLVM_PREFIX:-/opt/llvm-23.1.1}"
export LLVM_PREFIX

git -C "$HERE" submodule update --init third_party/bpf-mlir third_party/spinel
# bpf-mlir-loader (a submodule with a local file URL in the development tree: it cannot be cloned off this machine — a design
# decision). Of its nested submodules, only the 3 the build needs (bml's own bpf-mlir is not fetched — the version check
# uses the gitlink)
. "$HERE/scripts/lib/bml-submodule.sh"; bml_submodule_update "$HERE" --init # protocol.file.allow only for a local file URL
git -C "$HERE/third_party/bpf-mlir-loader" submodule update --init third_party/libbpf third_party/elfutils third_party/zlib
echo "== bpf-mlir: $(git -C "$HERE/third_party/bpf-mlir" describe --tags --always) ($(git -C "$HERE/third_party/bpf-mlir" rev-parse HEAD))"
echo "== spinel:   $(git -C "$HERE/third_party/spinel" log -1 --format='%h %s' | cut -c1-100)"
"$LLVM_PREFIX/bin/clang" --version | head -1

BUILD_DIR="$HERE/build/bpf-mlir" "$HERE/third_party/bpf-mlir/build.sh"

# Spinel's build products (bin/, build/, vendor/prism) are covered by Spinel's .gitignore — they do not dirty the submodule
make -C "$HERE/third_party/spinel" deps
# At least 8 digits in the version string (spinel_rev.h — git rev-parse --short): if the digit count followed the number
# of objects in the repo, the spinel binary (part of the verified key) would differ between checkouts
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.abbrev GIT_CONFIG_VALUE_0=8 make -C "$HERE/third_party/spinel" -j"$(nproc)"
"$HERE/third_party/spinel/bin/spinel" --version
if [ -n "$(git -C "$HERE/third_party/spinel" status --porcelain)" ]; then
  echo "setup: third_party/spinel is dirty (build products outside .gitignore)" >&2; exit 1
fi
# The C loader's (bml's) 5 archives and the libbml with test caps
# cwd in bml's zlib dir — gcc's cwd (DWARF's comp_dir) is mapped by build-libs.sh's -ffile-prefix-map (bml, zlib), so no
# checkout path stays in the archives (the verified key does not depend on the path)
(cd "$HERE/third_party/bpf-mlir-loader/third_party/zlib" && "$HERE/third_party/bpf-mlir-loader/scripts/build-libs.sh" "$HERE/build/bml")
"$HERE/scripts/build-bml-test.sh"
if [ -n "$(git -C "$HERE/third_party/bpf-mlir-loader" status --porcelain)" ]; then
  echo "setup: third_party/bpf-mlir-loader is dirty" >&2; exit 1
fi
echo "== ok: $HERE/build/bpf-mlir/bin/ebpf-compile, $HERE/third_party/spinel/bin/spinel, $HERE/build/bml/lib"
