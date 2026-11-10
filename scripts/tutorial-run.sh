#!/bin/bash
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
FULL=0
[ "${1:-}" = "--full" ] && FULL=1
SRC="$HERE"
TAG="${SPINELBPF_TAG:-}"
mkdir -p "$HERE/build/tmp"
WORK=$(mktemp -d "$HERE/build/tmp/tutorial-XXXXXX")
trap 'rm -rf "$WORK"' EXIT
export TMPDIR="$WORK/tmp"
mkdir -p "$TMPDIR"
cd "$WORK"
. "$HERE/scripts/lib/rootlock.sh"
vm_guest_require
sudo() { rsudo "$@"; }
step() { echo "== $*"; }

if [ -n "$TAG" ]; then
  step "git clone --branch $TAG"
  git clone --branch "$TAG" "$SRC" spinel-bpf-mlir
else
  step "git clone (HEAD — SPINELBPF_TAG unset)"
  git clone "$SRC" spinel-bpf-mlir
fi
cd spinel-bpf-mlir
echo "== clone of $(git log -1 --format='%h %s' | cut -c1-80)"
if [ "$FULL" = 1 ]; then
  step "scripts/setup.sh"
  scripts/setup.sh
else
  step "setup skipped (no --full) — the source repo's toolchain"
  . "$HERE/scripts/lib/bml-submodule.sh"; bml_submodule_update . -q --init
  export SPINEL="$HERE/third_party/spinel/bin/spinel" EBPF_COMPILE="$HERE/build/bpf-mlir/bin/ebpf-compile" SPINELBPF_LOADER_LIBS="$HERE/build/bml/lib"
fi
export GOPRIVATE='github.com/yuskesh/*' GOFLAGS=-mod=mod
/usr/local/go/bin/go build -o build/bin/spinelbpf ./cmd/spinelbpf
build/bin/spinelbpf --version
head -1 <(build/bin/spinelbpf --version) | grep -q "^spinel-bpf-mlir v[0-9.]* (commit $(git rev-parse HEAD | cut -c1-12))$" || { echo "!! --version: not this clone's commit or +dirty"; exit 1; }
if build/bin/spinelbpf --version | grep -q "^ebpf-compile: not found$"; then echo "!! ebpf-compile not found"; exit 1; fi
build/bin/spinelbpf --version > "$WORK/version.txt"
"$HERE/scripts/check-version-doc.sh" docs/tutorial.md "$WORK/version.txt" || { echo "!! docs/tutorial.md and --version disagree on the dependency lines"; exit 1; }

build/bin/spinelbpf build -o build/bin/xdpcount examples/xdpcount/xdpcount.rb
sudo build/bin/xdpcount --selftest 10
build/bin/spinelbpf build -o build/bin/tccount examples/tccount/tccount.rb
sudo build/bin/tccount --selftest
build/bin/spinelbpf build -o build/bin/greetwatch examples/greetwatch/greetwatch.rb
sudo build/bin/greetwatch --selftest --target examples/greetwatch/target/greeter
build/bin/spinelbpf build -o build/bin/forkcount examples/forkcount/forkcount.rb
sudo build/bin/forkcount --selftest

[ -z "$(git status --porcelain)" ] || { git status --porcelain; echo "!! the tutorial changed tracked files"; exit 1; }
echo "RESULT ok"
