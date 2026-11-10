#!/bin/bash
# scripts/tutorial-run.sh — runs the commands of the `sh` blocks of docs/tutorial.md in order, in a fresh clone. The
# command lines are spelled as in the tutorial (TestTutorialCommands checks that each tutorial line is in this file — a
# mismatch between the page and the runner fails). Run it **after committing**.
#   scripts/tutorial-run.sh                       # a clone of the current HEAD; step 0's setup uses the source repo's build (toolchain, bml archives)
#   scripts/tutorial-run.sh --full                # also runs step 0's scripts/setup.sh in the clone (network — bpf-mlir's submodules and libprism)
#   SPINELBPF_TAG=v0.8.0 scripts/tutorial-run.sh  # a clone of the tag (git clone --branch)
# The `sudo` of steps 1–4 is `sudo -n` inside bpf-mlir's root lock (it needs root permission — without it, it stops).
#   scripts/tutorial-run.sh --build-only          # no root step and no VM guard — every non-sudo line runs, each `sudo` line
#                                                 #   is skipped by name (runs on the host, needs no Go)
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
FULL=0 BUILD_ONLY=0
for a; do
  case $a in
    --full) FULL=1 ;;
    --build-only) BUILD_ONLY=1 ;;
    *) echo "usage: scripts/tutorial-run.sh [--full] [--build-only]" >&2; exit 2 ;;
  esac
done
SRC="$HERE"
TAG="${SPINELBPF_TAG:-}"
mkdir -p "$HERE/build/tmp"
WORK=$(mktemp -d "$HERE/build/tmp/tutorial-XXXXXX")
trap 'rm -rf "$WORK"' EXIT
export TMPDIR="$WORK/tmp"
mkdir -p "$TMPDIR"
cd "$WORK"
. "$HERE/scripts/lib/rootlock.sh"
if [ "$BUILD_ONLY" = 1 ]; then
  sudo() { echo "== skipped (--build-only): sudo $*"; } # no root step runs
else
  vm_guest_require # root steps run only in a VM guest; on the host, stop before the clone
  sudo() { rsudo "$@"; } # the tutorial's spelling `sudo` becomes `sudo -n` inside bpf-mlir's root lock
fi
step() { echo "== $*"; }

# Step 0
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
  # Instead of setup: the toolchain and bml archives built in the source repo (the bml submodule is fetched for the link's
  # headers — as in clone-check)
  step "setup skipped (no --full) — the source repo's toolchain"
  . "$HERE/scripts/lib/bml-submodule.sh"; bml_submodule_update . -q --init # protocol.file.allow only for a local file URL
  export SPINEL="$HERE/third_party/spinel/bin/spinel" EBPF_COMPILE="$HERE/build/bpf-mlir/bin/ebpf-compile" SPINELBPF_LOADER_LIBS="$HERE/build/bml/lib"
fi
[ "$FULL" = 1 ] || export BML_PREFIX="$HERE/build/bml" # without --full, the source repo's bml archives
scripts/build-c-driver.sh build/bin
build/bin/spinelbpf --version
head -1 <(build/bin/spinelbpf --version) | grep -q "^spinel-bpf-mlir v[0-9.]* (commit $(git rev-parse HEAD | cut -c1-12))$" || { echo "!! --version: not this clone's commit or +dirty"; exit 1; }
if build/bin/spinelbpf --version | grep -q "^ebpf-compile: not found$"; then echo "!! ebpf-compile not found"; exit 1; fi
# Check the tutorial's expected dependency lines in step 0 against the dependency lines of --version, both ways (a version
# bump must not silently leave stale lines in the tutorial)
build/bin/spinelbpf --version > "$WORK/version.txt"
"$HERE/scripts/check-version-doc.sh" docs/tutorial.md "$WORK/version.txt" || { echo "!! docs/tutorial.md and --version disagree on the dependency lines"; exit 1; }

# Steps 1–4
build/bin/spinelbpf build -o build/bin/xdpcount examples/xdpcount/xdpcount.rb
sudo build/bin/xdpcount --selftest 10
build/bin/spinelbpf build -o build/bin/tccount examples/tccount/tccount.rb
sudo build/bin/tccount --selftest
build/bin/spinelbpf build -o build/bin/greetwatch examples/greetwatch/greetwatch.rb
sudo build/bin/greetwatch --selftest --target examples/greetwatch/target/greeter
build/bin/spinelbpf build -o build/bin/forkcount examples/forkcount/forkcount.rb
sudo build/bin/forkcount --selftest

[ -z "$(git status --porcelain)" ] || { git status --porcelain; echo "!! the tutorial changed tracked files"; exit 1; }
if [ "$BUILD_ONLY" = 1 ]; then echo "RESULT ok (build-only: the sudo steps did not run)"; else echo "RESULT ok"; fi
