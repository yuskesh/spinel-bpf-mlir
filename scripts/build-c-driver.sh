#!/bin/bash
# scripts/build-c-driver.sh <outdir> — builds spinelbpf, the default build: the C driver with the C frontend in
# the same binary, so the build needs no Go.
#   <outdir>/spinelbpf  csrc/driver + csrc/pin + the C frontend (csrc/frontend, csrc/spinelread, csrc/intv), linked with bml's
#                       libbml_build.a, libbml.a, libbpf.a, libelf.a, libz.a
# Needs scripts/setup.sh (build/bml). Environment:
#   BML_PREFIX (default <repo>/build/bml: bml's installed headers and archives — clone-check.sh passes the source repo's),
#   CC (default cc), SPINELBPF_PUBLIC=1 (the public form in the development tree, for tests; the published tree is always
#   public through csrc/pin/form_public.h, which only it carries), E175_MUT=1|2 (only the mutation controls showing that
#   the Go-against-C output comparison catches a driver defect — 1 one byte of the wrote line, 2 one byte of _embed.S), DRIVER_TOOL=1
#   (also <outdir>/driver_tool, the test-side check runner of cmd/spinelbpf/e175_test.go).
# The Go driver (go build ./cmd/spinelbpf) stays as the test-side canon (the C build must match its output byte for byte); no script builds it for users.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: scripts/build-c-driver.sh <outdir>" >&2; exit 2; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OUT=$1
mkdir -p "$OUT"
OUT=$(cd -- "$OUT" && pwd)
CC=${CC:-cc}
BML=${BML_PREFIX:-$HERE/build/bml}
for f in "$BML/include/bml/build.h" "$BML/lib/libbml_build.a" "$BML/lib/libbml.a" "$BML/lib/libelf.a" "$BML/lib/libz.a"; do
  [ -e "$f" ] || { echo "build-c-driver: $f is missing — run scripts/setup.sh" >&2; exit 1; }
done
stamp=$(git -C "$HERE" rev-parse HEAD | cut -c1-12) # version.Commit: 12 hex digits, +dirty as git status --porcelain
[ -z "$(git -C "$HERE" status --porcelain)" ] || stamp="$stamp+dirty"
flags=(-std=gnu11 -O2 -Wall -Wextra -Werror -I"$HERE/csrc/driver" -I"$HERE/csrc/pin" -I"$BML/include"
  "-DSPINELBPF_REPO=\"$HERE\"" "-DSPINELBPF_COMMIT_STAMP=\"$stamp\"")
form="$HERE/csrc/pin/form_public.h" # the public form: only the published tree has it (from distribution/templates/)
if [ -f "$form" ]; then flags+=(-include "$form"); fi
if [ "${SPINELBPF_PUBLIC:-}" = 1 ]; then flags+=(-DSPINELBPF_PUBLIC); fi
case "${E175_MUT:-}" in
  "") ;;
  1|2) flags+=("-DE175_MUT=$E175_MUT") ;;
  *) echo "build-c-driver: E175_MUT must be 1 or 2, got $E175_MUT" >&2; exit 2 ;;
esac
# the C frontend: every file of csrc/frontend except the top-level differential test's entry (toptool.c, it has a main), csrc/spinelread except its main,
# and csrc/intv's bigint and intv (not its tool) — the set spinelfe is built from
fe=()
for f in "$HERE"/csrc/frontend/*.c "$HERE"/csrc/spinelread/*.c; do
  case $f in */frontend/toptool.c|*/spinelread/main.c) ;; *) fe+=("$f") ;; esac
done
srcs=("$HERE"/csrc/driver/{main,build,cfront,seam,checks,diag,jsonv,util}.c "$HERE/csrc/pin/pin.c" "${fe[@]}"
  "$HERE/csrc/intv/bigint.c" "$HERE/csrc/intv/intv.c")
"$CC" "${flags[@]}" -o "$OUT/spinelbpf" "${srcs[@]}" \
  "$BML/lib/libbml_build.a" "$BML/lib/libbml.a" "$BML/lib/libbpf.a" "$BML/lib/libelf.a" "$BML/lib/libz.a"
if [ "${DRIVER_TOOL:-}" = 1 ]; then # test-side only: never in a product
  "$CC" "${flags[@]}" -o "$OUT/driver_tool" "$HERE/csrc/driver/driver_tool.c" "$HERE"/csrc/driver/{checks,diag,jsonv,util}.c \
    "$BML/lib/libbml_build.a" "$BML/lib/libbml.a" "$BML/lib/libbpf.a" "$BML/lib/libelf.a" "$BML/lib/libz.a"
fi
echo "build-c-driver: $OUT/spinelbpf ($stamp)"
