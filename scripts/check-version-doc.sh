#!/bin/bash
# scripts/check-version-doc.sh — compares, in both directions, the expected `--version` dependency lines in step 0 of docs/tutorial.md with spinelbpf --version's
# output dependency lines (from line 2), so a version bump cannot silently leave a stale tutorial line (as once happened after a dependency bump).
# The expected lines are the lines of the first fenced block (a ``` line with no language) after a line that ends with "pinned dependencies:".
# In an expected line, `…` and a `<…>` placeholder each match any text: the parts between them must appear in order, the first at the start and the last at the end.
#   scripts/check-version-doc.sh <tutorial.md> <file with the --version output>
set -euo pipefail
doc=$1 out=$2
mapfile -t items < <(awk '/pinned dependencies:$/{m=1; next} m && !f && /^```$/{f=1; next} f && /^```$/{exit} f{print}' "$doc")
[ "${#items[@]}" -gt 0 ] || { echo "check-version-doc: no expected dependency lines found in $doc (the fenced block after \"pinned dependencies:\")" >&2; exit 1; }
mapfile -t lines < <(tail -n +2 "$out")
rc=0
sep=$'\x1f'
match() { # $1 item, $2 line
  local it=$1 ln=$2 parts p rest i
  local pat=${it//…/$sep}
  pat=$(sed "s/<[^>]*>/$sep/g" <<<"$pat")
  [[ $pat == *"$sep"* ]] || { [[ $ln == "$it" ]]; return; }
  IFS=$sep read -r -a parts <<<"$pat"
  [[ $pat == *"$sep" ]] && parts+=("")
  [[ $ln == "${parts[0]}"* ]] || return 1
  rest=${ln#"${parts[0]}"}
  for ((i = 1; i < ${#parts[@]} - 1; i++)); do
    p=${parts[i]}
    [[ $rest == *"$p"* ]] || return 1
    rest=${rest#*"$p"}
  done
  [[ $rest == *"${parts[${#parts[@]}-1]}" ]]
}
for it in "${items[@]}"; do
  ok=0
  for ln in "${lines[@]}"; do match "$it" "$ln" && ok=1; done
  [ $ok = 1 ] || { echo "check-version-doc: $doc expects \`$it\` but --version has no such line" >&2; rc=1; }
done
for ln in "${lines[@]}"; do
  [ -n "$ln" ] || continue
  ok=0
  for it in "${items[@]}"; do match "$it" "$ln" && ok=1; done
  [ $ok = 1 ] || { echo "check-version-doc: --version prints \`$ln\` but $doc does not list it" >&2; rc=1; }
done
exit $rc
