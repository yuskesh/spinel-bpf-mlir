# scripts/lib/bml-submodule.sh — fetching the bml (third_party/bpf-mlir-loader) submodule (sourced by setup.sh,
# clone-check.sh and tutorial-run.sh).
# The bml URL in the development .gitmodules is a local file URL (a design decision — no remote is created), and git by default
# refuses the file protocol for submodules.
# protocol.file.allow=always is added only when that URL is a local file URL (the public form's .gitmodules uses https, so it does
# not need it).

# bml_file_allow <URL> prints the arguments to put before git, one per line (`-c` and `protocol.file.allow=always`, only
# for a local file URL).
bml_file_allow() {
  case "${1:-}" in
    file:*) printf '%s\n' -c protocol.file.allow=always ;;
  esac
}

# bml_submodule_update <repo> [submodule update arguments…] reads bml's URL from the repo's .gitmodules and fetches the
# bml submodule.
bml_submodule_update() {
  local repo=$1 url
  shift
  url=$(git -C "$repo" config -f .gitmodules submodule.third_party/bpf-mlir-loader.url) || { echo "bml_submodule_update: $repo/.gitmodules has no URL for third_party/bpf-mlir-loader" >&2; return 2; }
  local -a c
  mapfile -t c < <(bml_file_allow "$url")
  git -C "$repo" "${c[@]}" submodule update "$@" third_party/bpf-mlir-loader
}
