
bml_file_allow() {
  case "${1:-}" in
    file:*) printf '%s\n' -c protocol.file.allow=always ;;
  esac
}

bml_submodule_update() {
  local repo=$1 url
  shift
  url=$(git -C "$repo" config -f .gitmodules submodule.third_party/bpf-mlir-loader.url) || { echo "bml_submodule_update: $repo/.gitmodules has no URL for third_party/bpf-mlir-loader" >&2; return 2; }
  local -a c
  mapfile -t c < <(bml_file_allow "$url")
  git -C "$repo" "${c[@]}" submodule update "$@" third_party/bpf-mlir-loader
}
