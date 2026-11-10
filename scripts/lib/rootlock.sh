RL=${SPINELBPF_ROOT_LOCK:-/run/lock/bpf-mlir-root.lock}
. "$(dirname -- "${BASH_SOURCE[0]}")/guest-only.sh"
rsudo_at() { local s=$1 c=$2; shift 2
  vm_guest_check "$c" || { echo "rsudo: refusing to run on the host — root runs only in the VM guest" >&2; return 126; }
  [ -e "$RL" ] || { echo "rsudo: the bpf-mlir root lock $RL is missing (bpf-mlir's root stage creates it)" >&2; return 125; }
  ( flock -n 9 || { echo "rsudo: another holds the bpf-mlir root lock — waiting" >&2; flock -w 1800 9; } || { echo "rsudo: could not take the root lock in 30 minutes" >&2; exit 125; }
    "$s" -n "$@" ) 9<"$RL"
}
rsudo() { rsudo_at /usr/bin/sudo /proc/cmdline "$@"; }
