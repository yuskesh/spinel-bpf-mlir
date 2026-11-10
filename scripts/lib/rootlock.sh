# scripts/lib/rootlock.sh — runs root calls one at a time inside bpf-mlir's host-wide shared lock (bpf-mlir's root
# stages compare the host's links / routes before and after; the same form as the rsudo of bml's gate).
# Source it and call `rsudo <command> …` (= `sudo -n <command> …`). The fd is opened and closed in a subshell per call (the
# caller's shell never holds the fd — no lock is left behind by a failure or signal midway). flock works on a read fd
# too. It stops if the file is missing (bpf-mlir's side creates it — never create it silently), and returns rc 125 if
# the lock cannot be taken within 30 minutes. SPINELBPF_ROOT_LOCK overrides the lock's path (for tests).
# Without the VM guest mark it does not run sudo and stops with rc 126 (root never runs against the host kernel). The
# sudo and cmdline paths are arguments of rsudo_at — the control (TestRsudoGuestGuard) passes only fakes (no path that
# overrides them through the environment).
RL=${SPINELBPF_ROOT_LOCK:-/run/lock/bpf-mlir-root.lock}
. "$(dirname -- "${BASH_SOURCE[0]}")/guest-only.sh"
rsudo_at() { local s=$1 c=$2; shift 2
  vm_guest_check "$c" || { echo "rsudo: refusing to run on the host — root runs only in the VM guest (scripts/gate-vm.sh)" >&2; return 126; }
  [ -e "$RL" ] || { echo "rsudo: the bpf-mlir root lock $RL is missing (bpf-mlir's root stage creates it)" >&2; return 125; }
  ( flock -n 9 || { echo "rsudo: another holds the bpf-mlir root lock — waiting" >&2; flock -w 1800 9; } || { echo "rsudo: could not take the root lock in 30 minutes" >&2; exit 125; }
    "$s" -n "$@" ) 9<"$RL" # rootlock:ok
}
rsudo() { rsudo_at /usr/bin/sudo /proc/cmdline "$@"; }
