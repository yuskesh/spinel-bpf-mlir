# scripts/lib/guest-only.sh — root stages run only inside the VM guest (a design decision); sudo is never run on the host.
# Source this file. `vm_guest_check <cmdline path>` returns 0 if that /proc/cmdline-like file has spinelbpf_vm_mark=<mark> (the mark is env SPINELBPF_VM_MARK — a random value per boot).
# `vm_guest_require` stops with rc 126 on the host (call it at the top of a root script). The path is an argument (a control passes a fake file — env does not override it).
vm_guest_check() {
  local cl=$1 m=${SPINELBPF_VM_MARK:-} f
  [ -n "$m" ] && [ -r "$cl" ] || return 1
  for f in $(cat "$cl"); do [ "$f" = "spinelbpf_vm_mark=$m" ] && return 0; done
  return 1
}
vm_guest_require() {
  vm_guest_check /proc/cmdline || { echo "$0: refusing to run on the host — root stages run only in the VM guest (scripts/gate-vm.sh)" >&2; exit 126; }
}
# vm_record_ok checks the form of a verified record ID (E<digits>), so the formal run's host side and guest reject an empty or malformed ID by the same rule before any BPF.
vm_record_ok() { [[ "${1:-}" =~ ^E[0-9]+$ ]]; }
