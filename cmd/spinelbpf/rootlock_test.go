package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func rootLock() string {
	if p := os.Getenv("SPINELBPF_ROOT_LOCK"); p != "" {
		return p
	}
	return "/run/lock/bpf-mlir-root.lock"
}

const (
	realSudoPath = "/usr/bin/sudo"
	procCmdline  = "/proc/cmdline"
	vmMarkEnv    = "SPINELBPF_VM_MARK"
	vmMarkArg    = "spinelbpf_vm_mark="
	rootSkipMsg  = "root test: runs in the VM guest only (scripts/gate-vm.sh) — no guest mark"
)

func rootAllowed(cmdlinePath, mark string) bool {
	if mark == "" || strings.ContainsAny(mark, " \t\n") {
		return false
	}
	b, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(b)) {
		if f == vmMarkArg+mark {
			return true
		}
	}
	return false
}

var rootNeededMu sync.Mutex

func recordRootNeeded(t testing.TB) {
	rootNeededMu.Lock()
	defer rootNeededMu.Unlock()
	name := strings.SplitN(t.Name(), "/", 2)[0]
	dir := os.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "root_needed.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("recording the root test: %v", err)
	}
	defer f.Close()
	fmt.Fprintln(f, name)
}

func sudoCmd(t testing.TB, args ...string) *exec.Cmd {
	t.Helper()
	return sudoCmdAt(t, realSudoPath, procCmdline, args...)
}

func sudoCmdAt(t testing.TB, sudoPath, cmdlinePath string, args ...string) *exec.Cmd {
	t.Helper()
	if !rootAllowed(cmdlinePath, os.Getenv(vmMarkEnv)) {
		recordRootNeeded(t)
		t.Skip(rootSkipMsg)
	}
	l := rootLock()
	if _, err := os.Stat(l); err != nil {
		t.Fatalf("the bpf-mlir root lock %s is missing (bpf-mlir's root stage creates it): %v", l, err)
	}
	w := "600"
	if v := os.Getenv("SPINELBPF_ROOT_LOCK_WAIT"); v != "" {
		w = v
	}
	sh := `flock -o -E 125 -w "$1" "$2" "$3" -n "${@:4}"; rc=$?; [ $rc != 125 ] || echo "the bpf-mlir root lock $2 was not free within $1 s (another holds it — sudoCmd)" >&2; exit $rc`
	return exec.Command("bash", append([]string{"-c", sh, "rootlock", w, l, sudoPath}, args...)...)
}
