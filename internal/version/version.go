// Package version holds spinel-bpf-mlir's version string and the dependency pins.
//
// Version is the release version (v0.x — no compatibility promise, docs/release.md). It does not change until the next
// release (so that the version line of the generated `.mlir` does not drift; builds between releases are told apart by
// the commit in `--version`). BML and Spinel are the leading digits of the submodules' pinned commits (TestVersionPins
// checks them against the gitlinks — raising a pin and forgetting the constant fails). The bpf-mlir version is the
// go.mod require (read from the build information).
package version

import (
	"fmt"
	"runtime/debug"
	"strings"
)

const (
	Version = "v0.10.0"
	BML     = "065901b"
	Spinel  = "086d514d"
)

// BpfMLIRModule (bpf-mlir's Go module — the go.mod require) and bpfMLIRLine come from a pair of files split between the
// development build and the public build (version_public.go is the public build's file).

// MLIRLine is the second line of the generated `.mlir` (the version only — no commit: artefacts stay reproducible within
// a version).
func MLIRLine() string { return "// spinel-bpf-mlir " + Version + "\n" }

// Commit is the build's vcs stamp (`<12 digits>`, plus `+dirty` if the tree was dirty). Without a stamp it is
// "unknown" (never silently empty).
func Commit(bi *debug.BuildInfo) string {
	if bi == nil {
		return "unknown"
	}
	rev, dirty := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "+dirty"
	}
	return rev
}

// BpfMLIR is the bpf-mlir version in the go.mod require (with a replace, still the required version — the replacement
// goes into a note: the version of its content is unknown. The authoritative version checks are ebpf-compile's --version
// and the check of bml's header).
func BpfMLIR(bi *debug.BuildInfo) string {
	if bi != nil {
		for _, d := range bi.Deps {
			if d.Path != BpfMLIRModule {
				continue
			}
			v := bpfMLIRLine(d.Version)
			if d.Replace != nil {
				r := d.Replace.Path
				if d.Replace.Version != "" {
					r += "@" + d.Replace.Version
				}
				v += "; replaced by " + r
			}
			return v + ")"
		}
	}
	return "unknown (no build information)"
}

// Text is the output of `spinelbpf --version` (ec is the first line of ebpf-compile's --version, or "" if none).
func Text(ec string) string {
	bi, _ := debug.ReadBuildInfo()
	var b strings.Builder
	fmt.Fprintf(&b, "spinel-bpf-mlir %s (commit %s)\n", Version, Commit(bi))
	fmt.Fprintf(&b, "bpf-mlir %s\n", BpfMLIR(bi))
	fmt.Fprintf(&b, "bml %s\n", bmlLine())
	fmt.Fprintf(&b, "spinel %s\n", Spinel)
	if ec == "" {
		ec = "not found"
	}
	fmt.Fprintf(&b, "ebpf-compile: %s\n", ec)
	return b.String()
}
