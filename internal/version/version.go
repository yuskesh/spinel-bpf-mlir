package version

import (
	"fmt"
	"runtime/debug"
	"strings"
)

const (
	Version = "v0.9.1"
	BML     = "41ec56f"
	Spinel  = "086d514d"
)

func MLIRLine() string { return "// spinel-bpf-mlir " + Version + "\n" }

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
