package version

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"
)

func TestPublicBpfMLIRLine(t *testing.T) {
	bi := &debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/yuskesh/go-bpf-mlir", Version: "v0.19.0"}}}
	for _, c := range []struct {
		bi   *debug.BuildInfo
		want string
	}{
		{bi, "v1.21.0 (commit 41b18856; Go packages github.com/yuskesh/go-bpf-mlir v0.19.0, go.mod require)"},
		{&debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/yuskesh/go-bpf-mlir", Version: "v0.19.0", Replace: &debug.Module{Path: "../g"}}}},
			"v1.21.0 (commit 41b18856; Go packages github.com/yuskesh/go-bpf-mlir v0.19.0, go.mod require; replaced by ../g)"},
		{&debug.BuildInfo{Deps: []*debug.Module{{Path: "example.invalid/bpf-mlir-copy", Version: "v0.19.0"}}}, "unknown (no build information)"},
		{nil, "unknown (no build information)"},
	} {
		if got := BpfMLIR(c.bi); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestPublicBMLLine(t *testing.T) {
	if got, want := bmlLine(), "v0.1.0 (commit 41ec56f)"; got != want {
		t.Errorf("bmlLine() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(toolchain.ReleaseBMLSourceCommit, BML) {
		t.Errorf("BML %s is not a prefix of ReleaseBMLSourceCommit %s", BML, toolchain.ReleaseBMLSourceCommit)
	}
}

func TestPublicBMLSourceVersion(t *testing.T) {
	p := filepath.Join("..", "..", "third_party", "bpf-mlir-loader", "SOURCE_VERSION")
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is absent — not a public checkout of bpf-mlir-loader", p)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBMLSourceVersion(b); err != nil {
		t.Errorf("%s: %v", p, err)
	}
}

func checkBMLSourceVersion(b []byte) error {
	ver, commit, err := toolchain.ParseSourceVersion(b)
	if err != nil {
		return err
	}
	if "v"+ver != toolchain.ReleaseBMLVersion || commit != toolchain.ReleaseBMLSourceCommit {
		return fmt.Errorf("version %s and source_commit %s, want %s and %s", ver, commit, toolchain.ReleaseBMLVersion, toolchain.ReleaseBMLSourceCommit)
	}
	return nil
}

func TestPublicBMLSourceVersionCheck(t *testing.T) {
	const real = "format=1\nversion=0.1.0\nsource_commit=41ec56f1d3df74e8ac56aec1e74f6a51c83a6bbc\n"
	if err := checkBMLSourceVersion([]byte(real)); err != nil {
		t.Errorf("the public bml v0.1.0 SOURCE_VERSION: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(real, "41ec56f1d3df", "a77443f1d3df", 1),
		strings.Replace(real, "version=0.1.0", "version=0.1.1", 1),
	} {
		err := checkBMLSourceVersion([]byte(bad))
		t.Logf("%q: %v", bad, err)
		if err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
