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

// TestPublicBpfMLIRLine: the bpf-mlir line of the public form's `--version` (the go-bpf-mlir version from the build
// information, the replace note, and no dependency).
func TestPublicBpfMLIRLine(t *testing.T) {
	bi := &debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/yuskesh/go-bpf-mlir", Version: "v0.21.0"}}}
	for _, c := range []struct {
		bi   *debug.BuildInfo
		want string
	}{
		{bi, "v1.23.0 (commit 1a58c8d6; Go packages github.com/yuskesh/go-bpf-mlir v0.21.0, go.mod require)"},
		{&debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/yuskesh/go-bpf-mlir", Version: "v0.21.0", Replace: &debug.Module{Path: "../g"}}}},
			"v1.23.0 (commit 1a58c8d6; Go packages github.com/yuskesh/go-bpf-mlir v0.21.0, go.mod require; replaced by ../g)"},
		{&debug.BuildInfo{Deps: []*debug.Module{{Path: "example.invalid/bpf-mlir-copy", Version: "v0.21.0"}}}, "unknown (no build information)"},
		{nil, "unknown (no build information)"},
	} {
		if got := BpfMLIR(c.bi); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

// TestPublicBMLLine: the public form's `--version` bml line names the public
// bpf-mlir-loader release and the first digits of its source commit, the bml the public form links. An earlier second check (BML is a
// prefix of ReleaseBMLSourceCommit) assumed one bml for both forms; the declared bml guard (toolchain TestBMLReleaseGuard) replaces it.
func TestPublicBMLLine(t *testing.T) {
	if got, want := bmlLine(), "v0.2.0 (commit 8ad2e0b)"; got != want {
		t.Errorf("bmlLine() = %q, want %q", got, want)
	}
}

// TestPublicBMLSourceVersion: the version and source_commit in the public tree's
// third_party/bpf-mlir-loader/SOURCE_VERSION match the public pin (ReleaseBMLVersion, ReleaseBMLSourceCommit). The bml
// submodule of the development tree has no SOURCE_VERSION, so it skips there (the export side confirms by its PASS line
// that it ran in the public tree).
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

// checkBMLSourceVersion checks the version and source_commit in SOURCE_VERSION against the public bml pin.
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

// TestPublicBMLSourceVersionCheck: the positive and negative cases of checkBMLSourceVersion (the public bml v0.2.0
// SOURCE_VERSION, read from an anonymous clone of the public repository, and a different source_commit or version).
func TestPublicBMLSourceVersionCheck(t *testing.T) {
	const real = "format=1\nversion=0.2.0\nsource_commit=8ad2e0b05434f6bd6c47618525982fd56ca5e9f4\n"
	if err := checkBMLSourceVersion([]byte(real)); err != nil {
		t.Errorf("the public bml v0.2.0 SOURCE_VERSION: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(real, "8ad2e0b05434", "a77443f05434", 1),
		strings.Replace(real, "version=0.2.0", "version=0.1.1", 1),
		// the previous development bml 6587986, not the release source 8ad2e0b
		strings.Replace(real, "8ad2e0b05434f6bd6c47618525982fd56ca5e9f4", "6587986cb0ea8cdcb48b715ac73ca806d195c16e", 1),
		// the old public bml v0.1.1 source
		strings.Replace(real, "8ad2e0b05434f6bd6c47618525982fd56ca5e9f4", "ad2eafdc77e610ced3d83d2b39dd3c7ae81b88bc", 1),
	} {
		err := checkBMLSourceVersion([]byte(bad))
		t.Logf("%q: %v", bad, err)
		if err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
