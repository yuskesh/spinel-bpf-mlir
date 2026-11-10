package frontend

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repoRoot(t testing.TB) string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(f), "..", ".."))
}

func testSpinel(t testing.TB) Spinel {
	root := repoRoot(t)
	bin := filepath.Join(root, "third_party", "spinel", "bin", "spinel")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("spinel not built (scripts/setup.sh): %v", err)
	}
	return Spinel{Bin: bin, LibDir: filepath.Join(root, "ruby", "lib")}
}
