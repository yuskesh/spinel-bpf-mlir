package frontend

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNativeTwinText checks the shape of the twin text (lines unchanged, the harness) and writes it to TWIN_OUT when that is set
// (for checking the twin by hand).
func TestNativeTwinText(t *testing.T) {
	t.Parallel()
	src := filepath.Join(repoRoot(t), "examples", "xdpcount", "xdpcount.rb")
	text, _ := os.ReadFile(src)
	res, err := Analyze(testSpinel(t), t.TempDir(), src, string(text))
	if err != nil || res.Diags.Blocking() {
		t.Fatal(err, res.Diags)
	}
	tw, err := NativeTwin(string(text), res)
	if err != nil {
		t.Fatal(err)
	}
	if o := os.Getenv("TWIN_OUT"); o != "" {
		os.WriteFile(o, []byte(tw), 0o644)
	}
	t.Log("\n" + tw)
}
