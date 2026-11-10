package toolchain

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func TestModuleVersion(t *testing.T) {
	bi := &debug.BuildInfo{Deps: []*debug.Module{{Path: BPFMLIRGoModule, Version: "v0.8.0"}}}
	if v, err := ModuleVersion(bi); err != nil || v != "v0.8.0" {
		t.Fatal(v, err)
	}
	bi.Deps[0].Replace = &debug.Module{Path: "../bpf-mlir/go"}
	if _, err := ModuleVersion(bi); err == nil {
		t.Fatal("replace accepted")
	}
	if _, err := ModuleVersion(&debug.BuildInfo{}); err == nil {
		t.Fatal("missing dependency accepted")
	}
}

func TestVerifySpinel(t *testing.T) {
	ok := "spinel 2026.09.12+1138 (0d58c397) [gcc 14.2.0 (cc)]"
	if c, err := VerifySpinel(ok, "0d58c3972f0e"); err != nil || c != "0d58c397" {
		t.Fatal(c, err)
	}
	for _, tc := range []struct{ out, head, want string }{
		{"spinel 1 (deadbeef) [x]", "", "pinned to"},
		{ok, "aaaaaaaa", "third_party/spinel is at"},
		{"nothing", "", "no `spinel"},
	} {
		if _, err := VerifySpinel(tc.out, tc.head); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: want %q, got %v", tc.out, tc.want, err)
		}
	}
}

// TestParseSourceVersion (matching the real file's 3 lines): positive = the real SOURCE_VERSION of the public bpf-mlir
// v1.23.0 (testdata — byte-identical to the file in the two trees of the public-group export) and the form without a
// final newline; negative = a missing or different format, the line count, a duplicate, an extra line, the order, the
// shape of the version and the hex, CR, and the earlier 2-line form.
func TestParseSourceVersion(t *testing.T) {
	const c = "1a58c8d6ef57262dfaf68989c370925caddc66f9"
	actual, err := os.ReadFile(filepath.Join("testdata", "public_bpf_mlir_v1.23.0.SOURCE_VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{string(actual), "format=1\nversion=1.23.0\nsource_commit=" + c} {
		if v, got, err := ParseSourceVersion([]byte(s)); err != nil || v != "1.23.0" || got != c {
			t.Fatalf("%q: %s %s %v", s, v, got, err)
		}
	}
	const f, v = "format=1\n", "version=1.23.0\n"
	sc := "source_commit=" + c + "\n"
	for _, tc := range []struct{ name, in, want string }{
		{"previous_two_line_form", v + sc, "want exactly 3"},
		{"format_missing", v + sc + "extra=1\n", "line 1"},
		{"format_2", "format=2\n" + v + sc, "want format=1"},
		{"format_empty", "format=\n" + v + sc, "want format=1"},
		{"format_space", "format= 1\n" + v + sc, "want format=1"},
		{"duplicate_version", f + v + v + sc, "want exactly 3"},
		{"duplicate_format", f + f + v + sc, "want exactly 3"},
		{"extra_line", f + v + sc + "extra=1\n", "want exactly 3"},
		{"two_newlines", f + v + sc + "\n", "want exactly 3"},
		{"swapped", f + sc + v, "line 2"},
		{"v_prefix", f + "version=v1.23.0\n" + sc, "line 2"},
		{"short_commit", f + v + "source_commit=1a58c8d6\n", "line 3"},
		{"upper_hex", f + v + "source_commit=" + strings.ToUpper(c) + "\n", "line 3"},
		{"crlf", "format=1\r\nversion=1.23.0\r\nsource_commit=" + c + "\r\n", "carriage return"},
	} {
		_, _, err := ParseSourceVersion([]byte(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
		t.Logf("%s: %v", tc.name, err)
	}
}

// TestReleaseSource: how the public form gets check 4's value — in a temporary repo's third_party/bpf-mlir: success, no
// submodule, only .git, a version mismatch, a malformed file.
func TestReleaseSource(t *testing.T) {
	const c = "1a58c8d6ef57262dfaf68989c370925caddc66f9"
	mk := func(sv string, git bool) string {
		repo := t.TempDir()
		sub := filepath.Join(repo, "third_party", "bpf-mlir")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if git {
			if err := os.WriteFile(filepath.Join(sub, ".git"), []byte("gitdir: ../../.git/modules/third_party/bpf-mlir\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if sv != "" {
			if err := os.WriteFile(filepath.Join(sub, "SOURCE_VERSION"), []byte(sv), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return repo
	}
	good := "format=1\nversion=1.23.0\nsource_commit=" + c + "\n"
	if got, err := releaseSource(mk(good, true), "v1.23.0"); err != nil || got != c {
		t.Fatalf("checked out: %s %v", got, err)
	}
	if got, err := releaseSource(mk(good, false), "v1.23.0"); err != nil || got != c {
		t.Fatalf("tree without .git: %s %v", got, err)
	}
	if got, err := releaseSource(mk("", false), "v1.23.0"); err != nil || got != "" {
		t.Fatalf("not checked out: %q %v", got, err)
	}
	if got, err := releaseSource("", "v1.23.0"); err != nil || got != "" {
		t.Fatalf("no repo: %q %v", got, err)
	}
	for _, tc := range []struct {
		name, sv string
		git      bool
		want     string
	}{
		{"git_without_source_version", "", true, "has no SOURCE_VERSION"},
		{"other_version", "format=1\nversion=1.20.0\nsource_commit=" + c + "\n", true, "says version 1.20.0, but spinelbpf needs the bpf-mlir v1.23.0"},
		{"previous_two_line_form", "version=1.23.0\nsource_commit=" + c + "\n", true, "want exactly 3"},
	} {
		got, err := releaseSource(mk(tc.sv, tc.git), "v1.23.0")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %q %v", tc.name, tc.want, got, err)
		}
		t.Logf("%s: %v", tc.name, err)
	}
}
