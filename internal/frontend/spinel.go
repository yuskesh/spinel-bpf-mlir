package frontend

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Running Spinel. The source is placed in the analysis directory under the same basename as the user's file, and Spinel runs with
// that directory as its cwd (so the file names in the types JSON and the AST are the basename of the user's file).
// `--dump-ast` prints the AST and exits without writing the JSON (`spinel --dump-ast --emit-types` writes only the AST, with rc 0),
// so Spinel runs twice on the same input.

// Spinel says how to invoke Spinel.
type Spinel struct {
	Bin    string // the spinel executable (an absolute path)
	LibDir string // ruby/lib (an absolute path — used to resolve `require "bpf"` and to check the files that callees live in)
}

// Analysis is the result of analysing one input.
type Analysis struct {
	Dir   string
	AST   *AST
	Types *Types
}

func (s Spinel) run(dir string, args ...string) (stdout, stderr []byte, err error) {
	tmp := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(s.Bin, append([]string{"-I", s.LibDir}, args...)...)
	cmd.Dir = dir
	// TMPDIR is an absolute path (with a relative one, Spinel's --rbs seed can be dropped silently, among other things: when Spinel
	// cannot create its seed temp file it only prints a shell error and carries on with rc 0 — docs/upstream_suspects.md S3)
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.Bytes(), e.Bytes(), err
}

// Analyze writes text to dir under the name base and takes the AST and the types. When Spinel refuses the input (an error diagnostic
// in the JSON, or rc ≠ 0) it returns an SB000 Diag.
func (s Spinel) Analyze(dir, base, text string) (*Analysis, Diags, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, base), []byte(text), 0o644); err != nil {
		return nil, nil, err
	}
	astOut, astErr, err := s.run(dir, "--dump-ast", "--emit-types", base)
	if err != nil {
		return nil, Diags{{Verdict: Rejected, Code: SB000Spinel, Pos: Pos{File: base}, Msg: "spinel --dump-ast failed: " + firstLines(astErr, 5)}}, nil
	}
	jsonPath := filepath.Join(dir, "types.json")
	_ = os.Remove(jsonPath)
	_, tyErr, runErr := s.run(dir, "--emit-types", base, "-o", jsonPath)
	data, rerr := os.ReadFile(jsonPath)
	if rerr != nil {
		return nil, Diags{{Verdict: Rejected, Code: SB000Spinel, Pos: Pos{File: base}, Msg: "spinel --emit-types wrote no JSON: " + firstLines(tyErr, 5)}}, nil
	}
	a, err := ParseAST(string(astOut))
	if err != nil {
		return nil, nil, err
	}
	// The types are bound to this invocation's AST, after both are decoded and before any index or span use
	t, _, err := ParseTypesWithAST(data, a)
	if err != nil {
		return nil, nil, err
	}
	var ds Diags
	for _, e := range t.Errors() {
		ds = append(ds, Diag{Verdict: Rejected, Code: SB000Spinel, Pos: Pos{File: e.File, Line: e.Line, Col: e.Col + 1}, Msg: "spinel refused the program: " + e.Message})
	}
	if runErr != nil && len(ds) == 0 {
		ds = append(ds, Diag{Verdict: Rejected, Code: SB000Spinel, Pos: Pos{File: base}, Msg: "spinel --emit-types failed: " + firstLines(tyErr, 5)})
	}
	return &Analysis{Dir: dir, AST: a, Types: t}, ds, nil
}

// UsesThreads reports whether the program uses Threads and their kin (the -DSP_THREADS runtime), as Spinel itself decides it.
func (s Spinel) UsesThreads(dir, base string) (bool, error) {
	out, errb, err := s.run(dir, "--print-build", base)
	if err != nil {
		return false, fmt.Errorf("spinel --print-build failed: %s", firstLines(errb, 5))
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(l) == "define -DSP_THREADS" {
			return true, nil
		}
	}
	return false, nil
}

// Version returns the one line printed by spinel --version.
func (s Spinel) Version() (string, error) {
	out, err := exec.Command(s.Bin, "--version").Output()
	return strings.TrimSpace(string(out)), err
}

func firstLines(b []byte, n int) string {
	ls := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(ls) > n {
		ls = ls[:n]
	}
	return strings.Join(ls, " | ")
}
