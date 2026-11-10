package frontend

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Spinel struct {
	Bin    string
	LibDir string
}

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
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.Bytes(), e.Bytes(), err
}

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
	t, err := ParseTypes(data)
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
