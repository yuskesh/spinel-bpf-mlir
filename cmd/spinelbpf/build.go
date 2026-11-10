package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/bindrt"
	"github.com/yuskesh/go-bpf-mlir/layout"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/spinel-bpf-mlir/internal/frontend"
	"github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"
)

type Config struct {
	Repo                  string
	Spinel                string
	EbpfCompile           string
	SchemaCheck           string
	Clang                 string
	Go                    string
	LineInfo              string
	LoaderLibs            string
	SeamEmit, SeamInspect string
}

func repoRoot() string {
	if r := os.Getenv("SPINELBPF_ROOT"); r != "" {
		return r
	}
	_, f, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(f), "..", ".."))
}

func defaultConfig() (Config, error) {
	repo := repoRoot()
	if repo == "" {
		return Config{}, fmt.Errorf("cannot locate the spinel-bpf-mlir repo (set SPINELBPF_ROOT)")
	}
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	if v := os.Getenv("SPINELBPF_LOADER"); v != "" && v != "bml" {
		return Config{}, fmt.Errorf("SPINELBPF_LOADER=%s: the Go loader was removed — the only loader is bml (unset SPINELBPF_LOADER)", v)
	}
	ec := env("EBPF_COMPILE", filepath.Join(repo, "build", "bpf-mlir", "bin", "ebpf-compile"))
	llvm := env("LLVM_PREFIX", "/opt/llvm-23.1.1")
	return Config{
		Repo:        repo,
		Spinel:      env("SPINEL", filepath.Join(repo, "third_party", "spinel", "bin", "spinel")),
		EbpfCompile: ec,
		SchemaCheck: filepath.Join(filepath.Dir(ec), "ebpf-schema-check"),
		Clang:       filepath.Join(llvm, "bin", "clang"),
		Go:          env("GO", "/usr/local/go/bin/go"),
		LineInfo:    "auto",
		LoaderLibs:  env("SPINELBPF_LOADER_LIBS", filepath.Join(repo, "build", "bml", "lib")),
	}, nil
}

type BuildResult struct {
	Output *frontend.Output
	Files  []string
	Reused bool
}

func Build(cfg Config, source string) (res *BuildResult, err error) {
	seam := cfg.SeamEmit != ""
	if !seam {
		if _, err := os.Stat(cfg.Spinel); err != nil {
			return nil, fmt.Errorf("tool not found: %s (run scripts/setup.sh, or set SPINEL)", cfg.Spinel)
		}
		if _, err := toolchain.CheckSpinel(cfg.Spinel, cfg.Repo); err != nil {
			return nil, err
		}
	}
	compile := true
	for _, p := range []string{cfg.EbpfCompile, cfg.SchemaCheck, cfg.Clang} {
		if _, err := os.Stat(p); err != nil {
			compile = false
		}
	}
	verifiedCommit := ""
	if compile {
		v, err := toolchain.Check(cfg.EbpfCompile, cfg.Repo)
		if err != nil {
			return nil, err
		}
		verifiedCommit = v.Commit
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return nil, err
	}
	dir, base := filepath.Dir(abs), filepath.Base(abs)
	name := strings.TrimSuffix(base, ".rb")
	if name == base || name == "" {
		return nil, fmt.Errorf("%s: the source must be a .rb file", source)
	}
	var out *frontend.Output
	var gerr error
	var si *seamInput
	if seam {
		bc, err := bpfMLIRCommit(cfg, verifiedCommit)
		if err != nil {
			return nil, err
		}
		si, gerr = readSeam(cfg, abs, name, bc)
		if si != nil {
			out = si.Output
		}
	} else {
		work := workDir(cfg.Repo, abs)
		defer func() {
			if err == nil && os.Getenv("SPINELBPF_KEEP_WORK") != "1" {
				err = os.RemoveAll(work)
			}
		}()
		if err := os.RemoveAll(work); err != nil {
			return nil, err
		}
		lib := filepath.Join(cfg.Repo, "ruby", "lib")
		sp := frontend.Spinel{Bin: cfg.Spinel, LibDir: lib}
		out, gerr = frontend.Generate(sp, work, abs)
	}
	r := &BuildResult{Output: out}
	write := func(fname string, data []byte) error {
		p := filepath.Join(dir, fname)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return err
		}
		r.Files = append(r.Files, p)
		return nil
	}
	if out != nil && out.Domain != nil {
		if err := write(name+".domain.json", out.Domain); err != nil {
			return r, err
		}
	}
	if gerr != nil {
		return r, gerr
	}
	if !compile {
		if r, err := reuseCommitted(r, dir, name, out); err != nil || si == nil {
			return r, err
		}
		return r, write(name+".inspect-manifest.json", si.Manifest)
	}
	if err := write(name+".mlir", []byte(out.MLIR)); err != nil {
		return r, err
	}
	if err := write(name+".schema.json", out.Schema); err != nil {
		return r, err
	}
	if err := write(name+".maps.json", out.Maps); err != nil {
		return r, err
	}
	if err := runIn(dir, cfg.SchemaCheck, name+".schema.json"); err != nil {
		return r, fmt.Errorf("ebpf-schema-check refused the generated schema: %w", err)
	}
	stderr, err := compileELF(cfg, dir, name)
	if err != nil {
		return r, err
	}
	if err := write(name+".compile_warnings.txt", []byte(stderr)); err != nil {
		return r, err
	}
	if err := addCompileWarnings(out, "", stderr); err != nil {
		return r, err
	}
	r.Files = append(r.Files, filepath.Join(dir, name+".bpf.o"))
	if err := checkMapSymbols(filepath.Join(dir, name+".bpf.o"), out.Schema); err != nil {
		return r, err
	}
	if elf, err := os.ReadFile(filepath.Join(dir, name+".bpf.o")); err != nil {
		return r, err
	} else if si != nil {
		if err := frontend.UprobeBuildCheckFiles(elf, si.Files, si.Decl); err != nil {
			return r, err
		}
	} else if err := frontend.UprobeBuildCheck(elf, out.Result); err != nil {
		return r, err
	}
	sha, err := checkSchemaSHA(filepath.Join(dir, name+".bpf.o"), out.Schema)
	if err != nil {
		return r, err
	}
	if err := checkRecordsTable(out.Schema, out.Records); err != nil {
		return r, err
	}
	if err := write(name+"_embed.S", []byte(embedAsmRecords(name+".bpf.o", sha, name+".maps.json", out.Records))); err != nil {
		return r, err
	}
	if err := runIn(dir, cfg.Clang, "-c", "-x", "assembler", name+"_embed.S", "-o", name+"_embed.o"); err != nil {
		return r, fmt.Errorf("assembling the ELF embedding: %w", err)
	}
	r.Files = append(r.Files, filepath.Join(dir, name+"_embed.o"))
	if si != nil {
		if err := write(name+".inspect-manifest.json", si.Manifest); err != nil {
			return r, err
		}
	}
	return r, nil
}

func workDir(repo, abs string) string {
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(repo, "build", "spinelbpf", fmt.Sprintf("%s-%x-work", strings.TrimSuffix(filepath.Base(abs), ".rb"), sum[:4]))
}

func embedAsm(elf, sha, maps string) string { return embedAsmRecords(elf, sha, maps, "") }

func embedAsmRecords(elf, sha, maps, records string) string {
	rec := ""
	if records != "" {
		rec = fmt.Sprintf("  .globl spinelbpf_records\nspinelbpf_records:\n  .asciz \"%s\"\n", strings.ReplaceAll(records, "\n", `\n`))
	}
	return fmt.Sprintf(`# Code generated by spinelbpf. DO NOT EDIT.
  .section .rodata.spinelbpf_elf,"a"
  .balign 8
  .globl spinelbpf_elf_start
spinelbpf_elf_start:
  .incbin %q
  .globl spinelbpf_elf_end
spinelbpf_elf_end:
  .globl spinelbpf_schema_sha
spinelbpf_schema_sha:
  .asciz %q
  .globl spinelbpf_maps_json
spinelbpf_maps_json:
  .incbin %q
  .byte 0
%s  .section .note.GNU-stack,"",@progbits
`, elf, sha, maps, rec)
}

func compileELF(cfg Config, dir, name string) (string, error) {
	cmd := exec.Command(cfg.EbpfCompile, name+".mlir", "--schema", name+".schema.json", "--line-info="+cfg.LineInfo, "-o", name+".bpf.o")
	cmd.Dir = dir
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		if d, ok := unrollBudget(se.String()); ok {
			return "", &frontend.Error{Diags: frontend.Diags{d}}
		}
		return "", fmt.Errorf("ebpf-compile: %s", toolchain.RewriteLocs(fmt.Sprintf("%s: %v\n%s%s", filepath.Base(cfg.EbpfCompile), err, so.String(), strings.TrimSpace(se.String()))))
	}
	if so.Len() > 0 {
		_, err := toolchain.ParseCompileOutput(so.String(), "")
		return "", err
	}
	return se.String(), nil
}

var budgetMsg = regexp.MustCompile(`^loc\("([^"/]+)":(\d+):(\d+)\): error: 'ebpf\.loop' op (unrolling a body of .* is estimated at more than the limit of \d+ op\(s\) this compiler supports)$`)

func unrollBudget(stderr string) (frontend.Diag, bool) {
	for _, line := range strings.Split(stderr, "\n") {
		m := budgetMsg.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ln, _ := strconv.Atoi(m[2])
		col, _ := strconv.Atoi(m[3])
		return frontend.Diag{Verdict: frontend.Rejected, Code: frontend.SB030LoopShape, Pos: frontend.Pos{File: m[1], Line: ln, Col: col},
			Msg: "ebpf-compile: " + m[4] + " — the unrolled loop is too large for bpf-mlir: fewer iterations, a smaller body, or split the work over two loops"}, true
	}
	return frontend.Diag{}, false
}

const compileWarningFixes = " — known fixes (bpf-mlir): keep a constant default out of the index, e.g. put the ref.index inside the present region; leave room after a record array up to the next power of two"

func addCompileWarnings(out *frontend.Output, stdout, stderr string) error {
	ws, err := toolchain.ParseCompileOutput(stdout, stderr)
	if err != nil {
		return err
	}
	for _, w := range ws {
		msg := "ebpf-compile: " + w.Msg
		for _, n := range w.Notes {
			msg += fmt.Sprintf(" (note at %s: %s)", n.Loc, n.Msg)
		}
		msg += compileWarningFixes
		out.Result.Diags = append(out.Result.Diags, frontend.Diag{
			Verdict: frontend.Conditional, Code: frontend.SB021CompileWarning,
			Pos: frontend.Pos{File: w.Loc.File, Line: w.Loc.Line, Col: w.Loc.Col}, Msg: msg,
		})
	}
	return nil
}

func runIn(dir, bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &e, &e
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v\n%s", filepath.Base(bin), err, strings.TrimSpace(e.String()))
	}
	return nil
}

func checkMapSymbols(elfPath string, schema []byte) error {
	elf, err := os.ReadFile(elfPath)
	if err != nil {
		return err
	}
	syms, err := layout.MapSymbols(elf)
	if err != nil {
		return fmt.Errorf("reading the map symbols of %s: %w", elfPath, err)
	}
	var doc struct {
		Core struct {
			Maps []struct {
				Symbol string `json:"symbol"`
			} `json:"maps"`
		} `json:"core"`
	}
	if err := strictUnmarshal(schema, &doc); err != nil {
		return err
	}
	var want []string
	for _, m := range doc.Core.Maps {
		want = append(want, m.Symbol)
	}
	sort.Strings(syms)
	sort.Strings(want)
	if strings.Join(syms, ",") != strings.Join(want, ",") {
		return fmt.Errorf("the ELF's map symbols %v differ from the schema's maps %v", syms, want)
	}
	return nil
}

func checkRecordsTable(schema []byte, table string) error {
	var doc struct {
		Core struct {
			Records []struct {
				Symbol string `json:"symbol"`
				Size   int    `json:"size"`
				Fields []struct {
					Name   string `json:"name"`
					Offset int    `json:"offset"`
					Type   struct {
						Kind    string `json:"kind"`
						Bits    int    `json:"bits"`
						Signed  bool   `json:"signed"`
						Count   int    `json:"count"`
						Element struct {
							Bits   int  `json:"bits"`
							Signed bool `json:"signed"`
						} `json:"element"`
					} `json:"type"`
				} `json:"fields"`
			} `json:"records"`
			Globals []struct {
				Name    string `json:"name"`
				Section string `json:"section"`
				Type    struct {
					Bits   int  `json:"bits"`
					Signed bool `json:"signed"`
				} `json:"type"`
			} `json:"globals"`
			Maps []struct {
				Symbol string          `json:"symbol"`
				Kind   string          `json:"kind"`
				Record string          `json:"record"`
				Key    json.RawMessage `json:"key"`
				Value  json.RawMessage `json:"value"`
			} `json:"maps"`
		} `json:"core"`
	}
	if err := strictUnmarshal(schema, &doc); err != nil {
		return fmt.Errorf("reading the schema for the record table: %w", err)
	}
	want := map[string]string{}
	line := func(row, sym string) {
		for _, r := range doc.Core.Records {
			if r.Symbol != sym {
				continue
			}
			l := fmt.Sprintf("%s|%s|size=%d;", row, r.Symbol, r.Size)
			for _, f := range r.Fields {
				t := "u"
				if f.Type.Kind == "array" {
					if f.Type.Element.Signed {
						t = "i"
					}
					for i := 0; i < f.Type.Count; i++ {
						l += fmt.Sprintf("%s[%d]:%d:%s%d;", f.Name, i, f.Offset+i*f.Type.Element.Bits/8, t, f.Type.Element.Bits)
					}
					continue
				}
				if f.Type.Signed {
					t = "i"
				}
				l += fmt.Sprintf("%s:%d:%s%d;", f.Name, f.Offset, t, f.Type.Bits)
			}
			want[row] = l
		}
	}
	for _, m := range doc.Core.Maps {
		var k struct {
			Kind   string `json:"kind"`
			Symbol string `json:"symbol"`
		}
		if m.Kind != "ringbuf" && json.Unmarshal(m.Key, &k) == nil && k.Kind == "record_ref" {
			line(m.Symbol+":key", k.Symbol)
		}
		var v struct {
			Kind   string `json:"kind"`
			Symbol string `json:"symbol"`
		}
		switch {
		case m.Kind == "ringbuf":
			v.Symbol = m.Record
		case json.Unmarshal(m.Value, &v) != nil || v.Kind != "record_ref":
			continue
		}
		line(m.Symbol, v.Symbol)
	}
	wantG := map[string]string{}
	for _, g := range doc.Core.Globals {
		t := "u"
		if g.Type.Signed {
			t = "i"
		}
		wantG[g.Name] = fmt.Sprintf("G|%s|%s|%s%d", g.Name, g.Section, t, g.Type.Bits)
	}
	gotG := map[string]bool{}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSuffix(table, "\n"), "\n") {
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "G|") {
			p := strings.Split(l, "|")
			if len(p) != 5 || (p[4] != "0" && p[4] != "1") || (p[4] == "1" && p[2] != "rodata") || wantG[p[1]] != strings.Join(p[:4], "|") || gotG[p[1]] {
				return fmt.Errorf("the embedded global row %q does not match the schema's core.globals (%q)", l, wantG[p[1]])
			}
			gotG[p[1]] = true
			continue
		}
		parts := strings.SplitN(l, "|", 3)
		if len(parts) != 3 {
			return fmt.Errorf("the record layout table has a malformed line %q", l)
		}
		named := parts[0] + "|" + parts[1] + "|"
		for i, x := range strings.Split(strings.TrimSuffix(parts[2], ";"), ";") {
			if i > 0 && strings.HasPrefix(x, "_pad") {
				continue
			}
			named += x + ";"
		}
		got[parts[0]] = named
	}
	if len(gotG) != len(wantG) {
		return fmt.Errorf("the embedded table has %d global rows but the schema has %d globals", len(gotG), len(wantG))
	}
	if len(got) != len(want) {
		return fmt.Errorf("the record layout table has %d record maps but the schema has %d — the table and the schema come from different builds", len(got), len(want))
	}
	for k, w := range want {
		if got[k] != w {
			return fmt.Errorf("the record layout table differs from the schema for map %s:\n  table:  %s\n  schema: %s", k, got[k], w)
		}
	}
	return nil
}

func checkSchemaSHA(elfPath string, schema []byte) (string, error) {
	elf, err := os.ReadFile(elfPath)
	if err != nil {
		return "", err
	}
	p, err := bindrt.Parse(elf)
	if err != nil {
		return "", fmt.Errorf("reading the requirements of %s: %w", elfPath, err)
	}
	sum := sha256.Sum256(schema)
	want := hex.EncodeToString(sum[:])
	if got := p.Requirements().SchemaSHA256; got != want {
		return "", fmt.Errorf("the ELF's requirements carry schema sha256 %s but the schema file is %s", got, want)
	}
	return want, nil
}

func strictUnmarshal(data []byte, v any) error {
	var all any
	if err := requirements.DecodeStrictJSON(data, &all); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
