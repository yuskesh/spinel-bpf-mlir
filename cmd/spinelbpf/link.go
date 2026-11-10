package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/yuskesh/spinel-bpf-mlir/internal/frontend"
)

func reuseCommitted(r *BuildResult, dir, name string, out *frontend.Output) (*BuildResult, error) {
	for _, f := range []struct {
		name string
		got  []byte
	}{{name + ".mlir", []byte(out.MLIR)}, {name + ".schema.json", out.Schema}, {name + ".maps.json", out.Maps}} {
		want, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil || !bytes.Equal(f.got, want) {
			return r, fmt.Errorf("ebpf-compile (or ebpf-schema-check / clang) is not available and %s differs from the committed one — the eBPF side changed, so it must be compiled (run scripts/setup.sh)", f.name)
		}
	}
	for _, f := range []string{name + ".bpf.o", name + "_embed.o"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return r, fmt.Errorf("ebpf-compile is not available and %s is missing — run scripts/setup.sh", f)
		}
	}
	cw, err := os.ReadFile(filepath.Join(dir, name+".compile_warnings.txt"))
	if err != nil {
		return r, fmt.Errorf("ebpf-compile is not available and %s.compile_warnings.txt is missing — run scripts/setup.sh (the committed warnings of the ELF are part of the generated artefacts)", name)
	}
	if err := addCompileWarnings(out, "", string(cw)); err != nil {
		return r, fmt.Errorf("%s.compile_warnings.txt: %w", name, err)
	}
	r.Reused = true
	return r, nil
}

func Link(cfg Config, source, exe string) error {
	abs, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	outAbs, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	dir, name := filepath.Dir(abs), strings.TrimSuffix(filepath.Base(abs), ".rb")
	if err := checkBMLVersions(cfg); err != nil {
		return err
	}
	var links []string
	for _, a := range bmlArchives {
		p := filepath.Join(cfg.LoaderLibs, a)
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("the C loader archive %s is missing — run scripts/setup.sh (or set SPINELBPF_LOADER_LIBS)", p)
		}
		links = append(links, "--link", p)
	}
	links = append(links, "--link", filepath.Join(dir, name+"_embed.o"))
	tmp := filepath.Join(cfg.Repo, "build", "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	sp := exec.Command(cfg.Spinel, append([]string{"-I", filepath.Join(cfg.Repo, "ruby", "lib"), filepath.Base(abs), "-o", outAbs}, links...)...)
	sp.Dir = dir
	sp.Env = append(os.Environ(), "TMPDIR="+tmp)
	if o, err := sp.CombinedOutput(); err != nil {
		return fmt.Errorf("linking with spinel: %v\n%s", err, o)
	}
	allow, err := readAllow(filepath.Join(cfg.Repo, "packaging", "needed.allow"))
	if err != nil {
		return err
	}
	return CheckNeeded(outAbs, allow)
}

func readAllow(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			m[l] = true
		}
	}
	return m, nil
}

func CheckNeeded(exe string, allow map[string]bool) error {
	f, err := elf.Open(exe)
	if err != nil {
		return err
	}
	defer f.Close()
	libs, err := f.ImportedLibraries()
	if err != nil {
		return err
	}
	var bad []string
	for _, l := range libs {
		if !allow[l] {
			bad = append(bad, l)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%s needs shared libraries outside packaging/needed.allow: %v (all: %v)", exe, bad, libs)
	}
	for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
		if v, _ := f.DynString(tag); len(v) > 0 {
			return fmt.Errorf("%s has %v %v — the executable must not depend on a search path", exe, tag, v)
		}
	}
	return nil
}
