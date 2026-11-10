package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const verifiedTSV = "testdata/verified.tsv"

func shaFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

func shaTree(root string, pred func(string) bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !pred(p) {
			return nil
		}
		h, err := shaFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(repoRoot(), p)
		out = append(out, rel+" "+h)
		return nil
	})
	sort.Strings(out)
	return out, err
}

func firstLine(name string, args ...string) string {
	o, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("%s: error %v", name, err)
	}
	return strings.SplitN(strings.TrimSpace(string(o)), "\n", 2)[0]
}

var (
	envKeyOnce sync.Once
	envKeyVal  []string
	envKeyErr  error
)

func envKey() ([]string, error) {
	envKeyOnce.Do(func() {
		cfg, err := defaultConfig()
		if err != nil {
			envKeyErr = err
			return
		}
		r := cfg.Repo
		n, _ := os.ReadFile("/proc/sys/kernel/osrelease")
		k := []string{
			"uname -r " + strings.TrimSpace(string(n)),
			"nproc " + firstLine("nproc"),
			"gcc " + firstLine("gcc", "--version"),
			"clang " + firstLine(cfg.Clang, "--version"),
			"go " + firstLine(cfg.Go, "version"),
		}
		if o, err := exec.Command("git", "-C", r, "ls-files", "-s", "third_party/spinel").Output(); err == nil {
			k = append(k, "spinel gitlink "+strings.TrimSpace(string(o)))
		} else {
			envKeyErr = err
			return
		}
		bins := []string{cfg.Spinel, filepath.Join(r, "third_party", "spinel", "lib", "libspinel_rt.a"), filepath.Join(r, "third_party", "spinel", "lib", "libspinel_rt_mt.a"), cfg.EbpfCompile, cfg.SchemaCheck}
		for _, a := range bmlArchives {
			bins = append(bins, filepath.Join(cfg.LoaderLibs, a))
		}
		for _, b := range bins {
			h, err := shaFile(b)
			if err != nil {
				envKeyErr = err
				return
			}
			rel, _ := filepath.Rel(r, b)
			k = append(k, rel+" "+h)
		}
		goSrc := func(p string) bool { return strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") }
		for _, t := range []struct {
			dir  string
			pred func(string) bool
		}{
			{filepath.Join(r, "internal", "frontend"), func(p string) bool { return goSrc(p) && !strings.Contains(p, "/testdata/") }},
			{filepath.Join(r, "cmd", "spinelbpf"), func(p string) bool { return goSrc(p) && !strings.Contains(p, "/testdata/") }},
			{filepath.Join(r, "ruby", "lib"), func(p string) bool { return strings.HasSuffix(p, ".rb") }},
		} {
			l, err := shaTree(t.dir, t.pred)
			if err != nil {
				envKeyErr = err
				return
			}
			k = append(k, l...)
		}
		envKeyVal = k
	})
	return envKeyVal, envKeyErr
}

type declRef struct {
	file string
	node ast.Node
}

var (
	pkgOnce  sync.Once
	pkgDecls map[string][]declRef
	pkgErr   error
)

func loadPkgDecls() (map[string][]declRef, error) {
	pkgOnce.Do(func() {
		dir := filepath.Join(repoRoot(), "cmd", "spinelbpf")
		ents, err := os.ReadDir(dir)
		if err != nil {
			pkgErr = err
			return
		}
		pkgDecls = map[string][]declRef{}
		fset := token.NewFileSet()
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			af, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
			if err != nil {
				pkgErr = err
				return
			}
			add := func(name string, n ast.Node) { pkgDecls[name] = append(pkgDecls[name], declRef{e.Name(), n}) }
			for _, d := range af.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if d.Recv == nil {
						add(d.Name.Name, d)
					} else if rt := recvName(d.Recv); rt != "" {
						add(rt, d)
					}
				case *ast.GenDecl:
					for _, sp := range d.Specs {
						switch sp := sp.(type) {
						case *ast.TypeSpec:
							add(sp.Name.Name, sp)
						case *ast.ValueSpec:
							for _, n := range sp.Names {
								add(n.Name, sp)
							}
						}
					}
				}
			}
		}
	})
	return pkgDecls, pkgErr
}

func recvName(fl *ast.FieldList) string {
	if fl == nil || len(fl.List) == 0 {
		return ""
	}
	x := fl.List[0].Type
	if st, ok := x.(*ast.StarExpr); ok {
		x = st.X
	}
	if id, ok := x.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func closureOf(test string) (map[string]bool, map[string]bool, error) {
	decls, err := loadPkgDecls()
	if err != nil {
		return nil, nil, err
	}
	if len(decls[test]) == 0 {
		return nil, nil, fmt.Errorf("no declaration of %s in cmd/spinelbpf", test)
	}
	files, lits, seen := map[string]bool{}, map[string]bool{}, map[string]bool{}
	queue := []string{test}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if seen[n] {
			continue
		}
		seen[n] = true
		for _, d := range decls[n] {
			files[d.file] = true
			ast.Inspect(d.node, func(x ast.Node) bool {
				switch x := x.(type) {
				case *ast.Ident:
					if _, ok := decls[x.Name]; ok && !seen[x.Name] {
						queue = append(queue, x.Name)
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if v, err := strconv.Unquote(x.Value); err == nil {
							lits[v] = true
						}
					}
				}
				return true
			})
		}
	}
	return files, lits, nil
}

func verifiedKey(test string) (string, []string, error) {
	k, err := envKey()
	if err != nil {
		return "", nil, err
	}
	files, lits, err := closureOf(test)
	if err != nil {
		return "", nil, err
	}
	files["verified_test.go"] = true
	r := repoRoot()
	base := filepath.Join(r, "cmd", "spinelbpf")
	items := append([]string{"test " + test}, k...)
	var fl []string
	for f := range files {
		fl = append(fl, f)
	}
	sort.Strings(fl)
	for _, f := range fl {
		h, err := shaFile(filepath.Join(base, f))
		if err != nil {
			return "", nil, err
		}
		items = append(items, "cmd/spinelbpf/"+f+" "+h)
	}
	var paths []string
	scripts := false
	for l := range lits {
		if strings.HasSuffix(l, ".sh") {
			scripts = true
		}
		if l == "" || l == "." || l == ".." || strings.Contains(l, "\n") {
			continue
		}
		if strings.Contains(l, "/") {
			if filepath.Clean(l) == l && !strings.HasPrefix(l, "/") && !strings.HasPrefix(l, ".") && !strings.Contains(l, "..") {
				if fi, err := os.Stat(filepath.Join(r, "examples", l)); err == nil && fi.IsDir() {
					paths = append(paths, filepath.Join(r, "examples", l))
				}
			}
			continue
		}
		for _, d := range []string{filepath.Join(base, "testdata"), filepath.Join(r, "internal", "frontend", "testdata"), filepath.Join(r, "examples")} {
			if _, err := os.Stat(filepath.Join(d, l)); err == nil {
				paths = append(paths, filepath.Join(d, l))
			}
		}
	}
	if scripts {
		paths = append(paths, filepath.Join(r, "scripts"))
	}
	sort.Strings(paths)
	for _, p := range paths {
		l, err := trackedTree(p)
		if err != nil {
			return "", nil, err
		}
		items = append(items, l...)
	}
	s := sha256.Sum256([]byte(strings.Join(items, "\n")))
	return hex.EncodeToString(s[:]), items, nil
}

func trackedTree(p string) ([]string, error) {
	r := repoRoot()
	rel, _ := filepath.Rel(r, p)
	o, err := exec.Command("git", "-C", r, "ls-files", "-z", "--", rel).Output()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range strings.Split(string(o), "\x00") {
		if f == "" || strings.HasSuffix(f, "verified.tsv") {
			continue
		}
		h, err := shaFile(filepath.Join(r, f))
		if err != nil {
			return nil, err
		}
		out = append(out, f+" "+h)
	}
	sort.Strings(out)
	return out, nil
}

func readVerified() map[string]string {
	m := map[string]string{}
	f, err := os.Open(filepath.Join(repoRoot(), "cmd", "spinelbpf", verifiedTSV))
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Split(sc.Text(), "\t")
		if len(fs) >= 3 && !strings.HasPrefix(fs[0], "#") {
			m[fs[0]] = fs[2]
		}
	}
	return m
}

var verifiedMu sync.Mutex

func verifiedRecordAllowed(name, out, rootsPath string) bool {
	if out != "" {
		return true
	}
	b, err := os.ReadFile(rootsPath)
	if err != nil {
		return false
	}
	top := strings.SplitN(name, "/", 2)[0]
	for _, l := range strings.Fields(string(b)) {
		if l == top {
			return false
		}
	}
	return true
}

func requireUnverified(t *testing.T) {
	t.Helper()
	key, items, err := verifiedKey(t.Name())
	if err != nil {
		t.Fatalf("verified key: %v", err)
	}
	e, known := readVerified()[key]
	if known && os.Getenv("SPINELBPF_VERIFIED") != "off" {
		t.Skipf("verified %s (%s) — SPINELBPF_VERIFIED=off runs it", key[:12], e)
	}
	if os.Getenv("SPINELBPF_VERIFIED_ITEMS") == "1" {
		t.Logf("verified key items:\n%s", strings.Join(items, "\n"))
	}
	if known {
		t.Logf("verified key %s (%s) — running because SPINELBPF_VERIFIED=off", key[:12], e)
	} else {
		t.Logf("verified key %s (%d items) is not in %s — running", key[:12], len(items), verifiedTSV)
	}
	t.Cleanup(func() {
		if t.Failed() || t.Skipped() {
			return
		}
		if !known && !verifiedRecordAllowed(t.Name(), os.Getenv("SPINELBPF_VERIFIED_OUT"), filepath.Join(repoRoot(), "cmd", "spinelbpf", "testdata", "root_tests.txt")) {
			return
		}
		verifiedMu.Lock()
		defer verifiedMu.Unlock()
		if e := os.Getenv("VERIFIED_RECORD"); e != "" {
			if known {
				return
			}
			p := filepath.Join(repoRoot(), "cmd", "spinelbpf", verifiedTSV)
			if o := os.Getenv("SPINELBPF_VERIFIED_OUT"); o != "" {
				p = o
			}
			f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				t.Errorf("recording: %v", err)
				return
			}
			defer f.Close()
			fmt.Fprintf(f, "%s\t%s\t%s\t%s\n", key, t.Name(), e, time.Now().Format("2006-01-02"))
			return
		}
		list := "unverified.txt"
		if known {
			list = "verified_off.txt"
		}
		f, err := os.OpenFile(filepath.Join(repoRoot(), "build", "tmp", list), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "%s %s\n", t.Name(), key[:12])
			f.Close()
		}
	})
}

func parallel(t *testing.T) {
	t.Helper()
	t.Parallel()
}

func writeExec(t *testing.T, p string, data []byte) {
	t.Helper()
	src := p + ".src"
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("install", "-m", "0755", src, p).CombinedOutput(); err != nil {
		t.Fatalf("install %s: %v\n%s", p, err, out)
	}
	os.Remove(src)
}
