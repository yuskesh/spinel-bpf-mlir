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

// The verified-key skip: tests that rerun fixed facts on the kernel (differential tables, mutation controls, hook
// mutations, veth) are skipped when their static input key (a sha256) is in testdata/verified.tsv. The key covers every
// determinant of the artefacts — the frontend's and the build's Go source, the library's Ruby, the closure of the test's
// source and its testdata / examples / scripts, the toolchain binaries (spinel, libspinel_rt.a, ebpf-compile,
// ebpf-schema-check, the bml archives), the gcc / clang / go versions, uname -r and nproc.
//
//	SPINELBPF_VERIFIED=off      run everything (the control run, and every periodic full run)
//	VERIFIED_RECORD=E<n>        add the rows of the passing tests to verified.tsv, under experiment number <n> (the gate does not write)
//
// A test that ran because its key was missing is named in build/tmp/unverified.txt (the gate lists them at the end —
// having run is not a failure).
//
// The test-source items are found by walking, with go/parser, the reference closure from the test function (the
// package's top-level funcs, methods, types, vars and consts — in every file, whatever the build tag); a hand-written
// dependency list would go stale and give stale skips. The testdata and examples are those whose dir or file name under
// cmd/spinelbpf/testdata, internal/frontend/testdata or examples matches a string literal in the closure; scripts are all
// of scripts/ when a literal ends in .sh (the scripts source one another).

const verifiedTSV = "testdata/verified.tsv"

func shaFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// shaTree lists the path and sha of the files under root for which pred is true (sorted).
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

// cBuildScript is the script that builds the C default binary. If it is renamed, the key follows this one name.
const cBuildScript = "scripts/build-c-driver.sh"

// cBuildArchive is bml's archive that only the C driver links. It is not in bmlArchives, which is the Go driver's link order.
const cBuildArchive = "libbml_build.a"

// cBuildInclude is the installed header tree that the C build script passes with -I (bml's headers and the libbpf, libelf and zlib
// ones). Every file under it is a compile-time input: a changed enum or struct layout there is not pinned by the archive alone.
const cBuildInclude = "build/bml/include"

// cDefaultKey is the key items for the C default build: every C source and header under csrc, every file under
// cBuildInclude, the C build script and cBuildArchive. Once the tests build their executables with the C default, a change to any
// of these must change the key, or an old verified row could skip a test after a C change. TestVerifiedKeyCoversCDefault is its
// control.
func cDefaultKey(repo, loaderLibs string) ([]string, error) {
	k, err := shaTree(filepath.Join(repo, "csrc"), func(p string) bool {
		return strings.HasSuffix(p, ".c") || strings.HasSuffix(p, ".h")
	})
	if err != nil {
		return nil, err
	}
	if len(k) == 0 {
		return nil, fmt.Errorf("verified key: no C source under %s", filepath.Join(repo, "csrc"))
	}
	inc, err := shaTree(filepath.Join(repo, cBuildInclude), func(string) bool { return true })
	if err != nil {
		return nil, err
	}
	if len(inc) == 0 {
		return nil, fmt.Errorf("verified key: no header under %s", filepath.Join(repo, cBuildInclude))
	}
	k = append(k, inc...)
	for _, f := range []string{filepath.Join(repo, cBuildScript), filepath.Join(loaderLibs, cBuildArchive)} {
		h, err := shaFile(f)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(repo, f)
		k = append(k, rel+" "+h)
	}
	return k, nil
}

var (
	envKeyOnce sync.Once
	envKeyVal  []string
	envKeyErr  error
)

// envKey is the key items common to every covered test (computed once per test process).
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
		// The Spinel submodule's commit (the index gitlink — for the tests that rely on a property of Spinel's internal
		// function sp_Thread_current) and the threaded runtime
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
		ck, err := cDefaultKey(r, cfg.LoaderLibs)
		if err != nil {
			envKeyErr = err
			return
		}
		k = append(k, ck...)
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

// declRef is a top-level declaration and the file that holds it.
type declRef struct {
	file string
	node ast.Node
}

var (
	pkgOnce  sync.Once
	pkgDecls map[string][]declRef
	pkgErr   error
)

// loadPkgDecls maps the top-level names of every Go file in cmd/spinelbpf (whatever the build tag) to their declarations
// (a method goes under its receiver type's name).
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

// closureOf returns the set of files of the top-level declarations reachable from the test function, and the string
// literals in them.
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

// verifiedKey returns the test's key (the common items, the test's name, the closure's files, and the testdata /
// examples / scripts that the closure's literals point at) and the list of items.
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
			// A relative dir under examples (`bcc/<tool>`) — only the tool's dir goes into the key (not the whole
			// examples/bcc tree).
			// Only clean relative paths: `"./"` and the like change shape under Clean, so they are refused (an earlier
			// version accepted `"./"` and resolved it to the whole of examples).
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
		// Untracked build products (executables) in an example's dir do not go into the key — tracked files only
		l, err := trackedTree(p)
		if err != nil {
			return "", nil, err
		}
		items = append(items, l...)
	}
	s := sha256.Sum256([]byte(strings.Join(items, "\n")))
	return hex.EncodeToString(s[:]), items, nil
}

// trackedTree lists the path and sha of the files in the git index under p (a file or dir), except verified.tsv itself
// (so that recording does not change the key).
// New untracked testdata does not go into the key — run git add -N before the gate (a rule of this repo).
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

// readVerified maps each key in verified.tsv to its experiment number.
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

// verifiedRecordAllowed reports whether the key of test name may be recorded: a test in the list of root tests
// (rootsPath) only in a formal guest run (one that has a record destination out).
// With out set, it allows without reading the list. On the host side without out, if the list cannot be read it does
// not record (fail closed).
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

// requireUnverified is called at the head of a covered test: if the key is in verified.tsv it skips; otherwise the test
// runs, and if it passes it is recorded or added to the unverified list.
// The root skip (SPINELBPF_NO_ROOT) stays where each test had it (the sudo helper) — a key skip can be told apart by its
// `verified <key>` message.
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
		// A test in the root-test list whose root part is a child t.Run would have its parent pass on the host — so
		// outside a formal guest run, do not write its key
		if !known && !verifiedRecordAllowed(t.Name(), os.Getenv("SPINELBPF_VERIFIED_OUT"), filepath.Join(repoRoot(), "cmd", "spinelbpf", "testdata", "root_tests.txt")) {
			return
		}
		verifiedMu.Lock()
		defer verifiedMu.Unlock()
		if e := os.Getenv("VERIFIED_RECORD"); e != "" {
			if known { // do not write a key that is already there (recording during an off run once wrote duplicate rows)
				return
			}
			p := filepath.Join(repoRoot(), "cmd", "spinelbpf", verifiedTSV)
			if o := os.Getenv("SPINELBPF_VERIFIED_OUT"); o != "" { // a VM guest where the repo is read-only — the host checks the rows and adds them after the boot
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
		// A test that ran although its key is verified (SPINELBPF_VERIFIED=off) goes into a separate list — not mixed
		// with the unverified ones (mixing them once made the gate's final message misreport off runs)
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

// parallel runs a test that needs no exclusive resource in parallel (a t.Parallel helper). Exclusive tests (veth,
// Thread, multi-CPU, global tracing attaches, t.Setenv) do not call it — Go runs the non-parallel top-level tests first,
// serially, and the parallel tests together afterwards.
// The degree of parallelism is the gate's `-parallel ${GATE_JOBS}`.
func parallel(t *testing.T) {
	t.Helper()
	t.Parallel()
}

// writeExec writes a file to be executed. An fd written by this process is held by the forks of parallel tests until
// they exec, and an exec in that window fails with ETXTBSY (text file busy) — so a child process (install) writes the
// executable.
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
