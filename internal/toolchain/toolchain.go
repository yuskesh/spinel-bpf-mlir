package toolchain

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
)

const SpinelCommit = "086d514d"

type Verified struct {
	Describe  string
	Commit    string
	Module    string
	Submodule string
}

var versionLine = regexp.MustCompile(`(?m)^\s*bpf-mlir (\S+) \(commit (\S+)\)\s*$`)
var spinelLine = regexp.MustCompile(`^spinel \S+ \(([0-9a-f]{7,40})\)`)

func ModuleVersion(bi *debug.BuildInfo) (string, error) {
	if bi == nil {
		return "", errors.New("spinelbpf has no build information (runtime/debug.ReadBuildInfo) — cannot tell which bpf-mlir/go it was built with")
	}
	for _, d := range bi.Deps {
		if d.Path != BPFMLIRGoModule {
			continue
		}
		if d.Replace != nil {
			return "", fmt.Errorf("spinelbpf was built with %s replaced by %s %s — the compiler version cannot be checked against a replaced module (remove the replace directive)", BPFMLIRGoModule, d.Replace.Path, d.Replace.Version)
		}
		if d.Version == "" || d.Version == "(devel)" {
			return "", fmt.Errorf("spinelbpf was built with %s at version %q — the compiler version cannot be checked against an unversioned module", BPFMLIRGoModule, d.Version)
		}
		return d.Version, nil
	}
	return "", fmt.Errorf("spinelbpf's build information has no dependency %s", BPFMLIRGoModule)
}

func Verify(versionOutput, moduleVersion, submoduleCommit string) (Verified, error) {
	fix := compilerFix
	m := versionLine.FindStringSubmatch(versionOutput)
	if m == nil {
		return Verified{}, fmt.Errorf("ebpf-compile --version has no `bpf-mlir <version> (commit <sha>)` line — spinelbpf needs bpf-mlir commit %s; %s", PinnedCompilerCommit, fix)
	}
	v := Verified{Describe: m[1], Commit: m[2], Module: moduleVersion, Submodule: submoduleCommit}
	if v.Commit != PinnedCompilerCommit {
		return v, fmt.Errorf("ebpf-compile is bpf-mlir %s (commit %s), but spinelbpf needs exactly bpf-mlir commit %s; %s", v.Describe, v.Commit, PinnedCompilerCommit, fix)
	}
	if strings.HasSuffix(v.Describe, "-dirty") || v.Describe == "unknown" {
		return v, fmt.Errorf("ebpf-compile is bpf-mlir %q (commit %s), a build from modified or unidentified source: spinelbpf refuses it; %s", v.Describe, v.Commit, fix)
	}
	if moduleVersion != PinnedModuleVersion {
		return v, fmt.Errorf("spinelbpf was built with %s %s, but the pinned version is %s (%s) — rebuild spinelbpf with the go.mod of this repo", BPFMLIRGoModule, moduleVersion, PinnedModuleVersion, moduleNote)
	}
	if submoduleCommit != "" && submoduleCommit != v.Commit {
		return v, fmt.Errorf("ebpf-compile was built from bpf-mlir commit %s but %s %s — rebuild with scripts/setup.sh", v.Commit, submoduleWhat, submoduleCommit)
	}
	return v, nil
}

func headOf(repo, name string) (string, error) {
	if repo == "" {
		return "", nil
	}
	sub := filepath.Join(repo, "third_party", name)
	if _, err := os.Stat(filepath.Join(sub, ".git")); err != nil {
		return "", nil
	}
	out, err := exec.Command("git", "-C", sub, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("reading the commit of %s: %w", sub, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func Check(compiler, repo string) (Verified, error) {
	out, err := exec.Command(compiler, "--version").CombinedOutput()
	if err != nil {
		return Verified{}, fmt.Errorf("running %s --version: %w", compiler, err)
	}
	bi, _ := debug.ReadBuildInfo()
	mod, err := ModuleVersion(bi)
	if err != nil {
		return Verified{}, err
	}
	sub, err := submoduleSource(repo)
	if err != nil {
		return Verified{}, err
	}
	return Verify(string(out), mod, sub)
}

var sourceVersionNumber = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var sourceCommitHex = regexp.MustCompile(`^[0-9a-f]{40}$`)

const sourceVersionFormat = "1"

func ParseSourceVersion(b []byte) (version, commit string, err error) {
	s := string(b)
	if strings.ContainsRune(s, '\r') {
		return "", "", errors.New("SOURCE_VERSION has a carriage return")
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) != 3 {
		return "", "", fmt.Errorf("SOURCE_VERSION has %d lines, want exactly 3 (format=, version= and source_commit=)", len(lines))
	}
	if lines[0] != "format="+sourceVersionFormat {
		return "", "", fmt.Errorf("SOURCE_VERSION line 1 is %q, want format=%s", lines[0], sourceVersionFormat)
	}
	version, ok := strings.CutPrefix(lines[1], "version=")
	if !ok || !sourceVersionNumber.MatchString(version) {
		return "", "", fmt.Errorf("SOURCE_VERSION line 2 is %q, want version=<major>.<minor>.<patch>", lines[1])
	}
	commit, ok = strings.CutPrefix(lines[2], "source_commit=")
	if !ok || !sourceCommitHex.MatchString(commit) {
		return "", "", fmt.Errorf("SOURCE_VERSION line 3 is %q, want source_commit=<40 lowercase hex digits>", lines[2])
	}
	return version, commit, nil
}

func releaseSource(repo, want string) (string, error) {
	if repo == "" {
		return "", nil
	}
	sub := filepath.Join(repo, "third_party", "bpf-mlir")
	path := filepath.Join(sub, "SOURCE_VERSION")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Stat(filepath.Join(sub, ".git")); e != nil {
			return "", nil
		}
		return "", fmt.Errorf("%s is checked out but has no SOURCE_VERSION — spinelbpf checks ebpf-compile against the source_commit of the bpf-mlir %s source release", sub, want)
	}
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	v, c, err := ParseSourceVersion(b)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if "v"+v != want {
		return "", fmt.Errorf("%s says version %s, but spinelbpf needs the bpf-mlir %s source release", path, v, want)
	}
	return c, nil
}

func VerifySpinel(versionOutput, submoduleHead string) (string, error) {
	fix := "build Spinel " + SpinelCommit + " (scripts/setup.sh in spinel-bpf-mlir), or point SPINEL at a build of that commit"
	m := spinelLine.FindStringSubmatch(strings.TrimSpace(versionOutput))
	if m == nil {
		return "", fmt.Errorf("spinel --version has no `spinel <version> (<commit>)` line (%q); %s", strings.TrimSpace(versionOutput), fix)
	}
	c := m[1]
	if !strings.HasPrefix(c, SpinelCommit) && !strings.HasPrefix(SpinelCommit, c) {
		return c, fmt.Errorf("spinel is commit %s but spinelbpf is pinned to %s — the frontend reads Spinel's AST and types, whose shape is only checked for that commit; %s", c, SpinelCommit, fix)
	}
	if submoduleHead != "" && !strings.HasPrefix(submoduleHead, c) {
		return c, fmt.Errorf("spinel was built from commit %s but third_party/spinel is at %s — rebuild with scripts/setup.sh", c, submoduleHead)
	}
	return c, nil
}

func CheckSpinel(spinel, repo string) (string, error) {
	out, err := exec.Command(spinel, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("running %s --version: %w", spinel, err)
	}
	head, err := headOf(repo, "spinel")
	if err != nil {
		return "", err
	}
	return VerifySpinel(string(out), head)
}

var diagLoc = regexp.MustCompile(`^loc\("([^"]+)":(\d+):(\d+)\): (.*)$`)

func RewriteLocs(output string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if m := diagLoc.FindStringSubmatch(line); m != nil && !filepath.IsAbs(m[1]) {
			fmt.Fprintf(&b, "%s:%s:%s: ebpf-compile: %s\n", m[1], m[2], m[3], m[4])
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

type CompileLoc struct {
	File      string
	Line, Col int
}

func (l CompileLoc) String() string { return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Col) }

type CompileWarning struct {
	Loc   CompileLoc
	Msg   string
	Notes []CompileNote
}

type CompileNote struct {
	Loc CompileLoc
	Msg string
}

func ParseCompileOutput(stdout, stderr string) ([]CompileWarning, error) {
	unknown := func(what, line string) error {
		return fmt.Errorf("ebpf-compile exited 0 with %s — a new output shape of ebpf-compile; update spinelbpf's reader: %q", what, line)
	}
	if stdout != "" {
		return nil, unknown("output on stdout", strings.TrimRight(stdout, "\n"))
	}
	var ws []CompileWarning
	if stderr == "" {
		return nil, nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
		m := diagLoc.FindStringSubmatch(line)
		if m == nil || filepath.IsAbs(m[1]) {
			return nil, unknown("a stderr line that is not loc(\"<relative file>\":L:C): warning|note: …", line)
		}
		ln, _ := strconv.Atoi(m[2])
		col, _ := strconv.Atoi(m[3])
		loc := CompileLoc{File: m[1], Line: ln, Col: col}
		switch {
		case strings.HasPrefix(m[4], "warning: "):
			ws = append(ws, CompileWarning{Loc: loc, Msg: strings.TrimPrefix(m[4], "warning: ")})
		case strings.HasPrefix(m[4], "note: "):
			if len(ws) == 0 {
				return nil, unknown("a note before any warning", line)
			}
			w := &ws[len(ws)-1]
			w.Notes = append(w.Notes, CompileNote{Loc: loc, Msg: strings.TrimPrefix(m[4], "note: ")})
		default:
			return nil, unknown("a diagnostic that is neither a warning nor a note", line)
		}
	}
	return ws, nil
}
