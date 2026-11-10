// Package toolchain checks the versions of the ebpf-compile and spinel that spinelbpf uses (copied from mojo-bpf-mlir's
// internal/toolchain, with the Spinel check added).
//
// ebpf-compile: the compiler and the Go module are checked against one pinned commit (the same contract as
// go-bpf-mlir's — earlier the describe itself had to be `go/<module version>`, but the development pin's commit
// ab0db4b40 is not a release tag). On the `bpf-mlir <describe> (commit <sha>)` line of `ebpf-compile --version`, it
// stops loudly unless all of these hold — there is no path that skips the check:
//
//  1. the --version commit is PinnedCompilerCommit (the describe is only a provenance record — the version string is not checked)
//  2. the describe does not end in `-dirty` and is not `unknown` (a build from source changed from the pinned commit is refused)
//  3. the version of BPFMLIRGoModule (in the development form, bpf-mlir's Go module) in spinelbpf's build
//     (runtime/debug.ReadBuildInfo — a replace or (devel) stops) is PinnedModuleVersion
//  4. when the repo has third_party/bpf-mlir, its source commit (submoduleSource — in the development form, the
//     submodule's HEAD) is the --version commit
//
// In the public form (the public build), the commit in 1 is ReleaseCompilerCommit (the source release of
// bpf-mlir ReleaseCompilerVersion), and the module in 3 is go-bpf-mlir at ReleaseGoModuleVersion (the release that
// copies bpf-mlir's Go packages — go-bpf-mlir, the model, copies the packages into its own tree and so does not check a
// module, but this repo requires a separate module, so it checks the version). 2 is the same. 4 is the source_commit in
// SOURCE_VERSION at the root of the submodule's tree (the HEAD of the public bpf-mlir submodule is the export commit, a
// different SHA from C, the release compiler commit).
//
// spinel: the `(<commit>)` of `spinel --version` must be a prefix of SpinelCommit (the pinned version), and, when the
// repo has third_party/spinel, also match its HEAD.
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

// BPFMLIRGoModule, PinnedCompilerCommit, PinnedModuleVersion, compilerFix and moduleNote come from the pair of pin files
// split between the development build and the public build (pin_public.go is the public form's file; a copy of
// go-bpf-mlir's pair of pin files).

// SpinelCommit is the pinned Spinel commit (upstream matz/spinel). When raising the version, move this value and the
// submodule to the same commit.
const SpinelCommit = "086d514d"

// Verified holds the checked values (written into the artefacts' provenance record).
type Verified struct {
	Describe  string // the --version describe (a provenance record — no longer checked)
	Commit    string // the --version commit
	Module    string // the bpf-mlir/go version in spinelbpf's build
	Submodule string // the HEAD of third_party/bpf-mlir ("" when there is no submodule)
}

var versionLine = regexp.MustCompile(`(?m)^\s*bpf-mlir (\S+) \(commit (\S+)\)\s*$`)
var spinelLine = regexp.MustCompile(`^spinel \S+ \(([0-9a-f]{7,40})\)`)

// ModuleVersion takes the bpf-mlir/go version from the build information. A replace, (devel) or a missing dependency is
// an error.
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

// Verify checks the --version output, the module version and the submodule commit ("" for none) against the pin (checks
// 1–4 above).
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
	if err := ModuleStep(moduleVersion); err != nil {
		return v, err
	}
	if submoduleCommit != "" && submoduleCommit != v.Commit {
		return v, fmt.Errorf("ebpf-compile was built from bpf-mlir commit %s but %s %s — rebuild with scripts/setup.sh", v.Commit, submoduleWhat, submoduleCommit)
	}
	return v, nil
}

// ModuleStep is step 3 of Verify: the bpf-mlir Go module version against the pin. The C driver's frontend subprocess runs it on
// its own build information, with the same text.
func ModuleStep(moduleVersion string) error {
	if moduleVersion != PinnedModuleVersion {
		return fmt.Errorf("spinelbpf was built with %s %s, but the pinned version is %s (%s) — rebuild spinelbpf with the go.mod of this repo", BPFMLIRGoModule, moduleVersion, PinnedModuleVersion, moduleNote)
	}
	return nil
}

// headOf is the HEAD of repo/third_party/<name> ("" if there is no submodule).
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

// Check reads ebpf-compile's --version and checks it with spinelbpf's build information and the repo's submodule.
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

// sourceVersionFormat is the SOURCE_VERSION format version that can be read (`format=1`, as in the public bpf-mlir
// v1.21.0 export).
const sourceVersionFormat = "1"

// ParseSourceVersion strictly reads SOURCE_VERSION at the root of a bpf-mlir source release tree (matching the real
// file's 3 lines — an earlier version wrongly expected 2):
// exactly 3 lines, `format=1`, `version=<N.N.N>` and `source_commit=<40 lowercase hex digits>`, in this order (at most
// one final newline). Anything else is an error (fail closed).
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

// releaseSource is the public form's value for check 4: the source_commit in repo/third_party/bpf-mlir/SOURCE_VERSION.
// Its version must equal want (without the `v`).
// It returns "" when the submodule is not checked out (neither SOURCE_VERSION nor .git exists), and an error when .git
// exists but SOURCE_VERSION does not.
// It sits in a file without a build tag so that the development form's gate also tests it (the public form's
// submoduleSource calls it).
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

// VerifySpinel checks the output of spinel --version against the pinned commit and the submodule's HEAD ("" for none).
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

// CheckSpinel checks spinel's --version.
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

// RewriteLocs rewrites ebpf-compile's diagnostic lines `loc("F":L:C): <msg>` as `F:L:C: ebpf-compile: <msg>` (display
// only — the verdict does not change).
// The position keeps the loc's relative file name — the same form as the frontend's diagnostics and SB021 (an absolute
// path would leak the build directory).
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

// CompileLoc is the position of an ebpf-compile warning / note — it keeps the loc's relative file name (the same form as
// the frontend's diagnostic positions: an absolute path would leak the build directory and break reproducibility;
// RewriteLocs for rc ≠ 0 uses the same form).
type CompileLoc struct {
	File      string
	Line, Col int
}

func (l CompileLoc) String() string { return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Col) }

// CompileWarning is one warning that ebpf-compile printed with rc 0, with the notes that follow it (the non-root index
// warning of bpf-mlir v0.10.0 — e.g. "the constant index comes from here").
type CompileWarning struct {
	Loc   CompileLoc
	Msg   string
	Notes []CompileNote
}

// CompileNote is a note attached to a warning.
type CompileNote struct {
	Loc CompileLoc
	Msg string
}

// ParseCompileOutput reads the stdout and stderr of an ebpf-compile run that ended with rc 0, and returns the warnings
// (with the notes that follow them).
// Unknown output is an error (fail closed — so we notice when bpf-mlir adds a new kind of output): non-empty stdout, a
// line without a loc, a line that is not a warning / note (error: and so on), a note before any warning, a loc with an
// absolute path.
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
