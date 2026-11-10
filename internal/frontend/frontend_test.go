package frontend

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var wantLine = regexp.MustCompile(`(?m)^# want: (SB\d{3}) (\d+):(\d+)$`)

// TestNegative checks that each file in testdata/neg is stopped with the verdict given by its trailing `# want: SBnnn L:C`.
// It checks the stop was for the intended reason: every want is present, and every stopping code is one of the want codes
// (a different code mixed in is a failure).
func TestNegative(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	files, _ := filepath.Glob(filepath.Join("testdata", "neg", "*.rb"))
	if len(files) < 30 {
		t.Fatalf("expected the negative corpus, found %d files", len(files))
	}
	for _, f := range files {
		f := f
		t.Run(strings.TrimSuffix(filepath.Base(f), ".rb"), func(t *testing.T) { checkNegative(t, sp, f) })
	}
}

// checkNegative checks one negative example (with a trailing `# want: SBnnn L:C`); TestNegative and TestUprobeNegative
// (e080_test.go) share it.
func checkNegative(t *testing.T, sp Spinel, f string) {
	text, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	wants := wantLine.FindAllStringSubmatch(string(text), -1)
	if len(wants) == 0 {
		t.Fatalf("%s has no `# want:` line", f)
	}
	res, err := Analyze(sp, t.TempDir(), f, string(text))
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	base := filepath.Base(f)
	wantCodes := map[Code]bool{}
	for _, w := range wants {
		wantCodes[Code(w[1])] = true
		found := false
		for _, d := range res.Diags {
			if string(d.Code) == w[1] && fmt.Sprintf("%d:%d", d.Pos.Line, d.Pos.Col) == w[2]+":"+w[3] && (d.Pos.File == base || d.Pos.Line == 0) && (d.Verdict == Rejected || d.Verdict == Unknown) {
				found = true
			}
		}
		if !found {
			t.Errorf("want %s at %s:%s, got:\n%s", w[1], w[2], w[3], (&Error{Diags: res.Diags}).Error())
		}
	}
	for _, d := range res.Diags {
		if (d.Verdict == Rejected || d.Verdict == Unknown) && !wantCodes[d.Code] {
			t.Errorf("stopped for an unintended reason: %s", d)
		}
	}
	// the stopping diagnostics are exactly as many as the want lines (duplicate diagnostics are dropped; this pins, in a test, the
	// reason priority table in result.go)
	blocking := 0
	for _, d := range res.Diags {
		if d.Verdict == Rejected || d.Verdict == Unknown {
			blocking++
		}
	}
	if blocking != len(wants) {
		t.Errorf("want exactly %d stopping diagnostic(s), got %d:\n%s", len(wants), blocking, (&Error{Diags: res.Diags}).Error())
	}
	if len(res.Programs) != 0 {
		t.Errorf("a refused program still produced %d programs", len(res.Programs))
	}
}

// TestPositive checks that each file in testdata/pos generates and passes ebpf-opt, ebpf-compile and ebpf-schema-check.
func TestPositive(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	files, _ := filepath.Glob(filepath.Join("testdata", "pos", "*.rb"))
	if len(files) == 0 {
		t.Fatal("no positive cases")
	}
	for _, f := range files {
		f := f
		t.Run(strings.TrimSuffix(filepath.Base(f), ".rb"), func(t *testing.T) {
			out, err := Generate(sp, t.TempDir(), f)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			compileAll(t, out)
		})
	}
}

// compileAll runs the outputs through bpf-mlir's tools.
func compileAll(t *testing.T, out *Output) []byte {
	t.Helper()
	bin := filepath.Join(repoRoot(t), "build", "bpf-mlir", "bin")
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "x.mlir"), []byte(out.MLIR), 0o644))
	must(os.WriteFile(filepath.Join(dir, "x.schema.json"), out.Schema, 0o644))
	for _, c := range [][]string{
		{"ebpf-schema-check", "x.schema.json"},
		{"ebpf-opt", "x.mlir", "-o", "/dev/null"},
		{"ebpf-compile", "x.mlir", "--schema", "x.schema.json", "-o", "x.bpf.o"},
	} {
		cmd := exec.Command(filepath.Join(bin, c[0]), c[1:]...)
		cmd.Dir = dir
		if o, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s\n--- mlir\n%s", c, err, o, out.MLIR)
		}
	}
	elf, err := os.ReadFile(filepath.Join(dir, "x.bpf.o"))
	must(err)
	return elf
}

// TestGoldenExample checks that the committed outputs of examples/xdpcount are byte-identical to the current frontend's output
// (reproducible outputs — it stops a commit that did not regenerate them).
func TestGoldenExample(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	dir := filepath.Join(root, "examples", "xdpcount")
	out, err := Generate(testSpinel(t), t.TempDir(), filepath.Join(dir, "xdpcount.rb"))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for name, got := range map[string][]byte{
		"xdpcount.mlir": []byte(out.MLIR), "xdpcount.schema.json": out.Schema, "xdpcount.maps.json": out.Maps, "xdpcount.domain.json": out.Domain,
	} {
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the frontend's output (run spinelbpf build examples/xdpcount/xdpcount.rb)\n--- got\n%s", name, got)
		}
	}
}

// TestGenerateTwice checks that generating twice from the same source gives byte-identical output (the frontend stage).
func TestGenerateTwice(t *testing.T) {
	t.Parallel()
	src := filepath.Join(repoRoot(t), "examples", "xdpcount", "xdpcount.rb")
	a, err := Generate(testSpinel(t), t.TempDir(), src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(testSpinel(t), t.TempDir(), src)
	if err != nil {
		t.Fatal(err)
	}
	if a.MLIR != b.MLIR || !bytes.Equal(a.Schema, b.Schema) || !bytes.Equal(a.Maps, b.Maps) || !bytes.Equal(a.Domain, b.Domain) {
		t.Fatal("two generations from the same source differ")
	}
}

// TestInjectionWrongClass is a negative control for type injection (giving Spinel the root's argument types): injecting a String
// argument stops with SB010.
func TestInjectionWrongClass(t *testing.T) {
	t.Parallel()
	src := filepath.Join(repoRoot(t), "examples", "xdpcount", "xdpcount.rb")
	text, _ := os.ReadFile(src)
	res, err := analyze(testSpinel(t), t.TempDir(), src, string(text), analyzeOpts{inject: `"not a context"`})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res.Diags, SB010TypingProbe, "5:16") {
		t.Fatalf("want SB010 at the context parameter (5:16), got:\n%v", (&Error{Diags: res.Diags}).Error())
	}
}

// TestInjectionComparator is a negative control for the comparator (which compares the types with and without injection): changing
// one record outside the root in the injected types gives SB010.
func TestInjectionComparator(t *testing.T) {
	t.Parallel()
	src := filepath.Join(repoRoot(t), "examples", "xdpcount", "xdpcount.rb")
	text, _ := os.ReadFile(src)
	res, err := analyze(testSpinel(t), t.TempDir(), src, string(text), analyzeOpts{mutateTyping: func(ty *Types) {
		for i, r := range ty.Types {
			if r.File == "xdpcount.rb" && r.Kind == "IntegerNode" && r.Line == 6 && r.Col == 20 {
				ty.Types[i].RBS = "Float"
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res.Diags, SB010TypingProbe, "6:21") {
		t.Fatalf("want SB010 at 6:21, got:\n%v", (&Error{Diags: res.Diags}).Error())
	}
}

// TestDynamicDispatch tests SB004 (not reachable from source in the first accepted subset — receivers are limited to map constants
// and Spinel dispatches them directly): changing a codegen record to a switch stops it.
func TestDynamicDispatch(t *testing.T) {
	t.Parallel()
	src := filepath.Join(repoRoot(t), "examples", "xdpcount", "xdpcount.rb")
	text, _ := os.ReadFile(src)
	res, err := analyze(testSpinel(t), t.TempDir(), src, string(text), analyzeOpts{mutateTyping: func(ty *Types) {
		for i, r := range ty.Codegen {
			if r.File == "xdpcount.rb" && r.Name == "atomic_add" {
				ty.Codegen[i].Dispatch, ty.Codegen[i].Callee, ty.Codegen[i].Candidates = "switch", "", []string{"ArrayMap#atomic_add", "Other#atomic_add"}
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res.Diags, SB004UnknownEdge, "6:3") {
		t.Fatalf("want SB004 at 6:3, got:\n%v", (&Error{Diags: res.Diags}).Error())
	}
}

// TestAmbiguousType tests SB015: giving one node records of two types (specialisation) stops it.
func TestAmbiguousType(t *testing.T) {
	t.Parallel()
	src := filepath.Join(repoRoot(t), "examples", "xdpcount", "xdpcount.rb")
	text, _ := os.ReadFile(src)
	res, err := analyze(testSpinel(t), t.TempDir(), src, string(text), analyzeOpts{mutateTyping: func(ty *Types) {
		for _, r := range ty.Types {
			if r.File == "xdpcount.rb" && r.Kind == "CallNode" && r.Name == "lookup" {
				r.RBS = "Integer"
				ty.Types = append(ty.Types, r)
				return
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res.Diags, SB015AmbiguousType, "7:7") {
		t.Fatalf("want SB015 at 7:7, got:\n%v", (&Error{Diags: res.Diags}).Error())
	}
}

func hasCode(ds Diags, c Code, at string) bool {
	for _, d := range ds {
		if d.Code == c && fmt.Sprintf("%d:%d", d.Pos.Line, d.Pos.Col) == at {
			return true
		}
	}
	return false
}

// TestVerifyWorld checks that the allowed op set is a subset of bpf-mlir's stage 1, that the generated ops are in the allowed set,
// and that an op outside the set stops.
func TestVerifyWorld(t *testing.T) {
	t.Parallel()
	ref, err := ReferenceOps(filepath.Join(repoRoot(t), "third_party", "bpf-mlir", "docs", "reference", "ebpf_ops.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range AllowedOps() {
		if strings.HasPrefix(op, "ebpf.") && !ref[op] {
			t.Errorf("allowed op %s is not a stage ① op of bpf-mlir", op)
		}
	}
	golden, err := os.ReadFile(filepath.Join(repoRoot(t), "examples", "xdpcount", "xdpcount.mlir"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorld(string(golden)); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(golden), "ebpf.map.update", "ebpf.map.delete", 1)
	if err := VerifyWorld(bad); err == nil {
		t.Fatal("verify-bpf-world accepted ebpf.map.delete (outside the allowed set)")
	}
}

// TestSameOpsAsMojo checks that the sequence of ops and types in the .mlir of the xdpcount example is the same as in mojo-bpf-mlir's
// same example (testdata/mojo_xdpcount.mlir — a copy of mojo-bpf-mlir's examples/xdpcount/xdpcount.mlir), ignoring locations,
// SSA names and program names.
func TestSameOpsAsMojo(t *testing.T) {
	t.Parallel()
	norm := func(s string) string {
		s = regexp.MustCompile(` loc\([^)]*\)`).ReplaceAllString(s, "")
		s = regexp.MustCompile(`%[a-z]+\d*`).ReplaceAllString(s, "%_")
		s = regexp.MustCompile(`@\w+`).ReplaceAllString(s, "@_")
		var out []string
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "//") {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n")
	}
	ours, _ := os.ReadFile(filepath.Join(repoRoot(t), "examples", "xdpcount", "xdpcount.mlir"))
	mojo, err := os.ReadFile(filepath.Join("testdata", "mojo_xdpcount.mlir"))
	if err != nil {
		t.Fatal(err)
	}
	if norm(string(ours)) != norm(string(mojo)) {
		t.Fatalf("op sequence differs from mojo-bpf-mlir's xdpcount\n--- ours\n%s\n--- mojo\n%s", norm(string(ours)), norm(string(mojo)))
	}
}

// TestCodesNamed checks that every reason code has a name.
func TestCodesNamed(t *testing.T) {
	t.Parallel()
	var codes []string
	for c := range codeNames {
		codes = append(codes, string(c))
	}
	sort.Strings(codes)
	if len(codes) != 36 { // SB030 (loops), SB031 (array indices), SB032 (uprobe targets), SB033 (kernel types), SB034 and SB035 (subprograms)
		t.Fatalf("codes: %v", codes)
	}
}

// TestComparatorDependentRule covers a review finding: the comparator's rule "a difference in a node that contains a read of the
// root's argument is allowed" was added after seeing the first run's results (post hoc). For a program that reads ctx
// (testdata/neg/ctx_use.rb) it records the list of mismatches the comparator reports without the rule (the differences the rule
// allows), and checks that with the rule there are 0, and that the rule is not too wide (a difference in a node that contains no
// ctx read is still SB010).
func TestComparatorDependentRule(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	src := filepath.Join("testdata", "neg", "ctx_use.rb")
	text, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	res, err := analyze(sp, work, src, string(text), analyzeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Diags {
		if d.Code == SB010TypingProbe {
			t.Fatalf("with the rule, the comparator still reports %s", d)
		}
	}
	// compare the same two analyses (the types.json of work's plain run and of typing) without the rule
	load := func(sub string) *Types {
		data, err := os.ReadFile(filepath.Join(work, sub, "types.json"))
		if err != nil {
			t.Fatal(err)
		}
		ty, err := ParseTypes(data)
		if err != nil {
			t.Fatal(err)
		}
		return ty
	}
	lines := strings.Count(strings.TrimSuffix(string(text), "\n"), "\n") + 1
	without := CompareTypes(load("plain"), load("typing"), "ctx_use.rb", lines, map[string]bool{"prog": true}, nil)
	var got []string
	for _, d := range without {
		got = append(got, fmt.Sprintf("%d:%d %s", d.Pos.Line, d.Pos.Col, d.Msg))
	}
	t.Logf("comparator without the dependent rule: %d mismatches\n%s", len(without), strings.Join(got, "\n"))
	if len(without) == 0 {
		t.Fatal("the rule is not needed for ctx_use.rb — the recorded comparison says it was")
	}
	// negative control: even in a program that reads ctx, a difference in a node with no ctx read stops with SB010. Since duplicate
	// diagnostics are dropped, a program that already stops for another reason (ctx_use.rb's SB001) loses its SB010, so this changes the
	// type of a node outside the flow in pkt_ether, which has no other reason to stop (the IntegerNode 4 at 11:12 — `slot = 4`)
	src2 := filepath.Join("testdata", "pos", "pkt_ether.rb")
	text2, _ := os.ReadFile(src2)
	res2, err := analyze(sp, t.TempDir(), src2, string(text2), analyzeOpts{mutateTyping: func(ty *Types) {
		for i, r := range ty.Types {
			if r.File == "pkt_ether.rb" && r.Kind == "IntegerNode" && r.Line == 11 && r.Col == 11 {
				ty.Types[i].RBS = "Float"
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res2.Diags, SB010TypingProbe, "11:12") {
		t.Fatalf("the dependent rule is too wide: a difference outside the ctx reads passed\n%v", (&Error{Diags: res2.Diags}).Error())
	}
}

// TestUnusedMapConditional tests a rule added after a first run: a map that is declared but never used is a Conditional SB013 and
// does not appear in the schema or maps.json.
func TestUnusedMapConditional(t *testing.T) {
	t.Parallel()
	out, err := Generate(testSpinel(t), t.TempDir(), filepath.Join("testdata", "pos", "unused_map.rb"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(out.Result.Diags, SB013MapDeclShape, "4:1") {
		t.Fatalf("want a Conditional SB013 at 4:1, got %v", out.Result.Diags)
	}
	if bytes.Contains(out.Schema, []byte("Spare")) || bytes.Contains(out.Maps, []byte("Spare")) {
		t.Fatal("the unused map Spare is in the schema or maps.json")
	}
}

// TestComparatorAdditiveRule tests a rule added post hoc: a difference in a node that contains a value flowing from the root's
// argument is allowed only when the side without injection has no type (no record, or untyped). In pkt_ether, changing the typing
// type of a node in the flow that also has a type on the side without injection (the IfNode of `if w` — Integer) stops with SB010.
// Without the rule, the differences of the flow's nodes are listed as mismatches.
func TestComparatorAdditiveRule(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	src := filepath.Join("testdata", "pos", "pkt_ether.rb")
	text, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	res, err := analyze(sp, work, src, string(text), analyzeOpts{})
	if err != nil || res.Diags.Blocking() {
		t.Fatalf("pkt_ether: %v %v", err, res.Diags)
	}
	load := func(sub string) *Types {
		data, err := os.ReadFile(filepath.Join(work, sub, "types.json"))
		if err != nil {
			t.Fatal(err)
		}
		ty, err := ParseTypes(data)
		if err != nil {
			t.Fatal(err)
		}
		return ty
	}
	lines := strings.Count(strings.TrimSuffix(string(text), "\n"), "\n") + 1
	without := CompareTypes(load("plain"), load("typing"), "pkt_ether.rb", lines, map[string]bool{"ether": true}, nil)
	t.Logf("comparator without the dependent rule: %d mismatches", len(without))
	if len(without) == 0 {
		t.Fatal("the dependent rule is not needed for pkt_ether.rb")
	}
	res2, err := analyze(sp, t.TempDir(), src, string(text), analyzeOpts{mutateTyping: func(ty *Types) {
		for i, r := range ty.Types {
			if r.File == "pkt_ether.rb" && r.Kind == "IfNode" && r.Line == 9 && r.Col == 2 {
				ty.Types[i].RBS = "Float"
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res2.Diags, SB010TypingProbe, "9:3") {
		t.Fatalf("the additive rule is too wide: a typed node in the flow changed type and passed\n%v", (&Error{Diags: res2.Diags}).Error())
	}
}

// TestNoUncheckedPacketLoad checks that an unchecked ebpf.packet.load is not an allowed op (it reads an implicit 0 out of range).
func TestNoUncheckedPacketLoad(t *testing.T) {
	t.Parallel()
	for _, op := range AllowedOps() {
		if op == "ebpf.packet.load" || op == "ebpf.packet.store" {
			t.Fatalf("%s is in the allowed ops", op)
		}
	}
	if err := VerifyWorld("  %v0 = ebpf.packet.load %ctx[%v1] : !ebpf.ctx<\"xdp\">, i64 -> i8\n"); err == nil {
		t.Fatal("VerifyWorld accepted ebpf.packet.load")
	}
}

// TestPacketReproducible checks that the .mlir and schema of the packet positive examples are byte-identical across two generations.
func TestPacketReproducible(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	files, _ := filepath.Glob(filepath.Join("testdata", "pos", "pkt_*.rb"))
	if len(files) < 4 {
		t.Fatalf("want the packet positives, got %v", files)
	}
	for _, f := range files {
		a, err := Generate(sp, t.TempDir(), f)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Generate(sp, t.TempDir(), f)
		if err != nil {
			t.Fatal(err)
		}
		if a.MLIR != b.MLIR || !bytes.Equal(a.Schema, b.Schema) {
			t.Errorf("%s: two generations differ", f)
		}
	}
}

// TestUntypedSpellingCanary covers a review finding: the comparator's additive condition depends on how Spinel spells "no type"
// (RBS "untyped" and an empty signature — untypedOnly). On a known input (pkt_ether) it pins that the nodes in the flow on the side
// without injection (the LocalVariableWriteNode of `w = ctx.check(0, 14)` and the read in `if w`) use that spelling.
// If a Spinel upgrade changes the spelling, this test fails by name (before the allowance silently disappears, or another spelling
// is compared as a type).
func TestUntypedSpellingCanary(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	src := filepath.Join("testdata", "pos", "pkt_ether.rb")
	text, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if _, err := analyze(sp, work, src, string(text), analyzeOpts{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(work, "plain", "types.json"))
	if err != nil {
		t.Fatal(err)
	}
	ty, err := ParseTypes(data)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, r := range ty.Types {
		if r.File == "pkt_ether.rb" && r.Line == 8 && r.Col == 2 && r.Kind == "LocalVariableWriteNode" {
			seen["write"] = r.Name + "|" + r.RBS + "|" + r.Signature
		}
		if r.File == "pkt_ether.rb" && r.Line == 9 && r.Col == 5 && r.Kind == "LocalVariableReadNode" {
			seen["read"] = r.Name + "|" + r.RBS + "|" + r.Signature
		}
	}
	for _, k := range []string{"write", "read"} {
		if seen[k] != "w|untyped|" || !untypedOnly([]string{seen[k]}) {
			t.Fatalf("Spinel's spelling of \"no type\" changed: the %s of `w` in pkt_ether.rb without the typing probe is %q, want \"w|untyped|\" — update untypedOnly (the comparator's additive rule) for this Spinel version", k, seen[k])
		}
	}
}

// TestRecordComparator: in rec_pkt, which has two record types and where the key and value flow from ctx, the comparator without the
// rule reports mismatches and with the rule reports 0; changing the typing type of a node in the flow that also has a type on the side
// without injection (the IfNode of `if p` — p is the lookup of a key flowing from ctx) gives SB010 — the additive rule does not
// silently widen types along the flow of p.load.
// (The first version used rec_basic — a program that does not read ctx has 0 mismatches with or without injection (injection does not
// change the types along a record's flow) — and was kept as TestRecordComparatorNoCtx.)
func TestRecordComparator(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	src := filepath.Join("testdata", "pos", "rec_pkt.rb")
	text, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	res, err := analyze(sp, work, src, string(text), analyzeOpts{})
	if err != nil || res.Diags.Blocking() {
		t.Fatalf("rec_basic: %v %v", err, res.Diags)
	}
	load := func(sub string) *Types {
		data, err := os.ReadFile(filepath.Join(work, sub, "types.json"))
		if err != nil {
			t.Fatal(err)
		}
		ty, err := ParseTypes(data)
		if err != nil {
			t.Fatal(err)
		}
		return ty
	}
	lines := strings.Count(strings.TrimSuffix(string(text), "\n"), "\n") + 1
	without := CompareTypes(load("plain"), load("typing"), "rec_pkt.rb", lines, map[string]bool{"prog": true}, nil)
	t.Logf("comparator without the dependent rule: %d mismatches", len(without))
	for _, d := range without {
		t.Logf("  %s", d)
	}
	if len(without) == 0 {
		t.Fatal("the dependent rule is not needed for rec_pkt.rb")
	}
	res2, err := analyze(sp, t.TempDir(), src, string(text), analyzeOpts{mutateTyping: func(ty *Types) {
		for i, r := range ty.Types {
			if r.File == "rec_pkt.rb" && r.Kind == "IfNode" && r.Line == 16 && r.Col == 4 {
				ty.Types[i].RBS = "Float"
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(res2.Diags, SB010TypingProbe, "16:5") {
		t.Fatalf("the additive rule let a typed node in the p.load flow change type\n%v", (&Error{Diags: res2.Diags}).Error())
	}
}

// TestRecordReproducible checks that the .mlir, schema and maps.json of the record positive examples are byte-identical across two
// generations, and that the schema has records and record_ref.
func TestRecordReproducible(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	files, _ := filepath.Glob(filepath.Join("testdata", "pos", "rec_*.rb"))
	if len(files) == 0 {
		t.Fatal("no record positives")
	}
	files = append(files, filepath.Join("testdata", "pos", "ring_basic.rb"))   // a ring buffer's record (records holds the ringbuf row's record)
	files = append(files, filepath.Join("testdata", "pos", "hash_basic.rb"))   // a hash map's record key and value (records lists the key record first)
	files = append(files, filepath.Join("testdata", "pos", "percpu_basic.rb")) // per-CPU maps
	for _, f := range files {
		a, err := Generate(sp, t.TempDir(), f)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Generate(sp, t.TempDir(), f)
		if err != nil {
			t.Fatal(err)
		}
		if a.MLIR != b.MLIR || !bytes.Equal(a.Schema, b.Schema) || !bytes.Equal(a.Maps, b.Maps) {
			t.Errorf("%s: two generations differ", f)
		}
		if !(bytes.Contains(a.Schema, []byte(`"kind": "record_ref"`)) || bytes.Contains(a.Schema, []byte(`"kind": "ringbuf"`))) || !bytes.Contains(a.Maps, []byte(`"records"`)) || !bytes.Contains(a.Maps, []byte(`"value": "record:`)) {
			t.Errorf("%s: schema / maps.json lack the record parts", f)
		}
	}
}

// TestRecordComparatorNoCtx keeps a first-run observation: a record program that does not read ctx (rec_basic) has 0 comparator
// mismatches with or without injection — injection does not change the types along a record's flow.
func TestRecordComparatorNoCtx(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	src := filepath.Join("testdata", "pos", "rec_basic.rb")
	text, _ := os.ReadFile(src)
	work := t.TempDir()
	if _, err := analyze(sp, work, src, string(text), analyzeOpts{}); err != nil {
		t.Fatal(err)
	}
	load := func(sub string) *Types {
		data, _ := os.ReadFile(filepath.Join(work, sub, "types.json"))
		ty, err := ParseTypes(data)
		if err != nil {
			t.Fatal(err)
		}
		return ty
	}
	lines := strings.Count(strings.TrimSuffix(string(text), "\n"), "\n") + 1
	if d := CompareTypes(load("plain"), load("typing"), "rec_basic.rb", lines, map[string]bool{"prog": true}, nil); len(d) != 0 {
		t.Fatalf("want no mismatches without ctx reads, got %v", d)
	}
}

// TestLibraryKeepsEBPFTypes (a gate added from a review finding): adding a user-space side that calls the spinelbpf library's public
// API does not change Spinel's inferred types inside the eBPF program's defs (the records of typing's types.json — position, kind,
// name, type), both for a program that uses records and for one that does not.
// It catches, at the entry, the forms where a polymorphic API or generated splat breaks the eBPF side's types through whole-program
// inference (earlier, such forms made Spinel emit invalid C: a splat `class.new(*vals)` on a receiver of undetermined type, and
// member calls for types that never arrive through a polymorphic argument).
func TestLibraryKeepsEBPFTypes(t *testing.T) {
	t.Parallel()
	sp := testSpinel(t)
	cases := []struct {
		name, user string
		poison     bool // control: a form that breaks the types — a change is expected
	}{
		{"rec_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
v = obj.map_get_record(Stats, 0)
s = Stat.new(v[0], v[1], v[2], v[3], v[4])
obj.map_put_record(Stats, 1, s)
w = obj.map_get_record(Pairs, 1)
obj.map_put_record(Pairs, 0, Pair.new(w[0], w[1]))
x = obj.map_get(Out, 0)
obj.map_put(Out, 1, x)
obj.test_run_xdp("prog", 1)
obj.test_run_xdp_packet("prog", Array.new(14, 0))
puts obj.unmet.length
obj.close
`, false},
		{"lpm_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
obj.lpm_put(Rules, "10.0.0.0/8", 1)
puts obj.lpm_remove(Rules, "10.0.0.0/8")
puts obj.lpm_match(Rules, "10.1.2.3")
puts obj.lpm_has(Signed, "10.0.0.1")
l = obj.lpm_list(Rules)
puts l.length
puts SpinelBPF.lpm_prefix_len("10.0.0.0/8")
x = obj.map_get(Out, 0)
obj.map_put(Out, 1, x)
obj.test_run_xdp_packet("ipdeny", Array.new(64, 0))
puts obj.unmet.length
obj.close
`, false},
		{"sf_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
obj.attach_socket("short_only", 3)
puts obj.test_run_skb_packet("short_only", Array.new(78, 0))
puts obj.map_get(Out, 0)
puts obj.unmet.length
obj.close
`, false},
		{"cgs_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
l = obj.attach_cgroup("small_in", 3)
l.detach
puts obj.test_run_skb_packet("small_out", Array.new(78, 0))
puts obj.map_get(Out, 1)
puts obj.unmet.length
obj.close
`, false},
		{"nf_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
puts obj.test_run_netfilter("small_only", Array.new(40, 0), 2, 3)
puts obj.map_get(Out, 2)
puts obj.unmet.length
obj.close
`, false},
		{"ctxf_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
puts obj.test_run_xdp_packet("ifx", Array.new(64, 0))
puts obj.test_run_tc_packet("mark_in", Array.new(64, 0))
puts obj.map_get(Out, 3)
obj.close
`, false},
		{"adjh_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
obj.map_put(D, 0, 4)
puts obj.test_run_xdp_packet("shift", Array.new(64, 0))
puts obj.map_get(Out, 0)
obj.close
`, false},
		{"adjt_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
puts obj.test_run_xdp_packet("trim4", Array.new(64, 0))
puts obj.map_get(Out, 0)
obj.close
`, false},
		{"flow_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
r = obj.test_run_flow_dissector("flow4", Array.new(64, 0))
puts r[0]
puts r.length
l = obj.attach_netns("flow4", 3)
l.detach
obj.close
`, false},
		{"ops_int", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
x = obj.map_get(In, 0)
obj.map_put(In, 1, x)
obj.test_run_xdp("prog", 1)
obj.test_run_xdp_packet("prog", Array.new(14, 0))
puts obj.unmet.length
obj.close
`, false},
		{"ring_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
x = obj.map_get(Drops, 0)
obj.map_put(Drops, 1, x)
obj.test_run_xdp_packet("prog", Array.new(64, 0))
r = obj.ringbuf(Events)
e = r.read_record(0)
if e.length > 0
  ev = Event.new(e[0], e[1], e[2], e[3], e[4], e[5])
  puts ev.len
end
k = obj.ringbuf(Ticks)
u = k.read_record(10)
puts u.length
k.close
r.close
puts obj.unmet.length
obj.close
`, false},
		{"hash_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
x = obj.map_get(Out, 0)
obj.map_put(Out, 1, x)
obj.hash_put(Counts, 7, x)
y = obj.hash_get(Counts, 7)
puts obj.hash_has(Counts, 8)
puts obj.hash_delete(Counts, 8)
puts obj.hash_keys(Counts).length
obj.hash_put(Seen, -1, 2)
puts obj.hash_get(Seen, -1)
v = obj.hash_get_record(ByPort, 443)
obj.hash_put_record(ByPort, 443, Stat.new(v[0], v[1]))
k = obj.hash_keys_rk(Flows)
if k.length > 0
  fk = FlowKey.new(k[0][0], k[0][1], k[0][2], k[0][3])
  w = obj.hash_get_record_rk(Flows, fk)
  obj.hash_put_record_rk(Flows, fk, Stat.new(w[0], w[1]))
  puts obj.hash_has_rk(Flows, fk)
  puts obj.hash_delete_rk(Flows, fk)
end
puts y
obj.test_run_xdp("prog", 1)
puts obj.unmet.length
obj.close
`, false},
		{"percpu_basic", `
require "spinelbpf"
obj = SpinelBPF.load_embedded
n = SpinelBPF.possible_cpus
a = obj.percpu_get_record(PerProto, 3)
recs = []
i = 0
while i < a.length
  recs.push(Stats.new(a[i][0], a[i][1], a[i][2], a[i][3]))
  i += 1
end
obj.percpu_put_record(PerProto, 3, recs)
h = obj.percpu_get(Hits, 0)
obj.percpu_put(Hits, 0, h)
puts SpinelBPF.sum(h)
f = obj.percpu_hash_get_rk(PerFlow, FlowKey.new(17, 0, 53, 16909060))
obj.percpu_hash_put_rk(PerFlow, FlowKey.new(17, 0, 53, 16909060), f)
k = obj.percpu_hash_keys_rk(PerFlow)
puts k.length
puts obj.percpu_hash_has_rk(PerFlow, FlowKey.new(1, 0, 1, 1))
puts obj.percpu_hash_delete_rk(PerFlow, FlowKey.new(1, 0, 1, 1))
g = obj.percpu_hash_get_record(PerPort, 53)
obj.percpu_hash_put_record(PerPort, 53, [Stats.new(g[0][0], g[0][1], g[0][2], g[0][3])])
puts obj.percpu_hash_keys(PerPort).length
puts obj.percpu_hash_has(PerPort, 1)
puts obj.percpu_hash_delete(PerPort, 1)
puts n
obj.test_run_xdp("prog", 1)
obj.close
`, false},
		// control (the form of the first attempt): building a record's Struct from a polymorphic return value (Array or Integer) changes
		// the eBPF side's types — this test catches it
		{"rec_basic", `
def either(k)
  if k > 0
    return [1, 2, 3, 0, 5]
  end
  7
end
v = either(1)
s = Stat.new(v[0], v[1], v[2], v[3], v[4])
puts s.hits
`, true},
	}
	for _, c := range cases {
		src := filepath.Join("testdata", "pos", c.name+".rb")
		text, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		types := func(body string) (map[string]string, *Result) {
			d := t.TempDir()
			p := filepath.Join(d, c.name+".rb")
			os.WriteFile(p, []byte(body), 0o644)
			work := t.TempDir()
			res, err := analyze(sp, work, p, body, analyzeOpts{})
			if err != nil || (res.Diags.Blocking() && !c.poison) {
				t.Fatalf("%s: %v %v", c.name, err, res.Diags)
			}
			data, err := os.ReadFile(filepath.Join(work, "typing", "types.json"))
			if err != nil {
				t.Fatal(err)
			}
			ty, err := ParseTypes(data)
			if err != nil {
				t.Fatal(err)
			}
			out := map[string]string{}
			for _, r := range ty.Types {
				for _, pr := range res.Programs {
					if r.File == c.name+".rb" && r.Line >= pr.Pos.Line && r.EndLine <= pr.EndLine {
						out[fmt.Sprintf("%d:%d:%d:%d:%s", r.Line, r.Col, r.EndLine, r.EndCol, r.Kind)] += r.Name + "|" + r.RBS + ";"
					}
				}
			}
			return out, res
		}
		plain, _ := types(string(text))
		with, _ := types(string(text) + c.user)
		if len(plain) == 0 {
			t.Fatalf("%s: no typed nodes in the eBPF program", c.name)
		}
		diff := 0
		for k, v := range plain {
			if with[k] != v {
				diff++
				if c.poison {
					continue
				}
				t.Errorf("%s: the eBPF-side type at %s changed with the user-space side: %q → %q", c.name, k, v, with[k])
			}
		}
		if c.poison {
			if diff == 0 {
				t.Errorf("%s (control): the poisoning user code changed no eBPF-side type — the test would not catch it", c.name)
			}
			t.Logf("%s (control — polymorphic value into Stat.new): %d of %d eBPF-side typed nodes changed", c.name, diff, len(plain))
			continue
		}
		t.Logf("%s: %d eBPF-side typed nodes, %d changed", c.name, len(plain), diff)
	}
}
