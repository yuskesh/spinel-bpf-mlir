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

func TestNegative(t *testing.T) {
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

func TestPositive(t *testing.T) {
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

func TestGoldenExample(t *testing.T) {
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

func TestGenerateTwice(t *testing.T) {
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

func TestInjectionWrongClass(t *testing.T) {
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

func TestInjectionComparator(t *testing.T) {
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

func TestDynamicDispatch(t *testing.T) {
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

func TestAmbiguousType(t *testing.T) {
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

func TestVerifyWorld(t *testing.T) {
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

func TestSameOpsAsMojo(t *testing.T) {
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

func TestCodesNamed(t *testing.T) {
	var codes []string
	for c := range codeNames {
		codes = append(codes, string(c))
	}
	sort.Strings(codes)
	if len(codes) != 36 {
		t.Fatalf("codes: %v", codes)
	}
}

func TestComparatorDependentRule(t *testing.T) {
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

func TestUnusedMapConditional(t *testing.T) {
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

func TestComparatorAdditiveRule(t *testing.T) {
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

func TestNoUncheckedPacketLoad(t *testing.T) {
	for _, op := range AllowedOps() {
		if op == "ebpf.packet.load" || op == "ebpf.packet.store" {
			t.Fatalf("%s is in the allowed ops", op)
		}
	}
	if err := VerifyWorld("  %v0 = ebpf.packet.load %ctx[%v1] : !ebpf.ctx<\"xdp\">, i64 -> i8\n"); err == nil {
		t.Fatal("VerifyWorld accepted ebpf.packet.load")
	}
}

func TestPacketReproducible(t *testing.T) {
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

func TestUntypedSpellingCanary(t *testing.T) {
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

func TestRecordComparator(t *testing.T) {
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

func TestRecordReproducible(t *testing.T) {
	sp := testSpinel(t)
	files, _ := filepath.Glob(filepath.Join("testdata", "pos", "rec_*.rb"))
	if len(files) == 0 {
		t.Fatal("no record positives")
	}
	files = append(files, filepath.Join("testdata", "pos", "ring_basic.rb"))
	files = append(files, filepath.Join("testdata", "pos", "hash_basic.rb"))
	files = append(files, filepath.Join("testdata", "pos", "percpu_basic.rb"))
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

func TestRecordComparatorNoCtx(t *testing.T) {
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

func TestLibraryKeepsEBPFTypes(t *testing.T) {
	sp := testSpinel(t)
	cases := []struct {
		name, user string
		poison     bool
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
