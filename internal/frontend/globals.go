package frontend

import (
	"fmt"
	"math/big"
	"strings"
)

type GlobalDecl struct {
	Const    string
	Name     string
	Class    string
	Section  string
	Bits     int
	Signed   bool
	Optional bool
	Pos      Pos
}

func (g *GlobalDecl) Counter() bool { return g.Class == "Counter" }

func (g *GlobalDecl) TypeName() string {
	if g.Signed {
		return fmt.Sprintf("i%d", g.Bits)
	}
	return fmt.Sprintf("u%d", g.Bits)
}

var globalClasses = map[string]string{"BPF::Config": "Config", "BPF::OptionalConfig": "OptionalConfig", "BPF::Counter": "Counter"}

func (z *analyzer) globalDecl(a *AST, n *Node) bool {
	v := a.ref(n, "value")
	if v == nil || v.Type != "CallNode" || v.Str["name"] != "new" {
		return false
	}
	class, ok := globalClasses[constName(a, a.ref(v, "receiver"))]
	if !ok {
		return false
	}
	c := n.Str["name"]
	p := z.pos(a, n)
	z.badGlobals[c] = true
	if _, dup := z.globals[c]; dup {
		z.add(Rejected, SB029GlobalShape, p, "constant %s is assigned twice", c)
		return true
	}
	as := args(a, v)
	if len(as) != 2 || as[0].Type != "StringNode" || as[1].Type != "SymbolNode" {
		z.add(Rejected, SB029GlobalShape, p, "a global is declared as `%s = BPF::%s.new(\"%s\", :u16)` with a String and a Symbol literal", c, class, c)
		return true
	}
	name := as[0].Str["content"]
	if name != c {
		z.add(Rejected, SB029GlobalShape, z.pos(a, as[0]), "the global name %q differs from its constant %s — both sides look the global up by this name", name, c)
		return true
	}
	t := as[1].Str["value"]
	rt, ok := recordTypes[t]
	if !ok {
		z.add(Rejected, SB029GlobalShape, z.pos(a, as[1]), "the global's type must be one of :u8 … :u64 / :i8 … :i64, got :%s", t)
		return true
	}
	if class == "Counter" && rt[0] != 32 && rt[0] != 64 {
		z.add(Rejected, SB029GlobalShape, z.pos(a, as[1]), "a Counter is :u32, :u64, :i32 or :i64 (the widths of ebpf.global.atomic_add), got :%s", t)
		return true
	}
	if reservedPrefix.MatchString(name) {
		z.add(Rejected, SB007ReservedName, p, "global name %q uses the reserved prefix spinelbpf_", name)
		return true
	}
	delete(z.badGlobals, c)
	g := &GlobalDecl{Const: c, Name: name, Class: class, Section: "rodata", Bits: rt[0], Signed: rt[1] == 1, Optional: class == "OptionalConfig", Pos: p}
	if class == "Counter" {
		g.Section = "bss"
	}
	z.globals[c] = g
	z.globalOrder = append(z.globalOrder, g)
	return true
}

func (z *analyzer) checkGlobalNames(roots []rootDecl) {
	taken := map[string]string{}
	for _, m := range z.mapOrder {
		taken[m.Name] = "map"
	}
	for _, r := range z.ringOrder {
		taken[r.Name] = "ring buffer"
	}
	for _, r := range roots {
		taken[r.Name] = "program"
	}
	for _, g := range z.globalOrder {
		if what, ok := taken[g.Name]; ok {
			z.add(Rejected, SB029GlobalShape, g.Pos, "global %s has the same name as a %s — globals, maps and programs share the ELF symbol names", g.Name, what)
		}
	}
}

var globalValueCallees = map[string]string{"Config": "Config#value", "OptionalConfig": "OptionalConfig#value", "Counter": "Counter#value"}

func (c *progCtx) globalRead(n *Node, g *GlobalDecl, name string, as []*Node, p Pos) *Expr {
	if name == "add" {
		if !g.Counter() {
			c.add(Rejected, SB029GlobalShape, n, "%s is a %s (.rodata — set at load) and has no `add` — only a Counter (.bss) adds", g.Const, g.Class)
		} else {
			c.add(Rejected, SB029GlobalShape, n, "`%s.add(d)` is a statement, not a value (ebpf.global.atomic_add returns nothing)", g.Const)
		}
		return nil
	}
	if name != "value" || len(as) != 0 {
		c.add(Rejected, SB029GlobalShape, n, "a global is read as `%s.value` (and a Counter adds with `%s.add(d)`), not `%s`", g.Const, g.Const, name)
		return nil
	}
	callee, ok := c.callee(n)
	if !ok {
		return nil
	}
	if callee != globalValueCallees[g.Class] {
		c.add(Rejected, SB011ShadowedName, n, "`%s.value` resolves to %q, not BPF::%s", g.Const, callee, globalValueCallees[g.Class])
		return nil
	}
	c.usedGlobals[g] = true
	e := &Expr{Kind: "gload", Glob: g, Pos: p}
	if g.Bits == 64 && !g.Signed {
		e.Iv, e.Wide = iv(new(big.Int), new(big.Int).Set(u64Max)), true
	} else {
		e.Iv = widthRange(g.Bits, g.Signed)
	}
	return e
}

func (c *progCtx) globalAdd(n *Node, g *GlobalDecl, as []*Node, refVar string) (Stmt, bool) {
	if !g.Counter() {
		c.add(Rejected, SB029GlobalShape, n, "%s is a %s (.rodata — set at load) and has no `add` — only a Counter (.bss) adds", g.Const, g.Class)
		return Stmt{}, false
	}
	if len(as) != 1 {
		c.add(Rejected, SB029GlobalShape, n, "`%s.add(d)` takes one Integer", g.Const)
		return Stmt{}, false
	}
	callee, ok := c.callee(n)
	if !ok {
		return Stmt{}, false
	}
	if callee != "Counter#add" {
		c.add(Rejected, SB011ShadowedName, n, "`%s.add` resolves to %q, not BPF::Counter#add", g.Const, callee)
		return Stmt{}, false
	}
	c.noteFlowKey(as[0], "g:"+g.Const, n)
	if c.derivedRefs(as[0])["@g"+g.Const] {
		c.add(Rejected, SB019SharedReadModifyWrite, n, "`%s.add` adds a value read from %s itself (`%s.value`) — concurrent CPUs read the same old value and lose updates; use a delta that does not read %s", g.Const, g.Const, g.Const, g.Const)
		return Stmt{}, false
	}
	e := c.expr(as[0], refVar)
	if e == nil {
		return Stmt{}, false
	}
	if e.Bool {
		c.add(Rejected, SB001UnsupportedConstruct, as[0], "`%s.add` takes an Integer, not a boolean", g.Const)
		return Stmt{}, false
	}
	if e.Wide && !(g.Bits == 64 && !g.Signed) {
		c.add(Rejected, SB014SemanticGap, as[0], "a u64 value does not fit Ruby's Integer — add it only to a :u64 Counter, or narrow it first (`x & M` or `x >> K`)")
		return Stmt{}, false
	}
	c.usedGlobals[g] = true
	return Stmt{Kind: "gadd", Glob: g, Val: e, Pos: c.z.pos(c.a, n)}, true
}

func usedGlobalsOf(order []*GlobalDecl, progs []*Program) []*GlobalDecl {
	used := map[*GlobalDecl]bool{}
	for _, p := range progs {
		for _, g := range p.Globals {
			used[g] = true
		}
	}
	var out []*GlobalDecl
	for _, g := range order {
		if used[g] {
			out = append(out, g)
		}
	}
	return out
}

func globalRows(gs []*GlobalDecl) string {
	var b strings.Builder
	for _, g := range gs {
		opt := 0
		if g.Optional {
			opt = 1
		}
		fmt.Fprintf(&b, "G|%s|%s|%s|%d\n", g.Name, g.Section, g.TypeName(), opt)
	}
	return b.String()
}

func widthRange(bits int, signed bool) Ival {
	if bits >= 64 {
		if signed {
			return fullI64
		}
		return iv(new(big.Int), new(big.Int).Set(i64Max))
	}
	if !signed {
		return iv(new(big.Int), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1)))
	}
	h := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return iv(new(big.Int).Neg(h), new(big.Int).Sub(h, big.NewInt(1)))
}

func (c *progCtx) counterRead(n *Node) *GlobalDecl {
	if n == nil || n.Type != "CallNode" || n.Str["name"] != "value" {
		return nil
	}
	r := c.a.ref(n, "receiver")
	if r == nil || r.Type != "ConstantReadNode" {
		return nil
	}
	if g := c.z.globals[r.Str["name"]]; g != nil && g.Counter() {
		return g
	}
	return nil
}
