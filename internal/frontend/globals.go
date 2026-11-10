package frontend

import (
	"fmt"
	"math/big"
	"strings"
)

// Global variables: settings in .rodata (BPF::Config — a value is required at load; BPF::OptionalConfig — 0 when not given) and
// counters in .bss (BPF::Counter — ebpf.global.atomic_add; :u32 / :u64 / :i32 / :i64). bpf-mlir's only ops are ebpf.global.load
// and ebpf.global.atomic_add (there is no store).

// GlobalDecl is a global's declaration.
type GlobalDecl struct {
	Const    string
	Name     string
	Class    string // "Config" / "OptionalConfig" / "Counter"
	Section  string // "rodata" / "bss"
	Bits     int
	Signed   bool
	Optional bool
	Pos      Pos
}

// Counter reports whether g is a counter in .bss.
func (g *GlobalDecl) Counter() bool { return g.Class == "Counter" }

// TypeName returns a name such as :u16 (u / i and the width).
func (g *GlobalDecl) TypeName() string {
	if g.Signed {
		return fmt.Sprintf("i%d", g.Bits)
	}
	return fmt.Sprintf("u%d", g.Bits)
}

// globalClasses maps a declaration's receiver to the class name.
var globalClasses = map[string]string{"BPF::Config": "Config", "BPF::OptionalConfig": "OptionalConfig", "BPF::Counter": "Counter", "BPF::Global": "Global", "BPF::ExitInfo": "ExitInfo"}

// globalDecl reads `X = BPF::Config.new("X", :u16)` and the like (a wrong shape is SB029). If n is not such a declaration it returns
// false (it goes on to the other declarations, such as maps).
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
	if class == "ExitInfo" { // the .data user_exit_info record (no type argument)
		if len(as) != 1 || as[0].Type != "StringNode" {
			z.add(Rejected, SB029GlobalShape, p, "an exit info is declared as `%s = BPF::ExitInfo.new(\"%s\")` with a String literal", c, c)
			return true
		}
		if name := as[0].Str["content"]; name != c {
			z.add(Rejected, SB029GlobalShape, z.pos(a, as[0]), "the global name %q differs from its constant %s — both sides look the global up by this name", name, c)
			return true
		}
		if reservedPrefix.MatchString(c) {
			z.add(Rejected, SB007ReservedName, p, "global name %q uses the reserved prefix spinelbpf_", c)
			return true
		}
		delete(z.badGlobals, c)
		g := &GlobalDecl{Const: c, Name: c, Class: class, Section: "data", Pos: p}
		z.globals[c] = g
		z.globalOrder = append(z.globalOrder, g)
		return true
	}
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
	if class == "Counter" || class == "Global" {
		g.Section = "bss"
	}
	z.globals[c] = g
	z.globalOrder = append(z.globalOrder, g)
	return true
}

// checkGlobalNames checks that no global's name collides with a map, ring buffer or program name (they share the ELF symbol
// namespace — a rule of bpf-mlir's schema).
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

// globalValueCallees are the library callees of `X.value` (per class).
var globalValueCallees = map[string]string{"Config": "Config#value", "OptionalConfig": "OptionalConfig#value", "Counter": "Counter#value", "Global": "Global#value"}

// globalRead handles `X.value` (an expression). Any other method is SB029.
func (c *progCtx) globalRead(n *Node, g *GlobalDecl, name string, as []*Node, p Pos) *Expr {
	if g.Class == "ExitInfo" { // the .data user_exit_info record
		c.add(Rejected, SB029GlobalShape, n, "%s is a BPF::ExitInfo (the .data exit record) — it has no method on the eBPF side; only `BPF::Scx.exit_info(%s, %s)` writes it", g.Const, c.param, g.Const)
		return nil
	}
	if g.Class == "Global" && (name == "set" || name == "store") {
		c.globalSetRefused(n, g, name)
		return nil
	}
	if g.Class == "Global" && name != "value" {
		c.add(Rejected, SB029GlobalShape, n, "%s is a Global (.bss) — it is read with `%s.value` and written with `%s.set(v)`; it has no `%s`", g.Const, g.Const, g.Const, name)
		return nil
	}
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

// globalAdd handles the statement `C.add(d)` (Counter only — a 32-bit counter adds the low 32 bits of the delta: u32 and i32 have
// the same bits).
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
	// the delta reads the same Counter's value (directly or through a local) — the same kind as a map atomic_add whose delta reads the
	// same entry. The form that crosses functions is handled by the summaries
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

// usedGlobalsOf returns the globals the programs use (in declaration order).
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

// globalRows returns the G rows of the embedded table (`G|name|section|type|opt` — opt is 1 / 0; the library builds the config's
// optional column from it).
func globalRows(gs []*GlobalDecl) string {
	var b strings.Builder
	for _, g := range gs {
		if g.Class == "ExitInfo" { // a .data record has no G row (the user side reads rodata and bss)
			continue
		}
		opt := 0
		if g.Optional {
			opt = 1
		}
		fmt.Fprintf(&b, "G|%s|%s|%s|%d\n", g.Name, g.Section, g.TypeName(), opt)
	}
	return b.String()
}

// widthRange is the interval of an integer of width bits (8, 16, 32, 64): u is [0, 2^bits − 1], i is [−2^(bits−1), 2^(bits−1) − 1]
// (the caller handles u64 with Wide). typeRange (only the map value widths 32 / 64) gave 8- and 16-bit types the 64-bit interval,
// which was too wide (on the safe side, but it caused false SB014s).
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

// counterRead returns the Counter if n reads a Counter's `G.value` (the origin mark is `@g<Const>`).
func (c *progCtx) counterRead(n *Node) *GlobalDecl {
	if n == nil || n.Type != "CallNode" || n.Str["name"] != "value" {
		return nil
	}
	r := c.a.ref(n, "receiver")
	if r == nil || r.Type != "ConstantReadNode" {
		return nil
	}
	if g := c.z.globals[r.Str["name"]]; g != nil && (g.Counter() || g.Class == "Global") { // a Global's value carries the same mark (SB019 for `G.set(G.value)`)
		return g
	}
	return nil
}

// globalSetRefused stops a Global's write used as a value, and the old name `store` (Spinel types x.store as Hash#store),
// both before any callee lookup.
func (c *progCtx) globalSetRefused(n *Node, g *GlobalDecl, name string) {
	if name == "store" {
		c.add(Rejected, SB029GlobalShape, n, "`%s.store` is not a Global's write — write it with `%s.set(v)` (`store` is Hash#store to Spinel)", g.Const, g.Const)
		return
	}
	c.add(Rejected, SB029GlobalShape, n, "`%s.set(v)` is a statement, not a value (ebpf.global.store returns nothing)", g.Const)
}

// globalStmt handles a statement on a Global or an ExitInfo: `G.set(v)` → ebpf.global.store; `G.store` is refused by
// name, and `add` is not a Global's. handled is false for the other classes (Counter#add and the rest stay as they were).
func (c *progCtx) globalStmt(n *Node, g *GlobalDecl, refVar string) (s Stmt, ok, handled bool) {
	name := n.Str["name"]
	switch g.Class {
	case "ExitInfo":
		c.add(Rejected, SB029GlobalShape, n, "%s is a BPF::ExitInfo (the .data exit record) — it has no method on the eBPF side; only `BPF::Scx.exit_info(%s, %s)` writes it", g.Const, c.param, g.Const)
		return Stmt{}, false, true
	case "Global":
	default:
		return Stmt{}, false, false
	}
	switch name {
	case "store":
		c.globalSetRefused(n, g, name)
		return Stmt{}, false, true
	case "set":
	default:
		c.add(Rejected, SB029GlobalShape, n, "%s is a Global (.bss) — it is read with `%s.value` and written with `%s.set(v)`; it has no `%s`", g.Const, g.Const, g.Const, name)
		return Stmt{}, false, true
	}
	as := args(c.a, n)
	if len(as) != 1 {
		c.add(Rejected, SB029GlobalShape, n, "`%s.set(v)` takes one Integer", g.Const)
		return Stmt{}, false, true
	}
	callee, cok := c.callee(n)
	if !cok {
		return Stmt{}, false, true
	}
	if callee != "Global#set" {
		c.add(Rejected, SB011ShadowedName, n, "`%s.set` resolves to %q, not BPF::Global#set", g.Const, callee)
		return Stmt{}, false, true
	}
	c.noteFlowKey(as[0], "g:"+g.Const, n)
	if c.derivedRefs(as[0])["@g"+g.Const] {
		c.add(Rejected, SB019SharedReadModifyWrite, n, "`%s.set` writes a value read from %s itself (`%s.value`) — concurrent CPUs read the same old value and lose updates; write a value that does not read %s", g.Const, g.Const, g.Const, g.Const)
		return Stmt{}, false, true
	}
	e := c.expr(as[0], refVar)
	if e == nil {
		return Stmt{}, false, true
	}
	r := widthRange(g.Bits, g.Signed)
	switch {
	case e.Bool:
		c.add(Rejected, SB014SemanticGap, as[0], "`%s.set` takes an Integer, not a Bool", g.Const)
		return Stmt{}, false, true
	case e.Wide && !(g.Bits == 64 && !g.Signed):
		c.add(Rejected, SB014SemanticGap, as[0], "a u64 value does not fit %s (:%s) — write it only to a :u64 Global, or narrow it first (`x & M` or `x >> K`)", g.Const, g.TypeName())
		return Stmt{}, false, true
	case !e.Wide && !e.Iv.within(r.Lo, r.Hi):
		c.add(Rejected, SB014SemanticGap, as[0], "the value's range %s does not fit %s (:%s %s) — the store would truncate silently; narrow it (e.g. `& 0x%X`)", e.Iv, g.Const, g.TypeName(), r, r.Hi)
		return Stmt{}, false, true
	}
	c.usedGlobals[g] = true
	return Stmt{Kind: "gset", Glob: g, Val: e, Pos: c.z.pos(c.a, n)}, true, true
}
