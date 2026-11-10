package frontend

import (
	"fmt"
)

type hashClass struct {
	kind   string
	record bool
	class  string
}

var hashClasses = map[string]hashClass{
	"BPF::HashMap":             {"hash", false, "HashMap"},
	"BPF::LruHashMap":          {"lru_hash", false, "LruHashMap"},
	"BPF::RecordHashMap":       {"hash", true, "RecordHashMap"},
	"BPF::LruRecordHashMap":    {"lru_hash", true, "LruRecordHashMap"},
	"BPF::PerCpuHashMap":       {"percpu_hash", false, "PerCpuHashMap"},
	"BPF::PerCpuRecordHashMap": {"percpu_hash", true, "PerCpuRecordHashMap"},
}

var valueCounterpart = map[string]string{"HashMap": "RecordHashMap", "RecordHashMap": "HashMap", "LruHashMap": "LruRecordHashMap", "LruRecordHashMap": "LruHashMap", "PerCpuHashMap": "PerCpuRecordHashMap", "PerCpuRecordHashMap": "PerCpuHashMap"}

func perCPUExempt(m *MapDecl, kinds []string) bool {
	if m != nil && mutation("percpu-exempt-all") {
		return true
	}
	if m == nil || !m.PerCPU() || len(kinds) == 0 {
		return false
	}
	for _, k := range kinds {
		if k != "xdp" {
			return false
		}
	}
	return true
}

func (c *progCtx) exempt(m *MapDecl) bool { return perCPUExempt(m, c.z.rootKinds) }

var statusOps = map[string]string{"update": "any", "insert": "noexist", "replace": "exist", "delete": "delete", "add_or_init": "add_or_init"}

var errnoConsts = map[string]int64{"BPF::ENOENT": -2, "BPF::E2BIG": -7, "BPF::ENOMEM": -12, "BPF::EEXIST": -17}

var intTypes = map[string][2]int{"u32": {32, 0}, "u64": {64, 0}, "i32": {32, 1}, "i64": {64, 1}}

func (z *analyzer) sampleRecord(a *AST, x *Node) *RecordDecl {
	sc := constName(a, a.ref(x, "receiver"))
	r := z.records[sc]
	if x.Str["name"] != "new" || r == nil {
		z.add(Rejected, SB024RecordShape, z.pos(a, x), "the sample must be `S.new(0, …)` of a record S declared with BPF.record")
		return nil
	}
	sas := args(a, x)
	if len(sas) != len(r.Fields) {
		z.add(Rejected, SB024RecordShape, z.pos(a, x), "the sample must give all %d members of %s explicitly (upstream_suspects S5)", len(r.Fields), sc)
		return nil
	}
	if !z.sampleArgs(a, sas, r, "the sample's members must be the literal 0 — it is a sample of the type, not an initial value", "a hash map (key or value)") {
		return nil
	}
	return r
}

func (z *analyzer) hashMapDecl(a *AST, n *Node, hc hashClass) {
	v := a.ref(n, "value")
	c := n.Str["name"]
	p := z.pos(a, n)
	z.badMaps[c] = true
	z.badHash[c] = true
	if _, dup := z.maps[c]; dup {
		z.add(Rejected, SB013MapDeclShape, p, "constant %s is assigned twice", c)
		return
	}
	as := args(a, v)
	for _, x := range as {
		if x.Type == "CallNode" && z.badRecs[constName(a, a.ref(x, "receiver"))] {
			return
		}
	}
	shape := "`" + c + " = BPF::" + hc.class + ".new(\"" + c + "\", key, value, max_entries)` with literal arguments — key is :u32 / :u64 / :i32 / :i64 or a record sample `S.new(0, …)`"
	if hc.record {
		shape += ", value is a record sample `S.new(0, …)`"
	} else {
		shape += ", value is :u32 / :u64 / :i32 / :i64"
	}
	if len(as) != 4 || as[0].Type != "StringNode" || as[3].Type != "IntegerNode" {
		z.add(Rejected, SB013MapDeclShape, p, "a hash map is declared as %s", shape)
		return
	}
	name := as[0].Str["content"]
	if name != c {
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[0]), "the map name %q differs from its constant %s — both sides look the map up by this name, so they must be the same", name, c)
		return
	}
	for _, m := range z.mapOrder {
		if m.Name == name {
			z.add(Rejected, SB013MapDeclShape, p, "two map declarations use the name %q", name)
			return
		}
	}
	m := &MapDecl{Const: c, Name: name, Kind: hc.kind, Class: hc.class, Pos: p}
	switch k := as[1]; k.Type {
	case "SymbolNode":
		t, ok := intTypes[k.Str["value"]]
		if !ok {
			z.add(Rejected, SB013MapDeclShape, z.pos(a, k), "the key type must be :u32, :u64, :i32 or :i64 (8- and 16-bit keys are not accepted), got :%s", k.Str["value"])
			return
		}
		m.KeyBits, m.KeySigned = t[0], t[1] == 1
	case "CallNode":
		if m.KeyRecord = z.sampleRecord(a, k); m.KeyRecord == nil {
			return
		}
	default:
		z.add(Rejected, SB013MapDeclShape, z.pos(a, k), "a hash map is declared as %s", shape)
		return
	}
	switch x := as[2]; {
	case hc.record && x.Type == "CallNode":
		if m.Record = z.sampleRecord(a, x); m.Record == nil {
			return
		}
	case !hc.record && x.Type == "SymbolNode":
		t, ok := intTypes[x.Str["value"]]
		if !ok {
			z.add(Rejected, SB013MapDeclShape, z.pos(a, x), "the value type must be :u32, :u64, :i32 or :i64 (8- and 16-bit values are not accepted), got :%s", x.Str["value"])
			return
		}
		m.ValueBits, m.Signed = t[0], t[1] == 1
	case hc.record:
		z.add(Rejected, SB013MapDeclShape, z.pos(a, x), "BPF::%s takes a record sample `S.new(0, …)` as its value — integer values use BPF::%s", hc.class, valueCounterpart[hc.class])
		return
	default:
		z.add(Rejected, SB013MapDeclShape, z.pos(a, x), "BPF::%s takes an integer type as its value — record values use BPF::%s", hc.class, valueCounterpart[hc.class])
		return
	}
	entries, ok := z.literal(a, as[3])
	if !ok {
		return
	}
	if entries.Sign() <= 0 || !entries.IsUint64() || entries.Uint64() > 1<<32-1 {
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[3]), "max_entries must be a positive integer below 2^32, got %s", entries)
		return
	}
	if reservedPrefix.MatchString(name) {
		z.add(Rejected, SB007ReservedName, p, "map name %q uses the reserved prefix spinelbpf_", name)
		return
	}
	delete(z.badMaps, c)
	delete(z.badHash, c)
	m.MaxEntries = entries.Uint64()
	z.maps[c] = m
	z.mapOrder = append(z.mapOrder, m)
}

func (c *progCtx) statusCall(n *Node) (m *MapDecl, bad, ok bool) {
	if n == nil || n.Type != "CallNode" {
		return nil, false, false
	}
	if _, st := statusOps[n.Str["name"]]; !st {
		return nil, false, false
	}
	recv := c.a.ref(n, "receiver")
	if recv == nil || recv.Type != "ConstantReadNode" {
		return nil, false, false
	}
	if c.z.badHash[recv.Str["name"]] {
		return nil, true, true
	}
	m = c.z.maps[recv.Str["name"]]
	if m == nil || !m.IsHash() {
		return nil, false, false
	}
	return m, false, true
}

func (c *progCtx) statusParentOK(n *Node) bool {
	p := c.a.node(c.a.Parent[n.ID])
	if p != nil && p.Type == "LocalVariableWriteNode" && c.a.ref(p, "value") == n {
		return true
	}
	if p != nil && p.Type == "ArgumentsNode" {
		p = c.a.node(c.a.Parent[p.ID])
	}
	return p != nil && p.Type == "CallNode" && cmpOps[p.Str["name"]]
}

func statusIgnored(m *MapDecl, op string) string {
	return "the status of `" + m.Const + "." + op + "` (0 or a negative errno such as BPF::EEXIST) is dropped — receive it as `st = " + m.Const + "." + op + "(…)` and read `st`, compare it (`if " + m.Const + "." + op + "(…) != 0`), or drop it explicitly with `_ = " + m.Const + "." + op + "(…)`"
}

func (c *progCtx) statusLocalOK(w *Node, m *MapDecl, op string) bool {
	name := w.Str["name"]
	writes, reads := 0, 0
	walk(c.a, c.def, func(x *Node) bool {
		if x.Str["name"] != name {
			return true
		}
		switch x.Type {
		case "LocalVariableWriteNode", "LocalVariableOperatorWriteNode", "LocalVariableOrWriteNode", "LocalVariableAndWriteNode":
			writes++
		case "LocalVariableReadNode":
			reads++
		}
		return true
	})
	switch {
	case writes != 1 && c.statusReported[name]:
		return false
	case writes != 1:
		c.statusReported[name] = true
		c.add(Rejected, SB026StatusIgnored, w, "`%s` holds the status of `%s.%s` but is assigned %d times — a status local is assigned once (give each status its own name, so none is overwritten before it is read)", name, m.Const, op, writes)
		return false
	case reads == 0:
		c.add(Rejected, SB026StatusIgnored, w, "`%s` holds the status of `%s.%s` but is never read — check it (e.g. `if %s != 0`) or drop it explicitly with `_ = %s.%s(…)`", name, m.Const, op, name, m.Const, op)
		return false
	}
	return true
}

func (c *progCtx) statusExpr(n *Node, m *MapDecl, refVar string) *Expr {
	name := n.Str["name"]
	if name == "add_or_init" && m.Record != nil {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.add_or_init` takes integer values only — for a record value, `p = %s.lookup(k)`, `if p`, `p.atomic_add(:member, d)`, with `%s.insert(k, %s.new(…))` for a new key", m.Const, m.Const, m.Const, m.Record.Const)
		return nil
	}
	callee, ok := c.callee(n)
	if !ok {
		return nil
	}
	if callee != m.ClassName()+"#"+name {
		c.add(Rejected, SB011ShadowedName, n, "`%s` resolves to %s, not BPF::%s#%s", name, callee, m.ClassName(), name)
		return nil
	}
	if c.mapOf(c.a.ref(n, "receiver"), n) == nil {
		return nil
	}
	as := args(c.a, n)
	want := 2
	if name == "delete" {
		want = 1
	}
	if len(as) != want || c.a.ref(n, "block") != nil {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.%s` takes exactly %d argument(s)", m.Const, name, want)
		return nil
	}
	k := c.key(as[0], m, refVar)
	if want == 2 && !mutation("no-rmw") && c.rmwFirst(n, as[1], m, k, func(ref string) string {
		if name == "add_or_init" {
			return fmt.Sprintf("`%s.add_or_init` adds a value read from the same map (`%s.load`) — concurrent CPUs interleave the read and the add; use a delta that does not read %s", m.Name, ref, m.Const)
		}
		return fmt.Sprintf("`%s.%s` stores a value read from the same map (`%s.load`) — concurrent CPUs lose updates; use `%s.add_or_init` or `%s.atomic_add` inside `if %s`", m.Name, name, ref, m.Const, ref, ref)
	}) {
		return nil
	}
	var v *Expr
	if want == 2 {
		switch {
		case m.Record != nil:
			v = c.recordMake(as[1], m.Record, m, refVar)
		case name == "add_or_init":
			v = c.value(as[1], m, refVar, "delta")
		default:
			v = c.value(as[1], m, refVar, "value")
		}
		if v == nil {
			return nil
		}
	}
	if k == nil {
		return nil
	}
	if ref, ok := readsMap(v, m); ok && !mutation("no-rmw") && !c.exempt(m) {
		lk := c.refKey[ref]
		if lk == nil || lk.Kind != "lit" || k.Kind != "lit" || lk.Lit.Cmp(k.Lit) == 0 {
			c.add(Rejected, SB019SharedReadModifyWrite, n, "`%s.%s` stores a value read from the same map (`%s.load`) — concurrent CPUs lose updates; use `%s.add_or_init` or `%s.atomic_add` inside `if %s`", m.Name, name, ref, m.Const, ref, ref)
			return nil
		}
	}
	return &Expr{Kind: "hstatus", Op: statusOps[name], Map: m, Args: []*Expr{k, v}, Iv: fullI64, Pos: c.z.pos(c.a, n)}
}

func (c *progCtx) hashKey(n *Node, m *MapDecl, refVar string) *Expr {
	if m.KeyRecord != nil {
		if n.Type == "CallNode" && n.Str["name"] == "new" && constName(c.a, c.a.ref(n, "receiver")) == m.KeyRecord.Const {
			e := c.recordMake(n, m.KeyRecord, &MapDecl{Name: m.Name, Record: m.KeyRecord}, refVar)
			if e != nil && mutation("hash-key-swap") && len(e.Args) >= 2 {
				e.Args[0], e.Args[1] = e.Args[1], e.Args[0]
			}
			return e
		}
		c.add(Rejected, SB024RecordShape, n, "the key of %s is `%s.new(…)` written in the call itself — a record key is not kept in a local or built elsewhere (bpf-mlir: a record.make result does not cross blocks)", m.Const, m.KeyRecord.Const)
		return nil
	}
	e := c.expr(n, refVar)
	if e == nil {
		return nil
	}
	if e.Bool || e.Wide {
		c.add(Rejected, SB001UnsupportedConstruct, n, "a map key must be an Integer (not a bool, not an unnarrowed u64 value)")
		return nil
	}
	tr := intRange(m.KeyBits, m.KeySigned)
	if !e.Iv.within(tr.Lo, tr.Hi) {
		if e.Kind == "lit" {
			c.add(Rejected, SB014SemanticGap, n, "the key literal %s is outside %s (the %s key of %s; Ruby would not wrap it)", e.Lit, tr, m.KeyTypeName(), m.Name)
		} else {
			c.add(Rejected, SB014SemanticGap, n, "the key's range %s does not fit the %s key of %s %s — the key would be truncated silently; narrow it (e.g. `& 0xFFFF_FFFF`)", e.Iv, m.KeyTypeName(), m.Name, tr)
		}
		return nil
	}
	return e
}

func intRange(bits int, signed bool) Ival {
	return typeRange(&MapDecl{ValueBits: bits, Signed: signed})
}

func (c *progCtx) refAtomic(n *Node, refVar string) (Stmt, bool, bool) {
	recv := c.a.ref(n, "receiver")
	if n.Str["name"] != "atomic_add" || recv == nil || recv.Type != "LocalVariableReadNode" || c.refs[recv.Str["name"]] == nil || c.refMap[recv.Str["name"]].Record != nil {
		return Stmt{}, false, false
	}
	ref := recv.Str["name"]
	if ref != refVar {
		return Stmt{}, false, false
	}
	m := c.refMap[ref]
	if m.IsLpm() {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.atomic_add` is not accepted on lpm_trie %s — an lpm_trie is read-only on the eBPF side (read the value with `%s.load`; user space writes it with `obj.lpm_put`)", ref, m.Const, ref)
		return Stmt{}, false, true
	}
	callee, ok := c.callee(n)
	if !ok {
		return Stmt{}, false, true
	}
	if callee != "MapRef#atomic_add" {
		c.add(Rejected, SB011ShadowedName, n, "`atomic_add` resolves to %s, not BPF::MapRef#atomic_add", callee)
		return Stmt{}, false, true
	}
	as := args(c.a, n)
	if len(as) != 1 {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.atomic_add` takes one delta (`%s.atomic_add(d)`)", ref, ref)
		return Stmt{}, false, true
	}
	c.noteFlow(as[0], c.refMap[ref], n)
	if c.readsRefVia(as[0], ref) {
		c.add(Rejected, SB019SharedReadModifyWrite, n, "`%s.atomic_add` adds a value read from the same entry — use a delta that does not read `%s`", ref, ref)
		return Stmt{}, false, true
	}
	d := c.value(as[0], m, refVar, "delta")
	if d == nil {
		return Stmt{}, false, true
	}
	return Stmt{Kind: "ratomic", Var: ref, Map: m, Value: d, Pos: c.z.pos(c.a, n)}, true, true
}

func (c *progCtx) perCPUAdd(n *Node, refVar string) (Stmt, bool, bool) {
	recv := c.a.ref(n, "receiver")
	if n.Type != "CallOperatorWriteNode" || recv == nil || recv.Type != "CallNode" || recv.Str["name"] != "load" {
		return Stmt{}, false, false
	}
	pv := c.a.ref(recv, "receiver")
	if pv == nil || pv.Type != "LocalVariableReadNode" || c.refs[pv.Str["name"]] == nil {
		return Stmt{}, false, false
	}
	ref := pv.Str["name"]
	m := c.refMap[ref]
	if m.Record == nil || !c.exempt(m) {
		return Stmt{}, false, false
	}
	if ref != refVar {
		return Stmt{}, false, false
	}
	op := n.Str["binary_operator"]
	if op != "+" && op != "-" {
		c.add(Rejected, SB001UnsupportedConstruct, n, "`.%s %s= …` is not accepted on a per-CPU record member — only `+=` and `-=`", n.Str["name"], op)
		return Stmt{}, false, true
	}
	if !c.loadCallee(recv) {
		return Stmt{}, false, true
	}
	f := m.Record.Field(n.Str["name"])
	switch {
	case f == nil:
		c.add(Rejected, SB002UnsupportedCall, n, "record %s has no member `%s`", m.Record.Const, n.Str["name"])
		return Stmt{}, false, true
	case f.Pad:
		c.add(Rejected, SB024RecordShape, n, "`%s` is padding — it is neither read nor written on the eBPF side", f.Name)
		return Stmt{}, false, true
	}
	vn := c.a.ref(n, "value")
	c.noteFlow(vn, m, n)
	if c.readsRefVia(vn, ref) {
		c.add(Rejected, SB019SharedReadModifyWrite, n, "the delta of `%s.load.%s %s= …` reads the same entry — use a delta that does not read `%s`", ref, f.Name, op, ref)
		return Stmt{}, false, true
	}
	d := c.fieldValue(vn, f, m, refVar)
	if d == nil {
		return Stmt{}, false, true
	}
	return Stmt{Kind: "fadd", Var: ref, Map: m, Field: f, Value: d, Op: op, Pos: c.z.pos(c.a, n)}, true, true
}
