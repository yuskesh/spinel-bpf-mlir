package frontend

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
)

type Expr struct {
	Kind   string
	Op     string
	Args   []*Expr
	TpCopy *TpField
	Lit    *big.Int
	B      bool
	Var    string
	Ref    string
	Map    *MapDecl
	Bool   bool
	Iv     Ival
	Wide   bool
	Div    string
	Idx    int64
	Field  *RecordField
	Ring   *RingDecl
	Len    int64
	Glob   *GlobalDecl
	Path   string
	Pos    Pos
}

type Stmt struct {
	Kind    string
	Field   *RecordField
	Op      string
	Ring    *RingDecl
	Var     string
	Glob    *GlobalDecl
	Off     *Expr
	Len     int64
	Val     *Expr
	Cond    *Expr
	Then    []Stmt
	Else    []Stmt
	Map     *MapDecl
	Key     *Expr
	Value   *Expr
	Pos     Pos
	IfPos   Pos
	Count   int64
	Bound   *Expr
	Path    string
	Clamp   bool
	Incl    bool
	Carried []string
	KT      *KernelTypeDecl
	PtrOf   string
	PtrOfKT *KernelTypeDecl
	KStr    string
	Comm    bool
	TpCopy  *TpField
	TpStr   *TpField
	Argv    bool
	Index   *RecordField
	StrSSA  string
	IndexV  int
	Buf     bool
	BufLen  *Expr
	CountF  *RecordField
}

var binOps = map[string]bool{"+": true, "-": true, "*": true, "&": true, "|": true, "^": true, "<<": true, ">>": true, "/": true, "%": true}
var cmpOps = map[string]bool{"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true}
var mapOps = map[string]bool{"atomic_add": true, "update": true, "lookup": true, "insert": true, "replace": true, "delete": true, "add_or_init": true}

var windowReads = map[string]int64{"u8": 1, "be16": 2, "be32": 4, "le16": 2, "le32": 4}

type winInfo struct {
	len    int64
	active bool
}

type varInfo struct {
	Bool bool
	Iv   Ival
	From map[string]bool
}

type progCtx struct {
	statusReported map[string]bool
	z              *analyzer
	a              *AST
	t              *Types
	prog           *Program
	name           string
	param          string
	def            *Node
	refs           map[string]*Node
	refMap         map[string]*MapDecl
	refKey         map[string]*Expr
	wins           map[string]*winInfo
	used           map[*MapDecl]bool
	usedGlobals    map[*GlobalDecl]bool
	usedRings      map[*RingDecl]bool
	badBind        map[string]bool
	ostrs          map[string]bool
	ringMake       bool
	ostrLive       map[string]bool
	kptrs          map[string]*KernelTypeDecl
	kchecked       map[string]bool
	fpath          []string
	ctxKind        string
	poisoned       map[string]bool
	skipIfs        map[int]bool
	env            map[string]*varInfo
	loops          []*loopFrame
	escArm         string
	blockLocals    map[string]bool
	guardReturns   map[*Node]bool
}

func (c *progCtx) add(v Verdict, code Code, n *Node, format string, args ...any) {
	c.z.diags = append(c.z.diags, Diag{Verdict: v, Code: code, Pos: c.z.pos(c.a, n), Path: c.path(), Msg: fmt.Sprintf(format, args...)})
}

func (c *progCtx) rbs(n *Node) string {
	r, cnt := c.t.TypeOf(c.a, n)
	if cnt != 1 {
		return ""
	}
	return r.RBS
}

func (c *progCtx) typed(x *Node) bool {
	_, cnt := c.t.TypeOf(c.a, x)
	switch {
	case cnt > 1:
		c.add(Rejected, SB015AmbiguousType, x, "Spinel gives this %s %d types (a specialised node) — the eBPF side needs exactly one", x.Type, cnt)
		return false
	case cnt == 0 && c.prog != nil && c.prog.Kind == "fentry" && x.Type == "CallNode" && x.Str["name"] == "kptr" && c.isVarRead(c.a.ref(x, "receiver"), c.param):
		c.add(Rejected, SB033KernelTypeShape, x, "a fentry program reads its struct arguments only as `q = %s.kptr_or_null(i, T)` and `if q` (fentry pointers may always be NULL — declare `i => [:or_null, T]`)", c.param)
		return false
	case cnt == 0 && c.prog != nil && !hasPacket(c.prog.Kind) && x.Type == "CallNode" && c.isVarRead(c.a.ref(x, "receiver"), c.param):
		c.add(Rejected, SB028TracingKind, x, "the %s context has no `%s` — it reads %s", c.prog.Kind, x.Str["name"], ctxReads[c.prog.Kind])
		return false
	case cnt == 0:
		c.add(Unknown, SB001UnsupportedConstruct, x, "Spinel gives this %s no type — outside the typed subset (fail closed)", x.Type)
		return false
	}
	return true
}

func (z *analyzer) program(a *AST, d *Node, r rootDecl) *Program {
	c := &progCtx{z: z, a: a, t: z.typing.Types, def: d, name: r.Name, refs: map[string]*Node{}, statusReported: map[string]bool{}, refMap: map[string]*MapDecl{}, refKey: map[string]*Expr{}, wins: map[string]*winInfo{},
		used: map[*MapDecl]bool{}, usedGlobals: map[*GlobalDecl]bool{}, usedRings: map[*RingDecl]bool{}, badBind: map[string]bool{}, ostrs: map[string]bool{}, ostrLive: map[string]bool{}, kptrs: map[string]*KernelTypeDecl{}, kchecked: map[string]bool{}, poisoned: map[string]bool{}, skipIfs: map[int]bool{}, env: map[string]*varInfo{}, blockLocals: map[string]bool{}}
	c.prog = &Program{Name: r.Name, Kind: r.Kind, Pos: z.pos(a, d), DeclPos: r.Pos, EndLine: d.EndLine, Target: r.Target, Nargs: r.Nargs, Ret: r.Ret, Params: r.Params, BinarySHA: r.BinarySHA, BinaryPath: r.BinaryPath, SysTarget: r.SysTarget, TArgs: r.TArgs, TFields: r.TFields}
	before := len(z.diags)

	pn := a.ref(d, "parameters")
	param := a.arr(pn, "requireds")[0]
	c.param = param.Str["name"]
	cls := ctxClass[r.Kind]
	if pr, cnt := c.t.TypeOf(a, param); cnt != 1 || pr.RBS != cls || !z.classInLib(a, cls) {
		got := "(no type)"
		if pr != nil {
			got = pr.RBS
		}
		c.add(Rejected, SB010TypingProbe, param, "the context parameter `%s` must be typed BPF::%s (from ruby/lib/bpf.rb) by the typing probe, got %s", c.param, cls, got)
	}

	body := a.ref(d, "body")
	var stmts []*Node
	if body != nil {
		if body.Type != "StatementsNode" {
			c.add(Rejected, SB001UnsupportedConstruct, body, "the program body must be a plain sequence of statements (no rescue / ensure), got %s", body.Type)
			return nil
		}
		stmts = a.arr(body, "body")
	}
	bad := false
	walk(a, d, func(x *Node) bool {
		if !bad && r.Kind != "fmod_ret" && c.isFmodReturn(x) {
			c.add(Rejected, SB028TracingKind, x, "`BPF.fmod_return` ends only a fmod_ret program — %s", verdictReturns(r.Kind))
			bad = true
		}
		if !bad && x.Type == "ConstantPathNode" {
			cn := constName(a, x)
			vk := verdictKindOf(cn)
			switch {
			case vk == "" || vk == r.Kind:
			case vk == "socket_filter" || r.Kind == "socket_filter" || vk == "cgroup_skb" || r.Kind == "cgroup_skb" || vk == "netfilter" || r.Kind == "netfilter" || vk == "flow_dissector" || r.Kind == "flow_dissector" || vk == "fmod_ret" || r.Kind == "fmod_ret":
				c.add(Rejected, SB028TracingKind, x, "%s is %s verdict — %s", cn, verdictKindText(vk), verdictReturns(r.Kind))
				bad = true
			case vk == "xdp" && verdictsOf(r.Kind) == nil:
				c.add(Rejected, SB028TracingKind, x, "%s is an XDP verdict — a %s program returns nothing (its last value is dropped)", cn, r.Kind)
				bad = true
			case verdictsOf(r.Kind) == nil:
				c.add(Rejected, SB028TracingKind, x, "%s is a sched_cls (tcx) verdict — a %s program returns nothing (its last value is dropped)", cn, r.Kind)
				bad = true
			case vk == "xdp":
				c.add(Rejected, SB028TracingKind, x, "%s is an XDP verdict — a sched_cls (`BPF.tcx`) program returns BPF::TC_PASS or BPF::TC_DROP", cn)
				bad = true
			default:
				c.add(Rejected, SB028TracingKind, x, "%s is a sched_cls (tcx) verdict — an XDP program returns BPF::XDP_ABORTED / XDP_DROP / XDP_PASS / XDP_TX", cn)
				bad = true
			}
		}
		return !bad
	})
	if bad {
		return nil
	}
	if verdictsOf(r.Kind) == nil {
		c.prog.Body = c.stmts(stmts, "")
		c.prog.Verdict = "done"
		c.prog.VerdictPos = c.z.pos(a, d)
	} else {
		if len(stmts) == 0 {
			c.add(Rejected, SB008ProgramShape, d, "the program `%s` must end with %s", r.Name, verdictWant(r.Kind, "an XDP verdict (BPF::XDP_PASS etc.)"))
			return nil
		}
		last := stmts[len(stmts)-1]
		c.guardReturns = map[*Node]bool{}
		c.prog.Body = c.guardStmts(stmts[:len(stmts)-1])
		c.verdict(last)
	}
	for _, m := range z.mapOrder {
		if c.used[m] {
			c.prog.Maps = append(c.prog.Maps, m)
		}
	}
	for _, r := range z.ringOrder {
		if c.usedRings[r] {
			c.prog.Rings = append(c.prog.Rings, r)
		}
	}
	for _, g := range z.globalOrder {
		if c.usedGlobals[g] {
			c.prog.Globals = append(c.prog.Globals, g)
		}
	}
	if len(z.diags) > before && z.diags[before:].Blocking() {
		return nil
	}
	return c.prog
}

func (z *analyzer) classInLib(a *AST, name string) bool {
	inLib, elsewhere := false, false
	walk(a, a.node(a.Root), func(n *Node) bool {
		if n.Type == "ClassNode" {
			cn := constName(a, a.ref(n, "constant_path"))
			if cn == name || cn == "BPF::"+name {
				if a.File(n) == z.lib {
					inLib = true
				} else {
					elsewhere = true
				}
			}
		}
		return true
	})
	return inLib && !elsewhere
}

func copyEnv(e map[string]*varInfo) map[string]*varInfo {
	out := map[string]*varInfo{}
	for k, v := range e {
		vv := *v
		out[k] = &vv
	}
	return out
}

func joinEnv(a, b map[string]*varInfo) map[string]*varInfo {
	out := map[string]*varInfo{}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || va.Bool != vb.Bool {
			continue
		}
		v := *va
		if !v.Bool {
			v.Iv = union(va.Iv, vb.Iv)
		}
		v.From = unionRefs(va.From, vb.From)
		out[k] = &v
	}
	return out
}

func sortedKeys(m map[string]*varInfo) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c *progCtx) stmts(ns []*Node, refVar string) []Stmt {
	var out []Stmt
	for i := 0; i < len(ns); i++ {
		n := ns[i]
		switch n.Type {
		case "CallNode":
			if fi := c.z.userCall(c.a, n); fi != nil {
				if e := c.subCall(n, fi, refVar); e != nil {
					out = append(out, Stmt{Kind: "drop", Val: e, Pos: c.z.pos(c.a, n)})
				}
				continue
			}
			if c.isIterCall(n) {
				if s, ok := c.loopStmt(n); ok {
					out = append(out, s)
				}
				continue
			}
			if c.outputOfBadRing(n) {
				continue
			}
			if c.isOutput(n) {
				c.add(Rejected, SB025DroppedEvent, n, "%s", droppedMsg(c.ringOf(c.a.ref(n, "receiver"))))
				continue
			}
			if c.isOutputStr(n) {
				shape := outputStrShape(c.ringOf(c.a.ref(n, "receiver")))
				if n.Str["name"] == "output_comm" {
					shape = outputCommShape(c.ringOf(c.a.ref(n, "receiver")))
				}
				c.add(Rejected, SB025DroppedEvent, n, "the result of %s (nil when the ring is full) is dropped — use %s", n.Str["name"], shape)
				continue
			}
			if c.isAdjustPkt(n) {
				c.add(Rejected, SB026StatusIgnored, n, "the status of `%s.%s(d)` (0 or −errno) is dropped — use `st = %s.%s(d)` (read later) or `_ = %s.%s(d)`", c.param, n.Str["name"], c.param, n.Str["name"], c.param, n.Str["name"])
				continue
			}
			if m, bad, ok := c.statusCall(n); ok {
				if !bad && !c.readsBad(n) {
					c.add(Rejected, SB026StatusIgnored, n, "%s", statusIgnored(m, n.Str["name"]))
				}
				continue
			}
			if s, ok, handled := c.refAtomic(n, refVar); handled {
				if ok {
					out = append(out, s)
				}
				continue
			}
			if s, ok, handled := c.recordCall(n, refVar); handled {
				if ok {
					out = append(out, s)
				}
				continue
			}
			if s, ok := c.mapCall(n, refVar); ok {
				out = append(out, s)
			}
		case "CallOperatorWriteNode", "CallOrWriteNode", "CallAndWriteNode":
			if s, ok, handled := c.perCPUAdd(n, refVar); handled {
				if ok {
					out = append(out, s)
				}
				continue
			}
			c.add(Rejected, SB019SharedReadModifyWrite, n, "`.%s %s= …` on a record member reads and writes the map value — concurrent CPUs lose updates; use `p.atomic_add(:%s, d)`", n.Str["name"], n.Str["binary_operator"], n.Str["name"])
		case "LocalVariableWriteNode":
			v := c.a.ref(n, "value")
			if c.isSkAssign(v) {
				if s, ok := c.skAssignStmt(n); ok {
					out = append(out, s)
				} else {
					c.poisoned[n.Str["name"]] = true
				}
				continue
			}
			if c.outputOfBadRing(v) {
				continue
			}
			if c.kcheckCall(v) {
				if i+1 >= len(ns) || ns[i+1].Type != "IfNode" || !c.isVarRead(c.a.ref(ns[i+1], "predicate"), n.Str["name"]) {
					c.add(Rejected, SB005RefCheckShape, n, "`%s = %s(…)` (a nullable kernel pointer) must be followed immediately by `if %s`", n.Str["name"], v.Str["name"], n.Str["name"])
					c.badBind[n.Str["name"]] = true
					continue
				}
				if s, ok := c.kcheckStmt(n, ns[i+1], refVar); ok {
					out = append(out, s)
				} else {
					c.badBind[n.Str["name"]] = true
					c.skipIfs[ns[i+1].ID] = true
				}
				i++
				continue
			}
			if c.kptrCall(v) {
				if s, ok := c.kptrBind(n, c.topLevel(n)); ok {
					out = append(out, s)
				} else {
					c.badBind[n.Str["name"]] = true
				}
				continue
			}
			if c.isOutputStr(v) {
				if n.Str["name"] == "_" {
					if s, ok := c.outputStr(v, "", refVar); ok {
						out = append(out, s)
					}
					continue
				}
				if i+1 >= len(ns) || ns[i+1].Type != "IfNode" || !c.isVarRead(c.a.ref(ns[i+1], "predicate"), n.Str["name"]) {
					c.add(Rejected, SB025DroppedEvent, n, "`%s = %s.output_str(…)` must be followed immediately by `if %s` — %s", n.Str["name"], c.ringOf(c.a.ref(v, "receiver")).Const, n.Str["name"], outputStrShape(c.ringOf(c.a.ref(v, "receiver"))))
					c.badBind[n.Str["name"]] = true
					continue
				}
				if ss, ok := c.outputStrCheck(n, ns[i+1], refVar); ok {
					out = append(out, ss...)
				} else {
					c.badBind[n.Str["name"]] = true
					c.skipIfs[ns[i+1].ID] = true
				}
				i++
				continue
			}
			if c.isOutput(v) {
				r := c.ringOf(c.a.ref(v, "receiver"))
				if n.Str["name"] != "_" {
					c.add(Rejected, SB025DroppedEvent, n, "`%s = %s.output(…)` — the result is accepted only as an `if` / `unless` condition or `_ = …` (a bool local can carry it to a path that drops it)", n.Str["name"], r.Const)
					c.poisoned[n.Str["name"]] = true
					continue
				}
				if e := c.ringOutput(v, refVar); e != nil {
					out = append(out, Stmt{Kind: "ringout", Ring: r, Value: e.Args[0], Pos: c.z.pos(c.a, n)})
				}
				continue
			}
			if c.isAdjustPkt(v) && n.Str["name"] == "_" {
				if e := c.expr(v, refVar); e != nil {
					out = append(out, Stmt{Kind: "drop", Val: e, Pos: c.z.pos(c.a, n)})
				}
				continue
			}
			if m, bad, ok := c.statusCall(v); ok {
				if bad || c.readsBad(v) {
					c.poisoned[n.Str["name"]] = true
					continue
				}
				if n.Str["name"] == "_" {
					if e := c.statusExpr(v, m, refVar); e != nil {
						out = append(out, Stmt{Kind: "drop", Val: e, Pos: c.z.pos(c.a, n)})
					}
					continue
				}
				if !c.statusLocalOK(n, m, v.Str["name"]) {
					c.poisoned[n.Str["name"]] = true
					continue
				}
			}
			if v != nil && v.Type == "CallNode" && v.Str["name"] == "lookup" {
				if i+1 >= len(ns) || ns[i+1].Type != "IfNode" || !c.isVarRead(c.a.ref(ns[i+1], "predicate"), n.Str["name"]) {
					c.add(Rejected, SB005RefCheckShape, n, "`%s = %s.lookup(…)` must be followed immediately by `if %s` (the present / absent check)", n.Str["name"], constName(c.a, c.a.ref(v, "receiver")), n.Str["name"])
					c.badBind[n.Str["name"]] = true
					continue
				}
				if s, ok := c.lookupCheck(n, ns[i+1], refVar); ok {
					out = append(out, s)
				} else {
					c.badBind[n.Str["name"]] = c.refs[n.Str["name"]] == nil || c.refs[n.Str["name"]] != n
					c.skipIfs[ns[i+1].ID] = true
				}
				i++
				continue
			}
			if v != nil && v.Type == "CallNode" && v.Str["name"] == "check" && c.isVarRead(c.a.ref(v, "receiver"), c.param) && hasPacket(c.ctxKindOf()) {
				if i+1 >= len(ns) || ns[i+1].Type != "IfNode" || !c.isVarRead(c.a.ref(ns[i+1], "predicate"), n.Str["name"]) {
					c.add(Rejected, SB005RefCheckShape, n, "`%s = %s.check(off, len)` must be followed immediately by `if %s` (the in-range / out-of-range check)", n.Str["name"], c.param, n.Str["name"])
					c.badBind[n.Str["name"]] = true
					continue
				}
				if s, ok := c.windowCheck(n, ns[i+1], refVar); ok {
					out = append(out, s)
				} else {
					if c.wins[n.Str["name"]] == nil {
						c.badBind[n.Str["name"]] = true
					}
					c.skipIfs[ns[i+1].ID] = true
				}
				i++
				continue
			}
			if s, ok := c.assign(n, n.Str["name"], v, refVar); ok {
				out = append(out, s)
			}
		case "MultiWriteNode":
			if s, ok := c.kreadStmt(n); ok {
				out = append(out, s)
			}
		case "LocalVariableOperatorWriteNode":
			if s, ok := c.opAssign(n, refVar); ok {
				out = append(out, s)
			}
		case "IfNode", "UnlessNode":
			if s, ok := c.ifStmt(n, refVar); ok {
				out = append(out, s)
			}
		case "ReturnNode":
			continue
		case "LocalVariableReadNode":
			if n.Str["name"] == c.param {
				c.add(Rejected, SB001UnsupportedConstruct, n, "the context `%s` is used only as `w = %s.check(off, len)` right before `if w`", c.param, c.param)
			} else {
				c.add(Rejected, SB001UnsupportedConstruct, n, "a bare expression statement is not accepted")
			}
		case "BreakNode", "NextNode":
			if s, ok := c.escape(n, i == len(ns)-1); ok {
				out = append(out, s)
			}
		case "WhileNode", "UntilNode", "ForNode", "RedoNode":
			c.add(Rejected, SB001UnsupportedConstruct, n, "%s has no static bound — write %s with a bound ≤ %d", n.Type, loopForms, maxLoopCount)
		default:
			c.add(Rejected, SB001UnsupportedConstruct, n, "%s is not accepted on the eBPF side", n.Type)
		}
	}
	return out
}

func (c *progCtx) isVarRead(n *Node, name string) bool {
	return n != nil && n.Type == "LocalVariableReadNode" && n.Str["name"] == name
}

func (c *progCtx) assign(n *Node, name string, v *Node, refVar string) (Stmt, bool) {
	if c.badBind[name] || c.readsBad(v) {
		c.poisoned[name] = true
		return Stmt{}, false
	}
	if name == c.param || c.refs[name] != nil || c.wins[name] != nil {
		c.add(Rejected, SB005RefCheckShape, n, "`%s` cannot be reassigned (the context / a lookup result / a window is bound once)", name)
		return Stmt{}, false
	}
	if reservedPrefix.MatchString(name) {
		c.add(Rejected, SB007ReservedName, n, "`%s` uses the reserved prefix spinelbpf_", name)
		return Stmt{}, false
	}
	if v == nil || !c.typed(n) {
		return Stmt{}, false
	}
	e := c.expr(v, refVar)
	if e == nil {
		c.poisoned[name] = true
		return Stmt{}, false
	}
	if !c.valueOK(e, v) {
		c.poisoned[name] = true
		return Stmt{}, false
	}
	want := "Integer"
	if e.Bool {
		want = "bool"
	}
	if got := c.rbs(n); got != want {
		c.add(Rejected, SB001UnsupportedConstruct, n, "`%s` is typed %q by Spinel, not %s — a local must keep one type (Integer or bool)", name, got, want)
		return Stmt{}, false
	}
	if old, ok := c.env[name]; ok && old.Bool != e.Bool {
		c.add(Rejected, SB001UnsupportedConstruct, n, "`%s` changes between Integer and bool", name)
		return Stmt{}, false
	}
	c.env[name] = &varInfo{Bool: e.Bool, Iv: e.Iv, From: c.origin(v)}
	return Stmt{Kind: "assign", Var: name, Val: e, Pos: c.z.pos(c.a, n)}, true
}

func (c *progCtx) opAssign(n *Node, refVar string) (Stmt, bool) {
	name, op := n.Str["name"], n.Str["binary_operator"]
	info, ok := c.env[name]
	if !ok {
		c.add(Rejected, SB001UnsupportedConstruct, n, "`%s %s= …` needs `%s` defined before (Ruby reads nil)", name, op, name)
		return Stmt{}, false
	}
	if info.Bool || !binOps[op] {
		c.add(Rejected, SB001UnsupportedConstruct, n, "`%s %s= …` is not accepted", name, op)
		return Stmt{}, false
	}
	if !c.typed(n) {
		return Stmt{}, false
	}
	vn := c.a.ref(n, "value")
	rhs := c.expr(vn, refVar)
	if rhs == nil {
		return Stmt{}, false
	}
	lhs := &Expr{Kind: "var", Var: name, Iv: info.Iv, Pos: c.z.pos(c.a, n)}
	e := c.binary(n, op, lhs, rhs, vn)
	if e == nil {
		return Stmt{}, false
	}
	c.env[name] = &varInfo{Iv: e.Iv, From: unionRefs(info.From, c.origin(vn))}
	return Stmt{Kind: "assign", Var: name, Val: e, Pos: c.z.pos(c.a, n)}, true
}

func (c *progCtx) valueOK(e *Expr, n *Node) bool {
	if e.Wide {
		c.add(Rejected, SB014SemanticGap, n, "a u64 value %s (a u64 map value or BPF.ktime_ns) does not fit Ruby's Integer — narrow it first (`x & M` or `x >> K`), or pass it straight to a u64 map or record member", e.Iv)
		return false
	}
	return true
}

func (c *progCtx) ifStmt(n *Node, refVar string) (Stmt, bool) {
	pred := c.a.ref(n, "predicate")
	if c.readsBad(pred) {
		return Stmt{}, false
	}
	if pred != nil && pred.Type == "LocalVariableReadNode" && c.refs[pred.Str["name"]] != nil {
		c.add(Rejected, SB005RefCheckShape, n, "`if %s` is accepted only right after `%s = M.lookup(k)`", pred.Str["name"], pred.Str["name"])
		return Stmt{}, false
	}
	if pred != nil && pred.Type == "LocalVariableReadNode" && c.wins[pred.Str["name"]] != nil {
		c.add(Rejected, SB005RefCheckShape, n, "`%s %s` is not accepted — a window is checked only as `if %s` right after `%s = %s.check(off, len)`", map[string]string{"IfNode": "if", "UnlessNode": "unless"}[n.Type], pred.Str["name"], pred.Str["name"], pred.Str["name"], c.param)
		return Stmt{}, false
	}
	if w := condAssign(c.a, pred); w != nil {
		c.add(Rejected, SB005RefCheckShape, n, "an assignment inside the condition is not accepted — write `%s = …` on its own line, then `if %s`", w.Str["name"], w.Str["name"])
		return Stmt{}, false
	}
	cond := c.cond(pred, refVar)
	if cond == nil {
		return Stmt{}, false
	}
	if n.Type == "UnlessNode" {
		cond = &Expr{Kind: "not", Args: []*Expr{cond}, Bool: true, Pos: cond.Pos}
	}
	var thenN []*Node
	if st := c.a.ref(n, "statements"); st != nil {
		thenN = c.a.arr(st, "body")
	}
	var elseNode *Node
	if n.Type == "IfNode" {
		elseNode = c.a.ref(n, "subsequent")
	} else {
		elseNode = c.a.ref(n, "else_clause")
	}
	pre := c.env
	c.env = narrowEnv(pre, cond, true)
	savedArm := c.escArm
	if c.escArm != "window" {
		c.escArm = "if"
	}
	defer func() { c.escArm = savedArm }()
	s := Stmt{Kind: "if", Cond: cond, Pos: c.z.pos(c.a, n)}
	s.Then = c.stmts(thenN, refVar)
	thenEnv := c.env
	c.env = narrowEnv(pre, cond, false)
	if elseNode != nil {
		switch elseNode.Type {
		case "ElseNode":
			var elseN []*Node
			if st := c.a.ref(elseNode, "statements"); st != nil {
				elseN = c.a.arr(st, "body")
			}
			s.Else = c.stmts(elseN, refVar)
		case "IfNode":
			if es, ok := c.ifStmt(elseNode, refVar); ok {
				s.Else = []Stmt{es}
			}
		default:
			c.add(Rejected, SB001UnsupportedConstruct, elseNode, "%s after `if` is not accepted", elseNode.Type)
		}
	}
	c.env = joinArms(pre, thenEnv, c.env, escapes(s.Then), escapes(s.Else))
	return s, true
}

func joinArms(pre, a, b map[string]*varInfo, escA, escB bool) map[string]*varInfo {
	switch {
	case escA && escB:
		return copyEnv(pre)
	case escA:
		return b
	case escB:
		return a
	}
	return joinEnv(a, b)
}

func (c *progCtx) cond(n *Node, refVar string) *Expr {
	if n == nil || !c.typed(n) {
		return nil
	}
	if got := c.rbs(n); got != "bool" {
		c.add(Rejected, SB005RefCheckShape, n, "the condition is typed %q — conditions must be bool (Ruby treats 0 as true and nil as false, BPF does not; compare explicitly, e.g. `x != 0`)", got)
		return nil
	}
	e := c.expr(n, refVar)
	if e == nil {
		return nil
	}
	if !e.Bool {
		c.add(Rejected, SB005RefCheckShape, n, "the condition must be a bool expression")
		return nil
	}
	return e
}

func (c *progCtx) expr(n *Node, refVar string) *Expr {
	if n == nil || c.callsBadFunc(n) {
		return nil
	}
	p := c.z.pos(c.a, n)
	switch n.Type {
	case "ParenthesesNode":
		b := c.a.ref(n, "body")
		if b == nil || b.Type != "StatementsNode" || len(b.Arr["body"]) != 1 {
			c.add(Rejected, SB001UnsupportedConstruct, n, "a parenthesised expression must hold one expression")
			return nil
		}
		return c.expr(c.a.arr(b, "body")[0], refVar)
	case "IntegerNode":
		if !c.typed(n) {
			return nil
		}
		v, ok := c.z.literal(c.a, n)
		if !ok {
			return nil
		}
		if v.Cmp(literalLo) < 0 {
			c.add(Rejected, SB014SemanticGap, n, "integer literal %s is Spinel's nil marker (−2^63) — literals must be within [−2^63+1, 2^63−1]", v)
			return nil
		}
		return &Expr{Kind: "lit", Lit: v, Iv: point(v), Pos: p}
	case "TrueNode", "FalseNode":
		return &Expr{Kind: "blit", B: n.Type == "TrueNode", Bool: true, Pos: p}
	case "NilNode":
		c.add(Rejected, SB001UnsupportedConstruct, n, "nil is not a value on the eBPF side")
		return nil
	case "LocalVariableReadNode":
		name := n.Str["name"]
		if c.badBind[name] || (c.poisoned[name] && c.env[name] == nil) {
			return nil
		}
		if name == c.param {
			c.add(Rejected, SB001UnsupportedConstruct, n, "the context `%s` is used only as %s", c.param, ctxUse(c.ctxKindOf(), c.param))
			return nil
		}
		if c.refs[name] != nil {
			c.add(Rejected, SB005RefCheckShape, n, "`%s` may be read only as `if %s` and as `%s.load` inside it", name, name, name)
			return nil
		}
		if c.kptrs[name] != nil {
			c.kptrMisuse(n, name)
			return nil
		}
		if c.kchecked[name] {
			c.add(Rejected, SB005RefCheckShape, n, "`%s` (a nullable kernel pointer) may be read only as `if %s` and as `%s.load.m` / `%s.ptr(…)` inside it", name, name, name, name)
			return nil
		}
		if c.ostrs[name] {
			c.add(Rejected, SB005RefCheckShape, n, "`%s` (an output_str result) may be read only as `if %s` and as `%s.status` inside it", name, name, name)
			return nil
		}
		if c.wins[name] != nil {
			c.add(Rejected, SB005RefCheckShape, n, "window `%s` may be read only as `if %s` and as `%s.u8(i)` / `be16` / `be32` / `le16` / `le32` inside it", name, name, name)
			return nil
		}
		info, ok := c.env[name]
		if !ok {
			c.add(Rejected, SB001UnsupportedConstruct, n, "`%s` is not defined on every path here (Ruby would read nil)", name)
			return nil
		}
		if !c.typed(n) {
			return nil
		}
		return &Expr{Kind: "var", Var: name, Bool: info.Bool, Iv: info.Iv, Pos: p}
	case "AndNode", "OrNode":
		l, r := c.a.ref(n, "left"), c.a.ref(n, "right")
		sideEffect := false
		walk(c.a, r, func(x *Node) bool {
			if x.Type == "CallNode" && mapOps[x.Str["name"]] {
				sideEffect = true
			}
			return true
		})
		if sideEffect {
			c.add(Rejected, SB018LogicalSideEffect, n, "the right operand of `%s` calls a map operation — Ruby may skip it (short-circuit); move it into its own statement", map[string]string{"AndNode": "&&", "OrNode": "||"}[n.Type])
			return nil
		}
		le, re := c.cond(l, refVar), c.cond(r, refVar)
		if le == nil || re == nil {
			return nil
		}
		k := "and"
		if n.Type == "OrNode" {
			k = "or"
		}
		return &Expr{Kind: k, Args: []*Expr{le, re}, Bool: true, Pos: p}
	case "IfNode":
		cond := c.cond(c.a.ref(n, "predicate"), refVar)
		st, sub := c.a.ref(n, "statements"), c.a.ref(n, "subsequent")
		if cond == nil {
			return nil
		}
		if st == nil || len(st.Arr["body"]) != 1 || sub == nil || sub.Type != "ElseNode" || c.a.ref(sub, "statements") == nil || len(c.a.ref(sub, "statements").Arr["body"]) != 1 {
			c.add(Rejected, SB001UnsupportedConstruct, n, "an `if` used as a value must be `c ? a : b` with one expression in each arm")
			return nil
		}
		a := c.expr(c.a.arr(st, "body")[0], refVar)
		b := c.expr(c.a.arr(c.a.ref(sub, "statements"), "body")[0], refVar)
		if a == nil || b == nil {
			return nil
		}
		if a.Bool != b.Bool || a.Wide || b.Wide {
			c.add(Rejected, SB001UnsupportedConstruct, n, "both arms of `c ? a : b` must be the same type (Integer or bool)")
			return nil
		}
		e := &Expr{Kind: "sel", Args: []*Expr{cond, a, b}, Bool: a.Bool, Pos: p}
		if !a.Bool {
			e.Iv = union(a.Iv, b.Iv)
		}
		return e
	case "CallNode":
		return c.callExpr(n, refVar)
	case "ConstantPathNode":
		if v, ok := errnoConsts[constName(c.a, n)]; ok {
			if mutation("hash-errno") && v == -2 {
				v = 2
			}
			lit := big.NewInt(v)
			return &Expr{Kind: "lit", Lit: lit, Iv: point(lit), Pos: p}
		}
	}
	c.add(Rejected, SB001UnsupportedConstruct, n, "%s is not accepted in an expression on the eBPF side", n.Type)
	return nil
}

func (c *progCtx) callExpr(n *Node, refVar string) *Expr {
	name := n.Str["name"]
	p := c.z.pos(c.a, n)
	recv := c.a.ref(n, "receiver")
	as := args(c.a, n)
	if c.isIterCall(n) {
		c.add(Rejected, SB030LoopShape, n, "the value of `%s` (its receiver, or a break value) is not used on the eBPF side — write the loop as a statement and keep results in locals", name)
		return nil
	}
	if recv == nil && len(as) == 0 && c.a.ref(n, "block") == nil && c.blockLocals[name] {
		c.add(Rejected, SB030LoopShape, n, "`%s` was first assigned inside a loop block — Ruby does not keep it after the loop (it reads a method call); assign it before the loop", name)
		return nil
	}
	if recv != nil && recv.Type == "ConstantReadNode" {
		if g := c.z.globals[recv.Str["name"]]; g != nil {
			return c.globalRead(n, g, name, as, p)
		}
		if c.z.badGlobals[recv.Str["name"]] {
			return nil
		}
	}
	if m, bad, ok := c.statusCall(n); ok {
		if bad {
			return nil
		}
		if !c.statusParentOK(n) {
			c.add(Rejected, SB026StatusIgnored, n, "the status of `%s.%s` is accepted only as `st = %s.%s(…)` (read later), as an operand of a comparison, or as `_ = %s.%s(…)` — not as an argument, an arithmetic operand or another value", m.Const, name, m.Const, name, m.Const, name)
			return nil
		}
		return c.statusExpr(n, m, refVar)
	}
	if mapOps[name] {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s` is a statement, not a value (its result is not used on the eBPF side)", name)
		return nil
	}
	if name == "[]" && recv != nil && recv.Type == "CallNode" && refVar != "" {
		if ld := c.a.ref(recv, "receiver"); ld != nil && ld.Type == "CallNode" && ld.Str["name"] == "load" && c.isVarRead(c.a.ref(ld, "receiver"), refVar) && c.refMap[refVar].Record != nil {
			return c.elemRead(n, recv, ld, refVar)
		}
	}
	if recv != nil && recv.Type == "CallNode" && recv.Str["name"] == "load" && refVar != "" && c.isVarRead(c.a.ref(recv, "receiver"), refVar) && c.refMap[refVar].Record != nil {
		return c.fieldRead(n, recv, refVar)
	}
	if name == "load" && refVar != "" && c.isVarRead(recv, refVar) && c.refMap[refVar].Record != nil {
		c.add(Rejected, SB005RefCheckShape, n, "`%s.load` of a record is not a value — read a member (`%s.load.<member>`)", refVar, refVar)
		return nil
	}
	if name == "load" && c.isKptrRead(recv) {
		c.kptrMisuse(n, recv.Str["name"])
		return nil
	}
	if name == "load" {
		if !c.isVarRead(recv, refVar) || refVar == "" || len(as) != 0 {
			c.add(Rejected, SB005RefCheckShape, n, "`p.load` is accepted only inside `if p` right after `p = M.lookup(k)`")
			return nil
		}
		callee, ok := c.callee(n)
		if !ok {
			return nil
		}
		if callee != "MapRef#load" {
			c.add(Rejected, SB011ShadowedName, n, "`load` resolves to %s, not BPF::MapRef#load", callee)
			return nil
		}
		m := c.refMap[refVar]
		e := &Expr{Kind: "load", Ref: refVar, Map: m, Pos: p}
		switch {
		case m.ValueBits == 32 && !m.Signed:
			e.Iv = iv(new(big.Int), new(big.Int).Set(u32Max))
		case m.ValueBits == 32:
			e.Iv = iv(new(big.Int).Set(i32Min), new(big.Int).Set(i32Max))
		case m.Signed:
			e.Iv = fullI64
		default:
			e.Iv, e.Wide = iv(new(big.Int), new(big.Int).Set(u64Max)), true
		}
		return e
	}
	if !hasPacket(c.prog.Kind) && recv != nil && c.isVarRead(recv, c.param) {
		return c.tracingRead(n, name, as, p)
	}
	if c.prog.Kind == "flow_dissector" && (name == "key" || name == "set_key") && recv != nil && c.isVarRead(recv, c.param) {
		if name == "set_key" {
			c.add(Rejected, SB002UnsupportedCall, n, "`%s.set_key(…)` is a statement — not a value", c.param)
			return nil
		}
		return c.flowKeyRead(n, refVar)
	}
	if c.prog.Kind == "xdp" && (name == "adjust_head" || name == "adjust_tail") && recv != nil && c.isVarRead(recv, c.param) {
		return c.adjustPkt(n, refVar)
	}
	if ctxFields[c.prog.Kind][name] && recv != nil && c.isVarRead(recv, c.param) {
		return c.tracingRead(n, name, as, p)
	}
	if _, ok := windowReads[name]; ok {
		return c.windowRead(n, recv, as)
	}
	if c.outputOfBadRing(n) {
		return nil
	}
	if c.isOutput(n) {
		if !c.outputIsCondition(n) {
			c.add(Rejected, SB025DroppedEvent, n, "%s — not as an operand, argument or value", droppedMsg(c.ringOf(recv)))
			return nil
		}
		return c.ringOutput(n, refVar)
	}
	if c.isOutputStr(n) {
		c.add(Rejected, SB025DroppedEvent, n, "the result of output_str is accepted only as %s", outputStrShape(c.ringOf(recv)))
		return nil
	}
	if (name == "status" || name == "sent") && recv != nil && recv.Type == "LocalVariableReadNode" && c.ostrs[recv.Str["name"]] {
		return c.ostrStatus(n, recv, p)
	}
	if q := c.kcheckedRoot(n); q != "" {
		c.add(Rejected, SB005RefCheckShape, n, "`%s` (a nullable kernel pointer) may be read only as `if %s` and as `%s.load.m` / `%s.ptr(…)` inside it", q, q, q, q)
		return nil
	}
	if e, ok := c.kpathRead(n, p); ok {
		return e
	}
	if recv != nil && recv.Type == "CallNode" && recv.Str["name"] == "load" && c.isKptrRead(c.a.ref(recv, "receiver")) {
		return c.kfieldRead(n, recv, p)
	}
	if name == "addr" && recv != nil && c.isKptrRead(recv) {
		return c.kaddrRead(n, recv, p)
	}
	if recv != nil && c.isKptrRead(recv) {
		c.kptrMisuse(n, recv.Str["name"])
		return nil
	}
	if name == "pid_tgid" && constName(c.a, recv) == "BPF" {
		callee, ok := c.callee(n)
		if !ok {
			return nil
		}
		if callee != "BPF.pid_tgid" || len(as) != 0 {
			c.add(Rejected, SB011ShadowedName, n, "`BPF.pid_tgid` resolves to %q (with %d arguments), not the library's BPF.pid_tgid", callee, len(as))
			return nil
		}
		return &Expr{Kind: "pidtgid", Iv: iv(new(big.Int), new(big.Int).Set(u64Max)), Wide: true, Pos: p}
	}
	if name == "ktime_ns" && constName(c.a, recv) == "BPF" {
		callee, ok := c.callee(n)
		if !ok {
			return nil
		}
		if callee != "BPF.ktime_ns" || len(as) != 0 {
			c.add(Rejected, SB011ShadowedName, n, "`BPF.ktime_ns` resolves to %q (with %d arguments), not the library's BPF.ktime_ns", callee, len(as))
			return nil
		}
		return &Expr{Kind: "ktime", Iv: iv(new(big.Int), new(big.Int).Set(u64Max)), Wide: true, Pos: p}
	}
	if name == "**" {
		c.add(Rejected, SB001UnsupportedConstruct, n, "`**` is outside the eBPF side")
		return nil
	}
	isOp := binOps[name] || cmpOps[name] || name == "-@" || name == "~" || name == "!"
	if !isOp && name == "new" && c.z.records[constName(c.a, recv)] != nil {
		c.add(Rejected, SB024RecordShape, n, "a record value `%s.new(…)` is written directly as the argument of the map / ring buffer call that takes it (key, value or event) — it is not kept in a local or used as another value (bpf-mlir: a record.make result does not cross blocks)", constName(c.a, recv))
		return nil
	}
	if fi := c.z.userCall(c.a, n); fi != nil && !isOp {
		return c.subCall(n, fi, refVar)
	}
	if !isOp {
		c.add(Rejected, SB002UnsupportedCall, n, "call `%s` is not accepted on the eBPF side", name)
		return nil
	}
	if _, ok := c.calleeOp(n, !mutation("no-member-recv") && c.memberRead(recv)); !ok {
		return nil
	}
	switch name {
	case "!":
		x := c.cond(recv, refVar)
		if x == nil {
			return nil
		}
		return &Expr{Kind: "not", Args: []*Expr{x}, Bool: true, Pos: p}
	case "-@", "~":
		x := c.intExpr(recv, refVar)
		if x == nil {
			return nil
		}
		e := &Expr{Kind: "un", Op: name, Args: []*Expr{x}, Pos: p}
		if name == "-@" {
			e.Iv = ivNeg(x.Iv)
		} else {
			e.Iv = ivNot(x.Iv)
		}
		if !c.fits(n, e) {
			return nil
		}
		return e
	}
	if len(as) != 1 {
		c.add(Rejected, SB001UnsupportedConstruct, n, "operator `%s` takes one operand", name)
		return nil
	}
	if cmpOps[name] {
		l, r := c.intExpr(recv, refVar), c.intExpr(as[0], refVar)
		if l == nil || r == nil {
			return nil
		}
		return &Expr{Kind: "cmp", Op: name, Args: []*Expr{l, r}, Bool: true, Pos: p}
	}
	l := c.expr(recv, refVar)
	r := c.expr(as[0], refVar)
	if l == nil || r == nil {
		return nil
	}
	return c.binary(n, name, l, r, as[0])
}

func (c *progCtx) intExpr(n *Node, refVar string) *Expr {
	e := c.expr(n, refVar)
	if e == nil {
		return nil
	}
	if e.Bool {
		c.add(Rejected, SB001UnsupportedConstruct, n, "an Integer is needed here, got a bool")
		return nil
	}
	if e.Wide {
		c.valueOK(e, n)
		return nil
	}
	return e
}

func (c *progCtx) fits(n *Node, e *Expr) bool {
	if mutation("no-overflow") {
		if !e.Iv.fitsI64() {
			e.Iv = fullI64
		}
		return true
	}
	if !e.Iv.fitsI64() {
		c.add(Rejected, SB014SemanticGap, n, "`%s` may overflow: its value range %s does not fit a 64-bit Integer (Ruby grows / Spinel raises RangeError, BPF wraps) — narrow the operands (e.g. `x & 0xFFFF_FFFF`)", e.Op, e.Iv)
		return false
	}
	return true
}

func (c *progCtx) binary(n *Node, op string, l, r *Expr, rn *Node) *Expr {
	p := c.z.pos(c.a, n)
	if l.Bool || r.Bool {
		c.add(Rejected, SB001UnsupportedConstruct, n, "operator `%s` needs Integer operands", op)
		return nil
	}
	e := &Expr{Kind: "bin", Op: op, Args: []*Expr{l, r}, Pos: p}
	constRight := func(what string) (*big.Int, bool) {
		v, ok := r.Iv.isPoint()
		if !ok || r.Kind != "lit" {
			c.add(Rejected, SB006NonConstant, rn, "the %s of `%s` must be an integer literal", what, op)
			return nil, false
		}
		return v, true
	}
	switch op {
	case "&":
		if l.Wide {
			m, ok := constRight("mask")
			if !ok {
				return nil
			}
			if m.Sign() < 0 {
				c.add(Rejected, SB014SemanticGap, rn, "a u64 map value may be masked only with a non-negative literal")
				return nil
			}
			e.Iv = iv(new(big.Int), new(big.Int).Set(m))
			return e
		}
		if r.Wide {
			c.add(Rejected, SB014SemanticGap, n, "write the u64 map value on the left of `&` with a literal mask (`p.load & M`)")
			return nil
		}
		e.Iv = ivBit(op, l.Iv, r.Iv)
	case "|", "^":
		if l.Wide || r.Wide {
			if l.Wide {
				c.valueOK(l, n)
			} else {
				c.valueOK(r, n)
			}
			return nil
		}
		e.Iv = ivBit(op, l.Iv, r.Iv)
	case "<<", ">>":
		if r.Wide {
			c.valueOK(r, n)
			return nil
		}
		k, ok := constRight("shift count")
		if !ok {
			return nil
		}
		if k.Sign() < 0 || k.Cmp(big.NewInt(63)) > 0 {
			c.add(Rejected, SB014SemanticGap, rn, "shift count %s is outside [0, 63] (Ruby shifts the other way / to 0 or −1, BPF is poison)", k)
			return nil
		}
		sh := uint(k.Int64())
		f := new(big.Int).Lsh(bigOne, sh)
		if l.Wide {
			if op != ">>" || sh == 0 {
				c.valueOK(l, n)
				return nil
			}
			e.Iv = iv(new(big.Int), new(big.Int).Rsh(u64Max, sh))
			return e
		}
		if op == "<<" {
			e.Iv = iv(new(big.Int).Mul(l.Iv.Lo, f), new(big.Int).Mul(l.Iv.Hi, f))
		} else {
			e.Iv = iv(floorDiv(l.Iv.Lo, f), floorDiv(l.Iv.Hi, f))
		}
	case "/", "%":
		if l.Wide || r.Wide {
			if l.Wide {
				c.valueOK(l, n)
			} else {
				c.valueOK(r, n)
			}
			return nil
		}
		d, ok := constRight("divisor")
		if !ok {
			return nil
		}
		if d.Sign() == 0 {
			c.add(Rejected, SB014SemanticGap, rn, "division by zero (Ruby raises ZeroDivisionError)")
			return nil
		}
		switch {
		case l.Iv.nonNeg() && d.Sign() > 0:
			e.Div = "u"
			if op == "/" {
				e.Iv = iv(new(big.Int).Quo(l.Iv.Lo, d), new(big.Int).Quo(l.Iv.Hi, d))
			} else {
				hi := new(big.Int).Sub(d, bigOne)
				if l.Iv.Hi.Cmp(hi) < 0 {
					hi = new(big.Int).Set(l.Iv.Hi)
				}
				e.Iv = iv(new(big.Int), hi)
			}
		case isPow2Mag(d):
			e.Div = "floor"
			if op == "/" {
				e.Iv = minMax(floorDiv(l.Iv.Lo, d), floorDiv(l.Iv.Hi, d))
			} else if d.Sign() > 0 {
				e.Iv = iv(new(big.Int), new(big.Int).Sub(d, bigOne))
			} else {
				e.Iv = iv(new(big.Int).Add(d, bigOne), new(big.Int))
			}
		default:
			c.add(Rejected, SB014SemanticGap, n, "`%s %s` with a possibly negative dividend %s needs a divisor of ±2^k (Ruby floors; bpf-mlir divides i64 signed only by ±2^k)", op, d, l.Iv)
			return nil
		}
	default:
		if l.Wide || r.Wide {
			if l.Wide {
				c.valueOK(l, n)
			} else {
				c.valueOK(r, n)
			}
			return nil
		}
		switch op {
		case "+":
			e.Iv = ivAdd(l.Iv, r.Iv)
		case "-":
			e.Iv = ivSub(l.Iv, r.Iv)
		case "*":
			e.Iv = ivMul(l.Iv, r.Iv)
		}
	}
	if !c.fits(n, e) {
		return nil
	}
	return e
}

func (c *progCtx) memberRead(n *Node) bool {
	if n == nil || n.Type != "CallNode" || len(args(c.a, n)) != 0 || c.a.ref(n, "block") != nil {
		return false
	}
	ld := c.a.ref(n, "receiver")
	if ld == nil || ld.Type != "CallNode" || ld.Str["name"] != "load" || len(args(c.a, ld)) != 0 || c.a.ref(ld, "block") != nil {
		return false
	}
	p := c.a.ref(ld, "receiver")
	if p == nil || p.Type != "LocalVariableReadNode" || c.refs[p.Str["name"]] == nil {
		return false
	}
	m := c.refMap[p.Str["name"]]
	if m == nil || m.Record == nil {
		return false
	}
	f := m.Record.Field(n.Str["name"])
	return f != nil && !f.Pad
}

func (c *progCtx) hasMemberRead(n *Node) bool {
	found := false
	walk(c.a, n, func(x *Node) bool {
		if !found && c.memberRead(x) {
			found = true
		}
		return !found
	})
	return found
}

func (c *progCtx) calleeOp(n *Node, memberRecv bool) (string, bool) {
	if !memberRecv {
		return c.callee(n)
	}
	if !c.typed(n) {
		return "", false
	}
	cg, cnt := c.t.CodegenOf(c.a, n)
	name := n.Str["name"]
	if cnt != 1 {
		c.add(Unknown, SB004UnknownEdge, n, "Spinel placed no single call for `%s` (%d codegen records) — the target cannot be resolved statically", name, cnt)
		return "", false
	}
	if cg.Callee != "" {
		c.add(Rejected, SB009OperatorRedefined, n, "operator `%s` resolves to the user definition %s — redefined operators are refused", name, cg.Callee)
		return "", false
	}
	if cg.Dispatch != "direct" && cg.Dispatch != "boxed" {
		c.add(Unknown, SB004UnknownEdge, n, "`%s` is dispatched dynamically (%s %v) — the eBPF side needs a static call target", name, cg.Dispatch, cg.Candidates)
		return "", false
	}
	return "", true
}

func (c *progCtx) callee(n *Node) (string, bool) {
	if !c.typed(n) {
		return "", false
	}
	cg, cnt := c.t.CodegenOf(c.a, n)
	name := n.Str["name"]
	if cnt != 1 {
		c.add(Unknown, SB004UnknownEdge, n, "Spinel placed no single call for `%s` (%d codegen records) — the target cannot be resolved statically", name, cnt)
		return "", false
	}
	if operators[name] && cg.Callee != "" {
		c.add(Rejected, SB009OperatorRedefined, n, "operator `%s` resolves to the user definition %s — redefined operators are refused", name, cg.Callee)
		return "", false
	}
	if cg.Dispatch != "direct" {
		hint := ""
		if operators[name] && c.hasMemberRead(c.a.ref(n, "receiver")) {
			hint = "; for an operator on a record member's arithmetic, assign it to a local first (`x = p.load.m & 0xFF`, then `x + 1`)"
		}
		c.add(Unknown, SB004UnknownEdge, n, "`%s` is dispatched dynamically (%s %v) — the eBPF side needs a static call target%s", name, cg.Dispatch, cg.Candidates, hint)
		return "", false
	}
	return cg.Callee, true
}

func (c *progCtx) mapOf(recv *Node, call *Node) *MapDecl {
	if recv != nil && !c.typed(recv) {
		return nil
	}
	cn := constName(c.a, recv)
	m := c.z.maps[cn]
	if m == nil && c.z.badMaps[cn] {
		return nil
	}
	if m == nil || recv.Type != "ConstantReadNode" {
		c.add(Rejected, SB002UnsupportedCall, call, "`%s` needs a map declared at the top level (`X = BPF::ArrayMap.new(\"X\", …)`) as its receiver", call.Str["name"])
		return nil
	}
	wantT := m.ClassName()
	if c.rbs(recv) != wantT {
		c.add(Rejected, SB011ShadowedName, recv, "map %s is typed %q, not BPF::%s", cn, c.rbs(recv), wantT)
		return nil
	}
	c.used[m] = true
	return m
}

func typeRange(m *MapDecl) Ival {
	switch {
	case m.ValueBits == 32 && !m.Signed:
		return iv(new(big.Int), new(big.Int).Set(u32Max))
	case m.ValueBits == 32:
		return iv(new(big.Int).Set(i32Min), new(big.Int).Set(i32Max))
	case m.Signed:
		return fullI64
	}
	return iv(new(big.Int), new(big.Int).Set(i64Max))
}

func (c *progCtx) key(n *Node, m *MapDecl, refVar string) *Expr {
	if m.IsHash() {
		return c.hashKey(n, m, refVar)
	}
	e := c.expr(n, refVar)
	if e == nil {
		return nil
	}
	if e.Bool || e.Wide {
		c.add(Rejected, SB001UnsupportedConstruct, n, "a map key must be an Integer (not a bool, not an unnarrowed u64 value)")
		return nil
	}
	max := new(big.Int).SetUint64(m.MaxEntries - 1)
	if !e.Iv.within(bigZero, max) {
		if e.Kind == "lit" && (e.Lit.Cmp(u32Max) > 0 || e.Lit.Sign() < 0) {
			c.add(Rejected, SB014SemanticGap, n, "the key literal %s is outside [0, %s] (u32 on the eBPF side; Ruby would not wrap it)", e.Lit, u32Max)
			return nil
		}
		c.add(Rejected, SB020KeyOutOfRange, n, "the key's range %s is not within [0, %d] of map %s — an out-of-range array update fails silently; narrow it (e.g. `k %% %d`, `k & M`)", e.Iv, m.MaxEntries-1, m.Name, m.MaxEntries)
		return nil
	}
	return e
}

func (c *progCtx) value(n *Node, m *MapDecl, refVar string, role string) *Expr {
	e := c.expr(n, refVar)
	if e == nil {
		return nil
	}
	if e.Bool {
		c.add(Rejected, SB001UnsupportedConstruct, n, "a bool cannot be stored in a map (%s)", role)
		return nil
	}
	if e.Wide {
		if m.ValueBits == 64 && !m.Signed && (e.Kind == "load" || e.Kind == "ktime" || e.Kind == "pidtgid" || e.Kind == "retval" || e.Kind == "kparg" || e.Kind == "rawarg" || e.Kind == "tpfield" || e.Kind == "gload" || e.Kind == "kfload") {
			return e
		}
		c.valueOK(e, n)
		return nil
	}
	tr := typeRange(m)
	if !e.Iv.within(tr.Lo, tr.Hi) {
		if e.Kind == "lit" {
			c.add(Rejected, SB014SemanticGap, n, "the %s literal %s is outside %s (%s on the eBPF side; Ruby would not wrap it)", role, e.Lit, tr, m.TypeName())
		} else {
			c.add(Rejected, SB014SemanticGap, n, "the %s's range %s does not fit map %s's %s values %s — the store would truncate silently; narrow it (e.g. `& 0xFFFF_FFFF`)", role, e.Iv, m.Name, m.TypeName(), tr)
		}
		return nil
	}
	return e
}

func (c *progCtx) rmwFirst(n, val *Node, m *MapDecl, k *Expr, msg func(ref string) string) bool {
	c.noteFlow(val, m, n)
	if k == nil || c.exempt(m) {
		return false
	}
	for _, ref := range sortedSet(c.derivedRefs(val)) {
		if c.refMap[ref] != m {
			continue
		}
		if lk := c.refKey[ref]; lk != nil && lk.Kind == "lit" && k.Kind == "lit" && lk.Lit.Cmp(k.Lit) != 0 {
			continue
		}
		c.add(Rejected, SB019SharedReadModifyWrite, n, "%s", msg(ref))
		return true
	}
	return false
}

func (c *progCtx) derivedRefs(n *Node) map[string]bool {
	out := map[string]bool{}
	walk(c.a, n, func(x *Node) bool {
		if c.z.funcs != nil && c.z.userCall(c.a, x) != nil {
			out[fmt.Sprintf("@r%d", x.ID)] = true
			return false
		}
		if g := c.counterRead(x); g != nil && !mutation("no-counter-rmw") {
			out["@g"+g.Const] = true
			return false
		}
		if x.Type != "LocalVariableReadNode" {
			return true
		}
		name := x.Str["name"]
		if c.refs[name] != nil {
			out[name] = true
		} else if info := c.env[name]; info != nil {
			for r := range info.From {
				out[r] = true
			}
		}
		return true
	})
	return out
}

func (c *progCtx) origin(n *Node) map[string]bool {
	if mutation("no-origin") {
		return nil
	}
	return c.derivedRefs(n)
}

func (c *progCtx) readsRefVia(n *Node, ref string) bool {
	return c.derivedRefs(n)[ref]
}

func unionRefs(a, b map[string]bool) map[string]bool {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func sortedSet(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func readsMap(e *Expr, m *MapDecl) (string, bool) {
	if e == nil {
		return "", false
	}
	if (e.Kind == "load" || e.Kind == "fload") && e.Map == m {
		return e.Ref, true
	}
	for _, a := range e.Args {
		if r, ok := readsMap(a, m); ok {
			return r, true
		}
	}
	return "", false
}

func (c *progCtx) mapCall(n *Node, refVar string) (Stmt, bool) {
	name := n.Str["name"]
	if r := c.a.ref(n, "receiver"); r != nil && r.Type == "ConstantReadNode" {
		if g := c.z.globals[r.Str["name"]]; g != nil {
			if name == "add" {
				return c.globalAdd(n, g, args(c.a, n), refVar)
			}
			c.add(Rejected, SB029GlobalShape, n, "a bare `%s.%s` statement — a global is read as `%s.value` in an expression, and a Counter adds with `%s.add(d)`", g.Const, name, g.Const, g.Const)
			return Stmt{}, false
		}
		if c.z.badGlobals[r.Str["name"]] {
			return Stmt{}, false
		}
	}
	if !hasPacket(c.prog.Kind) && c.isVarRead(c.a.ref(n, "receiver"), c.param) {
		c.add(Rejected, SB028TracingKind, n, "a bare `%s.%s` statement — the %s context is read only as a value (%s)", c.param, name, c.prog.Kind, ctxReads[c.prog.Kind])
		return Stmt{}, false
	}
	if c.prog.Kind == "flow_dissector" && name == "set_key" && c.isVarRead(c.a.ref(n, "receiver"), c.param) {
		return c.flowKeyStore(n, refVar)
	}
	if c.prog.Kind == "sched_cls" && name == "mark=" && c.isVarRead(c.a.ref(n, "receiver"), c.param) {
		return c.ctxStore(n, refVar)
	}
	if c.readsBad(n) {
		return Stmt{}, false
	}
	if dm := c.z.maps[constName(c.a, c.a.ref(n, "receiver"))]; dm != nil && dm.IsLpm() && name != "lookup" && name != "check" && !operators[name] {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.%s` is not accepted — an lpm_trie is read-only on the eBPF side (look it up with `p = %s.lookup(a0, a1, a2, a3)` then `if p`; user space writes it with `obj.lpm_put`)", dm.Const, name, dm.Const)
		return Stmt{}, false
	}
	if name != "atomic_add" && name != "update" {
		switch {
		case name == "lookup":
			c.add(Rejected, SB005RefCheckShape, n, "`lookup` must be assigned to a local and checked with `if` (`p = M.lookup(k)` then `if p`)")
		case name == "check":
			c.add(Rejected, SB005RefCheckShape, n, "`check` must be assigned to a local and checked with `if` (`w = %s.check(off, len)` then `if w` — no block form)", c.param)
		case operators[name]:
			c.add(Rejected, SB001UnsupportedConstruct, n, "a bare `%s` expression statement is not accepted", name)
		default:
			c.add(Rejected, SB002UnsupportedCall, n, "call `%s` is not accepted on the eBPF side", name)
		}
		return Stmt{}, false
	}
	if dm := c.z.maps[constName(c.a, c.a.ref(n, "receiver"))]; dm != nil && dm.IsHash() && name == "atomic_add" {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.atomic_add(k, d)` is not accepted on a hash map — a missing key makes it do nothing silently; use `st = %s.add_or_init(k, d)` (adds, or creates the entry), or `p.atomic_add(d)` inside `if p` after `p = %s.lookup(k)`", dm.Const, dm.Const, dm.Const)
		return Stmt{}, false
	}
	if c.z.badHash[constName(c.a, c.a.ref(n, "receiver"))] && name == "atomic_add" {
		return Stmt{}, false
	}
	if dm := c.z.maps[constName(c.a, c.a.ref(n, "receiver"))]; dm != nil && dm.Record != nil && name == "atomic_add" {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.atomic_add` is not accepted on a record map — add to a member with `p = %s.lookup(k)`, `if p`, `p.atomic_add(:member, d)`", dm.Const, dm.Const)
		return Stmt{}, false
	}
	callee, ok := c.callee(n)
	if !ok {
		return Stmt{}, false
	}
	wantC := "ArrayMap"
	if dm := c.z.maps[constName(c.a, c.a.ref(n, "receiver"))]; dm != nil {
		wantC = dm.ClassName()
	}
	if callee != wantC+"#"+name && !(wantC == "ArrayMap" && callee == "RecordMap#"+name) {
		c.add(Rejected, SB011ShadowedName, n, "`%s` resolves to %s, not BPF::%s#%s", name, callee, wantC, name)
		return Stmt{}, false
	}
	m := c.mapOf(c.a.ref(n, "receiver"), n)
	as := args(c.a, n)
	if m == nil {
		return Stmt{}, false
	}
	if m.Record != nil {
		return c.recordUpdate(n, name, m, as, refVar)
	}
	if len(as) != 2 || c.a.ref(n, "block") != nil {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s` takes exactly two arguments (key, %s)", name, map[string]string{"atomic_add": "delta", "update": "value"}[name])
		return Stmt{}, false
	}
	role := map[string]string{"atomic_add": "delta", "update": "value"}[name]
	k := c.key(as[0], m, refVar)
	if name == "atomic_add" && c.rmwFirst(n, as[1], m, k, func(ref string) string {
		return fmt.Sprintf("`%s.atomic_add` adds a value read from the same entry (`%s.load`) — concurrent CPUs interleave the read and the add; use a delta that does not read the map (keys must be different literals to accept this form)", m.Name, ref)
	}) {
		return Stmt{}, false
	}
	if name == "update" && c.rmwFirst(n, as[1], m, k, func(ref string) string {
		return fmt.Sprintf("`%s.update` stores a value read from the same map (`%s.load`) — concurrent CPUs lose updates; use `%s.atomic_add` (keys must be different literals to accept this form)", m.Name, ref, m.Name)
	}) {
		return Stmt{}, false
	}
	v := c.value(as[1], m, refVar, role)
	if k == nil || v == nil {
		return Stmt{}, false
	}
	if ref, ok := readsMap(v, m); ok && name == "update" && !c.exempt(m) {
		lk := c.refKey[ref]
		if lk == nil || lk.Kind != "lit" || k.Kind != "lit" || lk.Lit.Cmp(k.Lit) == 0 {
			c.add(Rejected, SB019SharedReadModifyWrite, n, "`%s.update` stores a value read from the same map (`%s.load`) — concurrent CPUs lose updates; use `%s.atomic_add` (keys must be different literals to accept this form)", m.Name, ref, m.Name)
			return Stmt{}, false
		}
	}
	return Stmt{Kind: name, Map: m, Key: k, Value: v, Pos: c.z.pos(c.a, n)}, true
}

func (c *progCtx) lookupCheck(w, ifn *Node, outerRef string) (Stmt, bool) {
	name := w.Str["name"]
	call := c.a.ref(w, "value")
	if _, dup := c.refs[name]; dup {
		c.add(Rejected, SB005RefCheckShape, w, "`%s` is assigned twice — a lookup result is bound once", name)
		return Stmt{}, false
	}
	if _, used := c.env[name]; used || name == c.param || c.wins[name] != nil {
		c.add(Rejected, SB005RefCheckShape, w, "`%s` is already a local — a lookup result needs a fresh name", name)
		return Stmt{}, false
	}
	callee, ok := c.callee(call)
	if !ok {
		return Stmt{}, false
	}
	mapT, refT := "ArrayMap", "MapRef"
	dm := c.z.maps[constName(c.a, c.a.ref(call, "receiver"))]
	if dm != nil {
		mapT = dm.ClassName()
		if dm.Record != nil {
			refT = "RecordRef"
		}
	}
	if dm == nil && c.z.badMaps[constName(c.a, c.a.ref(call, "receiver"))] {
		return Stmt{}, false
	}
	if callee == "RecordMap#lookup" && mapT != "RecordMap" {
		return Stmt{}, false
	}
	if callee != mapT+"#lookup" {
		c.add(Rejected, SB011ShadowedName, call, "`lookup` resolves to %s, not BPF::%s#lookup", callee, mapT)
		return Stmt{}, false
	}
	m := c.mapOf(c.a.ref(call, "receiver"), call)
	as := args(c.a, call)
	if m == nil {
		return Stmt{}, false
	}
	if m.IsLpm() && len(as) != 4 {
		c.lpmKey(call, m, as, outerRef)
		return Stmt{}, false
	}
	if !m.IsLpm() && len(as) != 1 {
		c.add(Rejected, SB002UnsupportedCall, call, "`lookup` takes exactly one argument (key)")
		return Stmt{}, false
	}
	if !c.typed(w) || !c.typed(c.a.ref(ifn, "predicate")) {
		return Stmt{}, false
	}
	if c.rbs(w) != refT {
		c.add(Rejected, SB005RefCheckShape, w, "`%s` is typed %q, not BPF::%s", name, c.rbs(w), refT)
		return Stmt{}, false
	}
	var k *Expr
	if m.IsLpm() {
		k = c.lpmKey(call, m, as, outerRef)
	} else {
		k = c.key(as[0], m, outerRef)
	}
	if k == nil {
		return Stmt{}, false
	}
	c.refs[name] = w
	c.refMap[name] = m
	c.refKey[name] = k
	s := Stmt{Kind: "lookup_check", Map: m, Key: k, Var: name, Pos: c.z.pos(c.a, w), IfPos: c.z.pos(c.a, ifn)}
	var then []*Node
	if st := c.a.ref(ifn, "statements"); st != nil {
		then = c.a.arr(st, "body")
	}
	pre := c.env
	c.env = copyEnv(pre)
	savedArm := c.escArm
	if c.escArm != "window" {
		c.escArm = "if"
	}
	defer func() { c.escArm = savedArm }()
	s.Then = c.stmts(then, name)
	thenEnv := c.env
	c.env = copyEnv(pre)
	if sub := c.a.ref(ifn, "subsequent"); sub != nil {
		if sub.Type != "ElseNode" {
			c.add(Rejected, SB005RefCheckShape, sub, "`elsif` is not accepted after `if %s`", name)
			return Stmt{}, false
		}
		var els []*Node
		if st := c.a.ref(sub, "statements"); st != nil {
			els = c.a.arr(st, "body")
		}
		s.Else = c.stmts(els, outerRef)
	}
	c.env = joinArms(pre, thenEnv, c.env, escapes(s.Then), escapes(s.Else))
	walk(c.a, c.def, func(x *Node) bool {
		if x.Type != "LocalVariableReadNode" || x.Str["name"] != name {
			return true
		}
		if x == c.a.ref(ifn, "predicate") || c.inSkippedIf(x) || c.inRebindIf(x, name, w) {
			return true
		}
		parent := c.a.node(c.a.Parent[x.ID])
		if c.borrowArgUse(x) && inIf(c.a, x, ifn) {
			return true
		}
		if m.Record != nil {
			if parent != nil && parent.Type == "CallNode" && c.a.ref(parent, "receiver") == x && inIf(c.a, parent, ifn) {
				if parent.Str["name"] == "atomic_add" {
					return true
				}
				gp := c.a.node(c.a.Parent[parent.ID])
				if parent.Str["name"] == "load" && gp != nil && gp.Type == "CallNode" && c.a.ref(gp, "receiver") == parent && m.Record.Field(strings.TrimSuffix(gp.Str["name"], "=")) != nil {
					return true
				}
				if parent.Str["name"] == "load" && gp != nil && strings.HasPrefix(gp.Type, "Call") && strings.HasSuffix(gp.Type, "WriteNode") && c.a.ref(gp, "receiver") == parent {
					return true
				}
				if parent.Str["name"] == "load" && gp != nil && gp.Type == "CallNode" && c.a.ref(gp, "receiver") == parent && memberLike(gp.Str["name"]) {
					return true
				}
			}
			c.add(Rejected, SB005RefCheckShape, x, "`%s` may be read only as `if %s`, `%s.load.<member>` / `%s.load.<member> = e` and `%s.atomic_add(:member, d)` inside it — `%s.load` is not a value (no local, dup, comparison or argument: the kernel side writes the map entry directly)", name, name, name, name, name, name)
			return true
		}
		if parent != nil && parent.Type == "CallNode" && (parent.Str["name"] == "load" || parent.Str["name"] == "atomic_add") && c.a.ref(parent, "receiver") == x && inIf(c.a, parent, ifn) {
			return true
		}
		c.add(Rejected, SB005RefCheckShape, x, "`%s` may be read only as `if %s` and as `%s.load` / `%s.atomic_add(d)` inside it", name, name, name, name)
		return true
	})
	return s, true
}

func inIf(a *AST, x, ifn *Node) bool {
	st := a.ref(ifn, "statements")
	for p := x.ID; ; {
		pid, ok := a.Parent[p]
		if !ok {
			return false
		}
		if st != nil && pid == st.ID {
			return true
		}
		if pid == ifn.ID {
			return false
		}
		p = pid
	}
}

func (c *progCtx) verdict(n *Node) {
	v := n
	if n.Type == "ReturnNode" {
		var as []*Node
		if args := c.a.ref(n, "arguments"); args != nil {
			as = c.a.arr(args, "arguments")
		}
		if len(as) != 1 {
			c.add(Rejected, SB008ProgramShape, n, "`return` must return one %s", verdictWant(c.prog.Kind, "BPF::XDP_* constant"))
			return
		}
		v = as[0]
	}
	if c.isFmodReturn(v) {
		c.fmodVerdict(n, v)
		c.rejectMidReturns(n)
		return
	}
	if v.Type == "CallNode" && v.Str["name"] == "redirect" {
		c.redirectVerdict(n, v)
		return
	}
	cn := constName(c.a, v)
	table := verdictsOf(c.prog.Kind)
	if v.Type != "ConstantPathNode" || len(cn) < 5 || cn[:5] != "BPF::" || table[cn[5:]] == "" {
		c.add(Rejected, SB008ProgramShape, n, "the program must end with %s, got %s", verdictWant(c.prog.Kind, "an XDP verdict (BPF::XDP_ABORTED / XDP_DROP / XDP_PASS / XDP_TX)"), n.Type)
		return
	}
	if !c.typed(v) {
		return
	}
	if c.rbs(v) != "Integer" {
		c.add(Rejected, SB011ShadowedName, v, "%s is typed %q, not the Integer constant of ruby/lib/bpf.rb", cn, c.rbs(v))
		return
	}
	c.prog.Verdict = table[cn[5:]]
	c.prog.VerdictConst = cn[5:]
	c.prog.VerdictPos = c.z.pos(c.a, n)
	c.rejectMidReturns(n)
}

func (c *progCtx) rejectMidReturns(n *Node) {
	walk(c.a, c.def, func(x *Node) bool {
		if x.Type == "ReturnNode" && x != n && !c.guardReturns[x] {
			c.add(Rejected, SB008ProgramShape, x, "`return` is accepted only as the last statement or as a top-level guard %s", verdictWant(c.prog.Kind, "`return BPF::XDP_X if cond`"))
		}
		return true
	})
}

func condAssign(a *AST, n *Node) *Node {
	for n != nil && n.Type == "ParenthesesNode" {
		b := a.ref(n, "body")
		if b == nil || b.Type != "StatementsNode" || len(b.Arr["body"]) != 1 {
			return nil
		}
		n = a.arr(b, "body")[0]
	}
	if n != nil && n.Type == "LocalVariableWriteNode" {
		return n
	}
	return nil
}

func (c *progCtx) literalArg(n *Node, what string) (*big.Int, bool) {
	if n == nil || n.Type != "IntegerNode" {
		c.add(Rejected, SB006NonConstant, n, "the %s must be an integer literal", what)
		return nil, false
	}
	if !c.typed(n) {
		return nil, false
	}
	return c.z.literal(c.a, n)
}

func (c *progCtx) windowCheck(w, ifn *Node, outerRef string) (Stmt, bool) {
	name := w.Str["name"]
	call := c.a.ref(w, "value")
	if _, dup := c.wins[name]; dup || c.refs[name] != nil {
		c.add(Rejected, SB005RefCheckShape, w, "`%s` is assigned twice — a window is bound once", name)
		return Stmt{}, false
	}
	if _, used := c.env[name]; used || name == c.param {
		c.add(Rejected, SB005RefCheckShape, w, "`%s` is already a local — a window needs a fresh name", name)
		return Stmt{}, false
	}
	if c.a.ref(call, "block") != nil {
		c.add(Rejected, SB005RefCheckShape, call, "`check` takes no block — write `%s = %s.check(off, len)` then `if %s`", name, c.param, name)
		return Stmt{}, false
	}
	callee, ok := c.callee(call)
	if !ok {
		return Stmt{}, false
	}
	if want := ctxClass[c.ctxKindOf()] + "#check"; callee != want {
		c.add(Rejected, SB011ShadowedName, call, "`check` resolves to %s, not BPF::%s", callee, want)
		return Stmt{}, false
	}
	as := args(c.a, call)
	if len(as) != 2 {
		c.add(Rejected, SB002UnsupportedCall, call, "`check` takes exactly two arguments (offset, length)")
		return Stmt{}, false
	}
	if !c.typed(w) || !c.typed(c.a.ref(ifn, "predicate")) {
		return Stmt{}, false
	}
	if c.rbs(w) != "Window" {
		why := ""
		writes := 0
		walk(c.a, c.def, func(x *Node) bool {
			if (x.Type == "LocalVariableWriteNode" || x.Type == "LocalVariableOperatorWriteNode") && x.Str["name"] == name {
				writes++
			}
			return true
		})
		if writes > 1 {
			why = fmt.Sprintf(" — `%s` is reassigned elsewhere in `%s` (%d assignments), which makes Spinel widen its type; a window is bound once", name, c.name, writes)
		}
		c.add(Rejected, SB005RefCheckShape, w, "`%s` is typed %q, not BPF::Window%s", name, c.rbs(w), why)
		return Stmt{}, false
	}
	nv, ok := c.literalArg(as[1], "window length")
	if !ok {
		return Stmt{}, false
	}
	if nv.Cmp(big.NewInt(1)) < 0 || nv.Cmp(big.NewInt(65535)) > 0 {
		c.add(Rejected, SB022WindowIndex, as[1], "the window length %s is outside [1, 65535]", nv)
		return Stmt{}, false
	}
	n := nv.Int64()
	off := c.expr(as[0], outerRef)
	if off == nil {
		return Stmt{}, false
	}
	if off.Bool || off.Wide {
		c.add(Rejected, SB001UnsupportedConstruct, as[0], "the window offset must be an Integer (not a bool, not an unnarrowed u64 value)")
		return Stmt{}, false
	}
	hi := big.NewInt(65535 - n)
	if !mutation("no-offset-range") && !off.Iv.within(bigZero, hi) {
		c.add(Rejected, SB023PacketOffset, as[0], "the window offset's range %s is not within [0, %s] (65535 − %d) — a negative offset does not count from the end of the packet (unlike Ruby's a[-1]) and would silently give nil, Ruby does not wrap, and a packet offset beyond 0xffff has no meaning; narrow it (e.g. `x & 0xFFF`)", off.Iv, hi, n)
		return Stmt{}, false
	}
	info := &winInfo{len: n}
	c.wins[name] = info
	s := Stmt{Kind: "window_check", Var: name, Off: off, Len: n, Pos: c.z.pos(c.a, w), IfPos: c.z.pos(c.a, ifn)}
	var then []*Node
	if st := c.a.ref(ifn, "statements"); st != nil {
		then = c.a.arr(st, "body")
	}
	pre := c.env
	c.env = copyEnv(pre)
	info.active = true
	savedArm := c.escArm
	c.escArm = "window"
	defer func() { c.escArm = savedArm }()
	s.Then = c.stmts(then, outerRef)
	info.active = false
	thenEnv := c.env
	c.env = copyEnv(pre)
	if sub := c.a.ref(ifn, "subsequent"); sub != nil {
		if sub.Type != "ElseNode" {
			c.add(Rejected, SB005RefCheckShape, sub, "`elsif` is not accepted after `if %s`", name)
			return Stmt{}, false
		}
		var els []*Node
		if st := c.a.ref(sub, "statements"); st != nil {
			els = c.a.arr(st, "body")
		}
		s.Else = c.stmts(els, outerRef)
	}
	c.env = joinEnv(thenEnv, c.env)
	walk(c.a, c.def, func(x *Node) bool {
		if x.Type != "LocalVariableReadNode" || x.Str["name"] != name {
			return true
		}
		if x == c.a.ref(ifn, "predicate") || c.inSkippedIf(x) {
			return true
		}
		parent := c.a.node(c.a.Parent[x.ID])
		if c.borrowArgUse(x) && inIf(c.a, x, ifn) {
			return true
		}
		if parent != nil && parent.Type == "CallNode" && windowReads[parent.Str["name"]] > 0 && c.a.ref(parent, "receiver") == x && inIf(c.a, parent, ifn) {
			return true
		}
		if parent != nil && parent.Type == "CallNode" && windowReads[parent.Str["name"]] == 0 && c.a.ref(parent, "receiver") == x && inIf(c.a, parent, ifn) {
			return true
		}
		c.add(Rejected, SB005RefCheckShape, x, "window `%s` may be read only as `if %s` and as `%s.u8(i)` / `be16` / `be32` / `le16` / `le32` inside it", name, name, name)
		return true
	})
	return s, true
}

func (c *progCtx) windowRead(n, recv *Node, as []*Node) *Expr {
	name := n.Str["name"]
	if recv == nil || recv.Type != "LocalVariableReadNode" || c.wins[recv.Str["name"]] == nil {
		if recv != nil && c.isVarRead(recv, c.param) {
			c.add(Rejected, SB002UnsupportedCall, n, "the context has no `%s` — packet reads go through a checked window (`w = %s.check(off, len)`, `if w`, `w.%s(i)`)", name, c.param, name)
		} else {
			c.add(Rejected, SB002UnsupportedCall, n, "call `%s` is accepted only on a checked window", name)
		}
		return nil
	}
	wn := recv.Str["name"]
	info := c.wins[wn]
	if !info.active {
		return nil
	}
	callee, ok := c.callee(n)
	if !ok {
		return nil
	}
	if callee != "Window#"+name {
		c.add(Rejected, SB011ShadowedName, n, "`%s` resolves to %s, not BPF::Window#%s", name, callee, name)
		return nil
	}
	if len(as) != 1 {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s` takes exactly one argument (the index)", name)
		return nil
	}
	iv0, ok := c.literalArg(as[0], "window index")
	if !ok {
		return nil
	}
	width := windowReads[name]
	if iv0.Sign() < 0 || new(big.Int).Add(iv0, big.NewInt(width)).Cmp(big.NewInt(info.len)) > 0 {
		c.add(Rejected, SB022WindowIndex, as[0], "`%s.%s(%s)` reads bytes [%s, %s) outside the window [0, %d)", wn, name, iv0, iv0, new(big.Int).Add(iv0, big.NewInt(width)), info.len)
		return nil
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(bigOne, uint(8*width)), bigOne)
	return &Expr{Kind: "wload", Op: name, Ref: wn, Idx: iv0.Int64(), Len: info.len, Iv: iv(new(big.Int), max), Pos: c.z.pos(c.a, n)}
}

func (c *progCtx) readsBad(n *Node) bool {
	if n == nil {
		return false
	}
	found := false
	walk(c.a, n, func(x *Node) bool {
		if x.Type == "LocalVariableReadNode" && (c.badBind[x.Str["name"]] || (c.poisoned[x.Str["name"]] && c.env[x.Str["name"]] == nil)) {
			found = true
		}
		return !found
	})
	return found
}

func (c *progCtx) inSkippedIf(x *Node) bool {
	for p, ok := c.a.Parent[x.ID]; ok; p, ok = c.a.Parent[p] {
		if c.skipIfs[p] {
			return true
		}
	}
	return false
}

func (c *progCtx) inRebindIf(x *Node, name string, w *Node) bool {
	for p, ok := c.a.Parent[x.ID]; ok; p, ok = c.a.Parent[p] {
		ifn := c.a.node(p)
		if ifn == nil || ifn.Type != "IfNode" || !c.isVarRead(c.a.ref(ifn, "predicate"), name) {
			continue
		}
		st := c.a.node(c.a.Parent[ifn.ID])
		if st == nil || st.Type != "StatementsNode" {
			continue
		}
		body := c.a.arr(st, "body")
		for i := 1; i < len(body); i++ {
			if body[i] == ifn && body[i-1].Type == "LocalVariableWriteNode" && body[i-1].Str["name"] == name && body[i-1] != w {
				return true
			}
		}
	}
	return false
}

var ctxReads = map[string]string{
	"fentry":        "`ctx.arg(i)` (an integer argument declared in `BPF.fentry … args:`) and `q = ctx.kptr_or_null(i, T)` (a struct argument)",
	"fexit":         "`ctx.ret` (the declared return type)",
	"kprobe":        "`ctx.arg(n)` with n a declared parameter number (1..6)",
	"ksyscall":      "`ctx.arg(n)` with n a declared syscall argument number (1..6 — the syscall convention, the 4th is r10)",
	"kretprobe":     "`ctx.ret` (the declared return type — the return register; arguments are not readable on return)",
	"tracepoint":    "`ctx.field(:name)` with name a field declared in `BPF.tracepoint … fields:` (its declared type)",
	"raw_tp":        "`ctx.arg(i)` with i an Integer literal 0..11 (the tracepoint's args[i], 0-origin — a raw u64: narrow it with `x & M` / `x >> K` or store it in a u64 map)",
	"uretprobe":     "`ctx.ret` (the declared return type — the return register; arguments are not readable on return)",
	"uprobe":        "`ctx.arg(n)` (an integer parameter) and `ctx.str_arg(n)` (a :user_str parameter — only as the third argument of `R.output_str`) with n a declared parameter number (1..6)",
	"tp_btf":        "`t = ctx.kptr(i, T)` (a struct argument — then `t.load.m`) and `ctx.arg(i)` (an integer argument) with i declared in `BPF.tp_btf … args:`",
	"socket_filter": "`ctx.len` (the packet length, u32 — a socket_filter cannot read the packet itself in bpf-mlir v1.14.0)",
	"netfilter":     "`st = ctx.state(T)` (nf_hook_state) and `sk = ctx.skb(T)` (sk_buff) — then `st.load.hook` etc. (a netfilter program has no packet window)",
	"fmod_ret":      "`ctx.arg(i)` (an integer argument declared in `BPF.fmod_ret … args:`)",
}

func verdictWant(kind, xdp string) string {
	if kind == "fmod_ret" {
		switch xdp {
		case "`return BPF::XDP_X if cond`", "`return BPF::XDP_DROP if cond`":
			return "`return BPF.fmod_return(-1) if cond`"
		case "BPF::XDP_* constant":
			return "BPF::FMOD_CALL or BPF.fmod_return(literal)"
		}
		return "a named return value — BPF::FMOD_CALL (call the original function) or BPF.fmod_return(e) (e provably non-zero) — not an implicit last expression"
	}
	if kind == "socket_filter" {
		switch xdp {
		case "`return BPF::XDP_X if cond`", "`return BPF::XDP_DROP if cond`":
			return "`return BPF::SF_DROP if cond`"
		case "BPF::XDP_* constant":
			return "BPF::SF_* constant"
		}
		return "a socket_filter verdict (BPF::SF_KEEP / SF_DROP)"
	}
	if kind == "cgroup_skb" {
		switch xdp {
		case "`return BPF::XDP_X if cond`", "`return BPF::XDP_DROP if cond`":
			return "`return BPF::CG_DENY if cond`"
		case "BPF::XDP_* constant":
			return "BPF::CG_* constant"
		}
		return "a cgroup_skb verdict (BPF::CG_ALLOW / CG_DENY)"
	}
	if kind == "netfilter" {
		switch xdp {
		case "`return BPF::XDP_X if cond`", "`return BPF::XDP_DROP if cond`":
			return "`return BPF::NF_DROP if cond`"
		case "BPF::XDP_* constant":
			return "BPF::NF_* constant"
		}
		return "a netfilter verdict (BPF::NF_ACCEPT / NF_DROP)"
	}
	if kind == "flow_dissector" {
		switch xdp {
		case "`return BPF::XDP_X if cond`", "`return BPF::XDP_DROP if cond`":
			return "`return BPF::FLOW_DROP if cond`"
		case "BPF::XDP_* constant":
			return "BPF::FLOW_* constant"
		}
		return "a flow_dissector verdict (BPF::FLOW_OK / FLOW_DROP / FLOW_CONTINUE)"
	}
	if kind == "sk_lookup" {
		switch xdp {
		case "`return BPF::XDP_X if cond`", "`return BPF::XDP_DROP if cond`":
			return "`return BPF::SK_DROP if cond`"
		case "BPF::XDP_* constant":
			return "BPF::SK_* constant"
		}
		return "an sk_lookup verdict (BPF::SK_PASS / SK_DROP)"
	}
	if kind != "sched_cls" {
		return xdp
	}
	switch xdp {
	case "`return BPF::XDP_X if cond`", "`return BPF::XDP_DROP if cond`":
		return "`return BPF::TC_DROP if cond`"
	case "BPF::XDP_* constant":
		return "BPF::TC_* constant"
	}
	return "a sched_cls verdict (BPF::TC_PASS / TC_DROP)"
}

func ctxUse(kind, param string) string {
	if hasPacket(kind) {
		return fmt.Sprintf("`w = %s.check(off, len)` right before `if w`", param)
	}
	return ctxReads[kind]
}

func (c *progCtx) tracingRead(n *Node, name string, as []*Node, p Pos) *Expr {
	kind := c.prog.Kind
	callee, ok := c.callee(n)
	if !ok {
		return nil
	}
	typ := func(t string) *RecordField {
		rt := recordTypes[t]
		return &RecordField{Name: t, Bits: rt[0], Signed: rt[1] == 1}
	}
	mk := func(k string, f *RecordField, idx int64) *Expr {
		e := &Expr{Kind: k, Field: f, Idx: idx, Pos: p}
		if f.Bits == 64 && !f.Signed {
			e.Iv, e.Wide = iv(new(big.Int), new(big.Int).Set(u64Max)), true
		} else {
			e.Iv = widthRange(f.Bits, f.Signed)
		}
		return e
	}
	switch {
	case (kind == "socket_filter" && name == "len") || ctxFields[kind][name]:
		if want := ctxClass[kind] + "#" + name; callee != want || len(as) != 0 {
			c.add(Rejected, SB011ShadowedName, n, "`%s.%s` resolves to %q (with %d arguments), not BPF::%s", c.param, name, callee, len(as), want)
			return nil
		}
		return mk("ctxfield", &RecordField{Name: name, Bits: 32}, 0)
	case kind == "fexit" && name == "ret":
		if callee != "FexitCtx#ret" || len(as) != 0 {
			c.add(Rejected, SB011ShadowedName, n, "`%s.ret` resolves to %q (with %d arguments), not BPF::FexitCtx#ret", c.param, callee, len(as))
			return nil
		}
		return mk("retval", typ(c.prog.Ret), int64(c.prog.Nargs))
	case kind == "kretprobe" && name == "ret":
		if callee != "KretprobeCtx#ret" || len(as) != 0 {
			c.add(Rejected, SB011ShadowedName, n, "`%s.ret` resolves to %q (with %d arguments), not BPF::KretprobeCtx#ret", c.param, callee, len(as))
			return nil
		}
		return mk("kretval", typ(c.prog.Ret), 0)
	case kind == "uretprobe" && name == "ret":
		if callee != "UretprobeCtx#ret" || len(as) != 0 {
			c.add(Rejected, SB011ShadowedName, n, "`%s.ret` resolves to %q (with %d arguments), not BPF::UretprobeCtx#ret", c.param, callee, len(as))
			return nil
		}
		return mk("kretval", typ(c.prog.Ret), 0)
	case (kind == "ksyscall" && name == "argv_arg") || (kind == "tracepoint" && name == "argv_field"):
		c.add(Rejected, SB028TracingKind, n, "`%s.%s(…)` is accepted only as the third argument of `R.output_argv(S.new(…), :arg, %s.%s(…), :status, :index)` — an argv array is not a value on the eBPF side", c.param, name, c.param, name)
		return nil
	case kind == "ksyscall" && name == "str_arg":
		c.add(Rejected, SB028TracingKind, n, "`%s.str_arg(n)` is accepted only as the third argument of `R.output_str(S.new(…), :field, %s.str_arg(n), :status)` — a user string is not a value on the eBPF side", c.param, c.param)
		return nil
	case kind == "tracepoint" && name == "copy":
		c.add(Rejected, SB028TracingKind, n, "`%s.copy(:f)` (a byte array field) is not a value — it is accepted only as an array member's argument of `R.output(S.new(…))` or as `r.load.<member> = %s.copy(:f)` inside `if r` of a record map's lookup", c.param, c.param)
		return nil
	case kind == "tracepoint" && name == "str_field":
		c.add(Rejected, SB028TracingKind, n, "`%s.str_field(:f)` is accepted only as the third argument of `R.output_str(S.new(…), :field, %s.str_field(:f), :status)` — a user string is not a value on the eBPF side", c.param, c.param)
		return nil
	case kind == "tracepoint" && name == "field":
		if callee != "TracepointCtx#field" {
			c.add(Rejected, SB011ShadowedName, n, "`%s.field` resolves to %q, not BPF::TracepointCtx#field", c.param, callee)
			return nil
		}
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			c.add(Rejected, SB028TracingKind, n, "`%s.field(:name)` takes one Symbol literal — a field declared in `BPF.tracepoint … fields:`", c.param)
			return nil
		}
		fn := as[0].Str["value"]
		for _, f := range c.prog.TFields {
			if f.Name == fn {
				if f.Type == "user_str" {
					c.add(Rejected, SB028TracingKind, n, "`%s.field(:%s)`: %s is declared :user_str — read the string with `%s.str_field(:%s)` as the third argument of `R.output_str`", c.param, fn, fn, c.param, fn)
					return nil
				}
				if f.N > 0 {
					c.add(Rejected, SB028TracingKind, n, "`%s.field(:%s)`: %s is declared as a byte array [:%s, %d] — copy it with `%s.copy(:%s)` into a `[:u8, %d]` member of the event", c.param, fn, fn, f.Type, f.N, c.param, fn, f.N)
					return nil
				}
				if f.Type == "user_str_array" {
					c.add(Rejected, SB028TracingKind, n, "`%s.field(:%s)`: %s is declared :user_str_array — read its strings with `%s.argv_field(:%s)` as the third argument of `R.output_argv`", c.param, fn, fn, c.param, fn)
					return nil
				}
				rf := typ(f.Type)
				rf.Name = f.Name
				return mk("tpfield", rf, f.Offset)
			}
		}
		c.add(Rejected, SB028TracingKind, as[0], "`%s.field(:%s)`: %s is not declared in `BPF.tracepoint … fields:` (declare its offset and type from the tracefs format)", c.param, fn, fn)
		return nil
	case kind == "raw_tp" && name == "arg":
		if callee != "RawTpCtx#arg" {
			c.add(Rejected, SB011ShadowedName, n, "`%s.arg` resolves to %q, not BPF::RawTpCtx#arg", c.param, callee)
			return nil
		}
		if len(as) != 1 || as[0].Type != "IntegerNode" {
			c.add(Rejected, SB028TracingKind, n, "`%s.arg(i)` takes one Integer literal i — the tracepoint's args index 0..11", c.param)
			return nil
		}
		nb, ok := c.z.literal(c.a, as[0])
		if !ok {
			return nil
		}
		if !nb.IsInt64() || nb.Int64() < 0 || nb.Int64() > 11 {
			c.add(Rejected, SB028TracingKind, as[0], "`%s.arg(%s)`: a raw_tp argument index is 0..11 (args[i] of bpf_raw_tracepoint_args — 0-origin, unlike the 1-origin register numbers of `BPF.kprobe … params:`)", c.param, nb)
			return nil
		}
		return mk("rawarg", typ("u64"), nb.Int64())
	case kind == "kprobe" && name == "read":
		c.add(Rejected, SB028TracingKind, n, "`%s.read(n, offset, :type)` returns a value and a status — use it only as the statement `v, st = %s.read(…)` (the status is read later — a failed read is 0, like a real 0)", c.param, c.param)
		return nil
	case (kind == "kprobe" || kind == "ksyscall") && name == "arg":
		want := map[string]string{"kprobe": "KprobeCtx#arg", "ksyscall": "KsyscallCtx#arg"}[kind]
		if callee != want {
			c.add(Rejected, SB011ShadowedName, n, "`%s.arg` resolves to %q, not BPF::%s", c.param, callee, want)
			return nil
		}
		if len(as) != 1 || as[0].Type != "IntegerNode" {
			c.add(Rejected, SB028TracingKind, n, "`%s.arg(n)` takes one Integer literal n — a declared parameter number", c.param)
			return nil
		}
		nb, ok := c.z.literal(c.a, as[0])
		if !ok {
			return nil
		}
		for _, kp := range c.prog.Params {
			if nb.IsInt64() && int64(kp.N) == nb.Int64() {
				if kp.Type == "ptr" {
					return mk("kparg", &RecordField{Name: "ptr", Bits: 64, Signed: true}, nb.Int64())
				}
				if kp.Type == "user_str" {
					c.add(Rejected, SB028TracingKind, n, "`%s.arg(%s)`: parameter %s is declared :user_str — read the string with `%s.str_arg(%s)` as the third argument of `R.output_str`", c.param, nb, nb, c.param, nb)
					return nil
				}
				if kp.Type == "user_str_array" {
					c.add(Rejected, SB028TracingKind, n, "`%s.arg(%s)`: parameter %s is declared :user_str_array — read its strings with `%s.argv_arg(%s)` as the third argument of `R.output_argv`", c.param, nb, nb, c.param, nb)
					return nil
				}
				return mk("kparg", typ(kp.Type), nb.Int64())
			}
		}
		c.add(Rejected, SB028TracingKind, as[0], "`%s.arg(%s)`: %s is not a parameter number declared in `BPF.%s … params:` (numbers are 1..6, 1-origin like the schema's n)", c.param, nb, nb, kind)
		return nil
	case kind == "uprobe" && name == "arg":
		if callee != "UprobeCtx#arg" {
			c.add(Rejected, SB011ShadowedName, n, "`%s.arg` resolves to %q, not BPF::UprobeCtx#arg", c.param, callee)
			return nil
		}
		kp := c.uprobeParam(n, as)
		if kp == nil {
			return nil
		}
		if kp.Type == "user_str" {
			c.add(Rejected, SB028TracingKind, n, "`%s.arg(%d)`: parameter %d is declared :user_str — read it with `%s.str_arg(%d)` as the third argument of `R.output_str`", c.param, kp.N, kp.N, c.param, kp.N)
			return nil
		}
		if kp.Type == "user_buf" {
			c.add(Rejected, SB028TracingKind, n, "`%s.arg(%d)`: parameter %d is declared :user_buf — read it with `%s.buf_arg(%d)` as the third argument of `R.output_buf`", c.param, kp.N, kp.N, c.param, kp.N)
			return nil
		}
		if kp.Type == "ptr" {
			return mk("kparg", &RecordField{Name: "ptr", Bits: 64, Signed: true}, int64(kp.N))
		}
		return mk("kparg", typ(kp.Type), int64(kp.N))
	case (kind == "tp_btf" || kind == "fentry" || kind == "fmod_ret") && name == "arg":
		want := map[string]string{"tp_btf": "TpBtfCtx#arg", "fentry": "FentryCtx#arg", "fmod_ret": "FmodRetCtx#arg"}[kind]
		if callee != want {
			c.add(Rejected, SB011ShadowedName, n, "`%s.arg` resolves to %q, not BPF::%s", c.param, callee, want)
			return nil
		}
		if len(as) != 1 || as[0].Type != "IntegerNode" {
			c.add(Rejected, SB033KernelTypeShape, n, "`%s.arg(i)` takes one Integer literal i — an argument index declared in `BPF.%s … args:`", c.param, kind)
			return nil
		}
		nb, _ := c.z.literal(c.a, as[0])
		ta := c.prog.tpArg(int(nb.Int64()))
		if ta == nil {
			c.add(Rejected, SB033KernelTypeShape, as[0], "argument %s is not declared in `BPF.%s … args:`", nb, kind)
			return nil
		}
		if ta.KT != nil {
			c.add(Rejected, SB033KernelTypeShape, n, "argument %d is declared as the kernel struct %s — bind it with `t = %s.kptr(%d, %sT)`", ta.Idx, ta.KT.Const, c.param, ta.Idx, ta.KT.Const)
			return nil
		}
		return mk("kparg", typ(ta.Type), int64(ta.Idx))
	case kind == "tp_btf" && (name == "kptr" || name == "kptr_or_null"):
		c.add(Rejected, SB033KernelTypeShape, n, "`%s.%s(…)` is not a value — bind it as a statement in the program's body: `t = %s.kptr(i, T)`", c.param, name, c.param)
		return nil
	case kind == "uprobe" && name == "str_arg":
		c.add(Rejected, SB028TracingKind, n, "`%s.str_arg(n)` is accepted only as the third argument of `R.output_str(S.new(…), :field, %s.str_arg(n), :status)` — a user string is not a value on the eBPF side", c.param, c.param)
		return nil
	case kind == "uprobe" && name == "buf_arg":
		c.add(Rejected, SB028TracingKind, n, "`%s.buf_arg(n)` is accepted only as the third argument of %s — a user buffer is not a value on the eBPF side", c.param, outputBufForm(c.param))
		return nil
	}
	c.add(Rejected, SB028TracingKind, n, "the %s context has no `%s` — it reads %s", kind, name, ctxReads[kind])
	return nil
}

func verdictKindText(vk string) string {
	switch vk {
	case "xdp":
		return "an XDP"
	case "sched_cls":
		return "a sched_cls (tcx)"
	case "cgroup_skb":
		return "a cgroup_skb"
	case "netfilter":
		return "a netfilter"
	case "flow_dissector":
		return "a flow_dissector"
	case "fmod_ret":
		return "a fmod_ret"
	}
	return "a socket_filter"
}

func verdictReturns(kind string) string {
	switch kind {
	case "xdp":
		return "an XDP program returns BPF::XDP_ABORTED / XDP_DROP / XDP_PASS / XDP_TX"
	case "sched_cls":
		return "a sched_cls (`BPF.tcx`) program returns BPF::TC_PASS or BPF::TC_DROP"
	case "socket_filter":
		return "a socket_filter program returns BPF::SF_KEEP or BPF::SF_DROP"
	case "cgroup_skb":
		return "a cgroup_skb program returns BPF::CG_ALLOW or BPF::CG_DENY"
	case "netfilter":
		return "a netfilter program returns BPF::NF_ACCEPT or BPF::NF_DROP"
	case "flow_dissector":
		return "a flow_dissector program returns BPF::FLOW_OK / FLOW_DROP / FLOW_CONTINUE"
	case "fmod_ret":
		return "a fmod_ret program returns BPF::FMOD_CALL or BPF.fmod_return(e) (e provably non-zero)"
	}
	return "a " + kind + " program returns nothing (its last value is dropped)"
}

var ctxFields = map[string]map[string]bool{"xdp": {"ingress_ifindex": true}, "sched_cls": {"len": true, "mark": true}, "cgroup_skb": {"len": true}, "sk_lookup": {"local_port": true}}

func (c *progCtx) ctxStore(n *Node, refVar string) (Stmt, bool) {
	callee, ok := c.callee(n)
	if !ok {
		return Stmt{}, false
	}
	if callee != "SkBuff#mark=" {
		c.add(Rejected, SB011ShadowedName, n, "`%s.mark =` resolves to %s, not BPF::SkBuff#mark=", c.param, callee)
		return Stmt{}, false
	}
	as := args(c.a, n)
	if len(as) != 1 {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.mark = v` takes one value", c.param)
		return Stmt{}, false
	}
	e := c.expr(as[0], refVar)
	if e == nil {
		return Stmt{}, false
	}
	if e.Bool || e.Wide || !e.Iv.within(new(big.Int), new(big.Int).Set(u32Max)) {
		c.add(Rejected, SB014SemanticGap, as[0], "the value's range %s does not fit __sk_buff.mark (u32 [0, 4294967295]) — the store would truncate silently; narrow it (e.g. `& 0xFFFF_FFFF`)", e.Iv)
		return Stmt{}, false
	}
	return Stmt{Kind: "ctxstore", Path: "mark", Val: e, Pos: c.z.pos(c.a, n)}, true
}

func (c *progCtx) isAdjustPkt(n *Node) bool {
	return n != nil && n.Type == "CallNode" && (n.Str["name"] == "adjust_head" || n.Str["name"] == "adjust_tail") && c.prog != nil && c.prog.Kind == "xdp" && c.isVarRead(c.a.ref(n, "receiver"), c.param)
}

func (c *progCtx) adjustPkt(n *Node, refVar string) *Expr {
	nm := n.Str["name"]
	p := c.a.node(c.a.Parent[n.ID])
	if p == nil || p.Type != "LocalVariableWriteNode" || c.a.ref(p, "value") != n {
		c.add(Rejected, SB026StatusIgnored, n, "the status of `%s.%s(d)` (0 or −errno) is accepted only as `st = %s.%s(d)` (read later) or `_ = %s.%s(d)` — not as an argument, an operand or another value", c.param, nm, c.param, nm, c.param, nm)
		return nil
	}
	if !c.topLevel(p) {
		c.add(Rejected, SB002UnsupportedCall, p, "`%s = %s.%s(d)` is accepted only as a statement directly in the program's body — not inside an arm or a loop (the helper invalidates the packet windows; decide the delta in the arm and move the packet at the top level)", p.Str["name"], c.param, nm)
		return nil
	}
	callee, ok := c.callee(n)
	if !ok {
		return nil
	}
	if want := "XdpMd#" + nm; callee != want {
		c.add(Rejected, SB011ShadowedName, n, "`%s` resolves to %s, not BPF::%s", nm, callee, want)
		return nil
	}
	as := args(c.a, n)
	if len(as) != 1 {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.%s(d)` takes one delta", c.param, nm)
		return nil
	}
	if nm == "adjust_tail" {
		var k int64
		ok := as[0].Type == "IntegerNode"
		if ok {
			b, lok := c.z.literal(c.a, as[0])
			ok = lok && b.IsInt64() && b.Int64() <= 0 && b.Int64() >= i32Min.Int64()
			if ok {
				k = b.Int64()
			}
		}
		if !ok {
			c.add(Rejected, SB014SemanticGap, as[0], "`%s.adjust_tail(k)` takes an Integer literal k ≤ 0 (it only shrinks the tail; bpf-mlir accepts only a constant non-positive delta)", c.param)
			return nil
		}
		return &Expr{Kind: "adjt", Idx: k, Iv: iv(big.NewInt(-4095), new(big.Int)), Pos: c.z.pos(c.a, n)}
	}
	d := c.expr(as[0], refVar)
	if d == nil {
		return nil
	}
	if d.Bool || d.Wide || !d.Iv.within(new(big.Int).Set(i32Min), new(big.Int).Set(i32Max)) {
		c.add(Rejected, SB014SemanticGap, as[0], "the delta's range %s does not fit the helper's int (i32 [-2147483648, 2147483647]) — narrow it", d.Iv)
		return nil
	}
	return &Expr{Kind: "adjh", Args: []*Expr{d}, Iv: iv(big.NewInt(-4095), new(big.Int)), Pos: c.z.pos(c.a, n)}
}
