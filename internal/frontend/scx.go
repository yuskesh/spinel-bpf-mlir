package frontend

import (
	"fmt"
	"math/big"
	"strings"
)

// sched_ext ops: one Ruby call per bpf-mlir ebpf.scx op, accepted only in a struct_ops program of a sched_ext_ops
// table. Where each op may be called (the member, the region, sleepability) is bpf-mlir's rule, checked by ebpf-compile; the
// frontend checks the operands' kinds and widths. Any use adds the module attribute ebpf.scx_kfuncs = "insert".
//
//	cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)   BPF::Scx.dsq_insert(p, dsq, slice, flags)
//	BPF::Scx.dsq_insert_vtime(p, dsq, slice, vtime, flags)   BPF::Scx.dsq_move_to_local(dsq) (a Bool, may be dropped)
//	r = BPF::Scx.create_dsq(dsq, node) (a status)   BPF::Scx.task_set_dsq_vtime(p, vtime)   BPF::Scx.error("fmt", a, …)
//	BPF::Scx.exit_info(ctx, U)   BPF::Scx::DSQ_LOCAL / SLICE_DFL (ebpf.scx.const)

// scxOp is the shape of one op: whether its first argument is the checked task, the widths of the Integer operands, and the result
// ("" a statement, "bool", "status", "pair").
type scxOp struct {
	Task bool
	Args []int
	Res  string
}

var scxOps = map[string]scxOp{
	"select_cpu_dfl":     {true, []int{32, 64}, "pair"},
	"dsq_insert":         {true, []int{64, 64, 64}, ""},
	"dsq_insert_vtime":   {true, []int{64, 64, 64, 64}, ""},
	"dsq_move_to_local":  {false, []int{64}, "bool"},
	"create_dsq":         {false, []int{64, 32}, "status"},
	"task_set_dsq_vtime": {true, []int{64}, ""},
	"error":              {false, nil, ""},
	"exit_info":          {false, nil, ""},
}

// scxConsts are the SCX constants a program may read (the scxenum rows scx_simple uses — bpf-mlir KernelABITable.inc:1025-1026).
var scxConsts = map[string]string{"DSQ_LOCAL": "SCX_DSQ_LOCAL", "SLICE_DFL": "SCX_SLICE_DFL"}

// scxStatusDecl names create_dsq in the status rule's messages (SB026 — hash.go's wording).
var scxStatusDecl = &MapDecl{Const: "BPF::Scx"}

const scxMaxErrorArgs = 12 // MAX_BPRINTF_VARARGS (bpf-mlir ebpf.scx.error)

func i32Range() Ival {
	return iv(new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 31)), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 31), big.NewInt(1)))
}

// isScxCall reports whether n is `BPF::Scx.<op>(…)` with an op of the table.
func (c *progCtx) isScxCall(n *Node) bool {
	if n == nil || n.Type != "CallNode" || constName(c.a, c.a.ref(n, "receiver")) != "BPF::Scx" {
		return false
	}
	_, ok := scxOps[n.Str["name"]]
	return ok
}

// scxPlaceOK checks the program kind (a sched_ext_ops struct_ops program) and the callee.
func (c *progCtx) scxPlaceOK(n *Node) bool {
	name := n.Str["name"]
	if c.prog.Kind != "struct_ops" || c.prog.SOType != "sched_ext_ops" {
		c.add(Rejected, SB002UnsupportedCall, n, "`BPF::Scx.%s` is a sched_ext op — only a callback of a sched_ext_ops table calls it, not a %s program", name, c.progWhat())
		return false
	}
	callee, ok := c.callee(n)
	if !ok {
		return false
	}
	if callee != "Scx."+name { // Spinel's callee of a module function of BPF::Scx
		c.add(Rejected, SB011ShadowedName, n, "`BPF::Scx.%s` resolves to %q, not the library's BPF::Scx.%s", name, callee, name)
		return false
	}
	c.prog.Scx = true
	return true
}

// progWhat names the program in a placement message (its kind, or the struct_ops type).
func (c *progCtx) progWhat() string {
	if c.prog.Kind == "struct_ops" {
		return c.prog.SOType
	}
	return c.prog.Kind
}

// scxTask reads the task operand: a checked task pointer (p inside `if p`). After the `if` it is SB005, otherwise SB033.
func (c *progCtx) scxTask(n, x *Node) (string, *KernelTypeDecl, bool) {
	name := n.Str["name"]
	if x != nil && x.Type == "LocalVariableReadNode" {
		t := x.Str["name"]
		if d := c.kptrs[t]; d != nil && d.Name == "task_struct" {
			return t, d, true
		}
		if c.kchecked[t] {
			c.add(Rejected, SB005RefCheckShape, x, "`%s` (a nullable kernel pointer) may be passed to `BPF::Scx.%s` only inside its `if %s`", t, name, t)
			return "", nil, false
		}
	}
	c.add(Rejected, SB033KernelTypeShape, n, "the first argument of `BPF::Scx.%s` is the checked task pointer (`p = %s.kptr_or_null(i, TaskT)`, inside `if p`)", name, c.param)
	return "", nil, false
}

// scxOperand reads one Integer operand of width bits (64: a u64 — a Wide value written in the call, or an Integer in [0, 2^63 − 1];
// 32: an Integer that fits i32).
func (c *progCtx) scxOperand(op string, x *Node, bits int, refVar string) *Expr {
	e := c.expr(x, refVar)
	if e == nil {
		return nil
	}
	if e.Bool {
		c.add(Rejected, SB014SemanticGap, x, "`BPF::Scx.%s` takes an Integer here, not a Bool", op)
		return nil
	}
	if bits == 64 {
		if e.Wide {
			return e
		}
		r := widthRange(64, false)
		if !e.Iv.within(r.Lo, r.Hi) {
			c.add(Rejected, SB014SemanticGap, x, "the value's range %s does not fit this u64 operand of `BPF::Scx.%s` (%s for an Integer) — the op would see another number", e.Iv, op, r)
			return nil
		}
		return e
	}
	r := i32Range()
	if e.Wide || !e.Iv.within(r.Lo, r.Hi) {
		what := "the value's range " + e.Iv.String()
		if e.Wide {
			what = "a u64 value"
		}
		c.add(Rejected, SB014SemanticGap, x, "%s does not fit this i32 operand of `BPF::Scx.%s` (%s)", what, op, r)
		return nil
	}
	return e
}

// scxArgs reads the operands of op n (after the task, if any). It returns the task local, its type and the operands.
func (c *progCtx) scxArgs(n *Node, refVar string) (string, *KernelTypeDecl, []*Expr, bool) {
	name := n.Str["name"]
	op := scxOps[name]
	as := args(c.a, n)
	want := len(op.Args)
	if op.Task {
		want++
	}
	if len(as) != want {
		c.add(Rejected, SB002UnsupportedCall, n, "`BPF::Scx.%s` takes %d arguments, got %d", name, want, len(as))
		return "", nil, nil, false
	}
	t, kt := "", (*KernelTypeDecl)(nil)
	if op.Task {
		var ok bool
		if t, kt, ok = c.scxTask(n, as[0]); !ok {
			return "", nil, nil, false
		}
		as = as[1:]
	}
	var es []*Expr
	for i, x := range as {
		e := c.scxOperand(name, x, op.Args[i], refVar)
		if e == nil {
			return "", nil, nil, false
		}
		es = append(es, e)
	}
	return t, kt, es, true
}

// scxStmt handles a statement `BPF::Scx.<op>(…)` (handled is false when n is not one).
func (c *progCtx) scxStmt(n *Node, refVar string) (s Stmt, ok, handled bool) {
	if !c.isScxCall(n) {
		return Stmt{}, false, false
	}
	name := n.Str["name"]
	if !c.scxPlaceOK(n) {
		return Stmt{}, false, true
	}
	pos := c.z.pos(c.a, n)
	switch name {
	case "create_dsq":
		c.add(Rejected, SB026StatusIgnored, n, "%s", statusIgnored(scxStatusDecl, name))
		return Stmt{}, false, true
	case "select_cpu_dfl":
		c.add(Rejected, SB001UnsupportedConstruct, n, "`BPF::Scx.select_cpu_dfl` gives two values — write `cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)`")
		return Stmt{}, false, true
	case "error":
		as := args(c.a, n)
		if len(as) < 1 || as[0].Type != "StringNode" || as[0].Str["content"] == "" || strings.ContainsRune(as[0].Str["content"], 0) {
			c.add(Rejected, SB002UnsupportedCall, n, "`BPF::Scx.error(\"fmt\", a, …)` takes a non-empty format String literal first")
			return Stmt{}, false, true
		}
		if len(as)-1 > scxMaxErrorArgs {
			c.add(Rejected, SB002UnsupportedCall, n, "`BPF::Scx.error` takes at most %d Integers after the format", scxMaxErrorArgs)
			return Stmt{}, false, true
		}
		var es []*Expr
		for _, x := range as[1:] {
			e := c.expr(x, refVar)
			if e == nil {
				return Stmt{}, false, true
			}
			if e.Bool || e.Wide {
				c.add(Rejected, SB014SemanticGap, x, "`BPF::Scx.error` formats Integers (i64), not a Bool or a u64 value")
				return Stmt{}, false, true
			}
			es = append(es, e)
		}
		return Stmt{Kind: "scx", Op: name, Path: as[0].Str["content"], ScxArgs: es, Pos: pos}, true, true
	case "exit_info":
		as := args(c.a, n)
		if c.prog.SOMember != "exit" {
			c.add(Rejected, SB002UnsupportedCall, n, "`BPF::Scx.exit_info` reads the exit info argument of the `exit` member — not of `%s`", c.prog.SOMember)
			return Stmt{}, false, true
		}
		if len(as) != 2 || !c.isVarRead(as[0], c.param) || as[1].Type != "ConstantReadNode" || c.z.globals[as[1].Str["name"]] == nil || c.z.globals[as[1].Str["name"]].Class != "ExitInfo" {
			c.add(Rejected, SB002UnsupportedCall, n, "`BPF::Scx.exit_info(%s, U)` takes the context and a BPF::ExitInfo constant", c.param)
			return Stmt{}, false, true
		}
		g := c.z.globals[as[1].Str["name"]]
		c.usedGlobals[g] = true
		c.prog.SOArgs = soAddIndex(c.prog.SOArgs, 0)
		return Stmt{Kind: "scxexit", Glob: g, Pos: pos}, true, true
	}
	t, kt, es, ok := c.scxArgs(n, refVar)
	if !ok {
		return Stmt{}, false, true
	}
	return Stmt{Kind: "scx", Op: name, Var: t, KT: kt, ScxArgs: es, Pos: pos}, true, true
}

// scxExpr handles `BPF::Scx.<op>(…)` as a value: dsq_move_to_local (a Bool) and create_dsq (a status, in the places hash.go accepts).
func (c *progCtx) scxExpr(n *Node, refVar string) *Expr {
	name := n.Str["name"]
	if !c.scxPlaceOK(n) {
		return nil
	}
	switch scxOps[name].Res {
	case "bool":
	case "status":
		if !c.statusParentOK(n) {
			c.add(Rejected, SB026StatusIgnored, n, "the status of `BPF::Scx.%s` is accepted only as `st = BPF::Scx.%s(…)` (read later), as an operand of a comparison, or as `_ = BPF::Scx.%s(…)` — not as an argument, an arithmetic operand or another value", name, name, name)
			return nil
		}
	case "pair":
		c.add(Rejected, SB001UnsupportedConstruct, n, "`BPF::Scx.select_cpu_dfl` gives two values — write `cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)`")
		return nil
	default:
		c.add(Rejected, SB002UnsupportedCall, n, "`BPF::Scx.%s` has no value — call it as a statement", name)
		return nil
	}
	_, _, es, ok := c.scxArgs(n, refVar)
	if !ok {
		return nil
	}
	e := &Expr{Kind: "scx", Op: name, Args: es, Pos: c.z.pos(c.a, n)}
	if scxOps[name].Res == "bool" {
		e.Bool = true
	} else {
		e.Iv = i32Range()
	}
	return e
}

// scxConst reads `BPF::Scx::<NAME>` in an expression (ebpf.scx.const — an opaque i64 bit pattern, so Wide).
func (c *progCtx) scxConst(n *Node) (*Expr, bool) {
	cn := constName(c.a, n)
	if !strings.HasPrefix(cn, "BPF::Scx::") {
		return nil, false
	}
	k := strings.TrimPrefix(cn, "BPF::Scx::")
	full, ok := scxConsts[k]
	if !ok {
		c.add(Rejected, SB002UnsupportedCall, n, "%s is not an SCX constant of this version — a program reads BPF::Scx::DSQ_LOCAL and BPF::Scx::SLICE_DFL", cn)
		return nil, true
	}
	if c.prog.Kind != "struct_ops" || c.prog.SOType != "sched_ext_ops" {
		c.add(Rejected, SB002UnsupportedCall, n, "%s is a sched_ext constant — only a callback of a sched_ext_ops table reads it, not a %s program", cn, c.progWhat())
		return nil, true
	}
	c.prog.Scx = true
	return &Expr{Kind: "scxconst", Path: full, Iv: iv(new(big.Int), new(big.Int).Set(u64Max)), Wide: true, Pos: c.z.pos(c.a, n)}, true
}

// scxSelect reads `cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)` (handled is false when the value is not that call — the
// caller then applies the other multiple-assignment rules).
func (c *progCtx) scxSelect(n *Node, refVar string) (s Stmt, ok, handled bool) {
	ts, v := c.a.arr(n, "lefts"), c.a.ref(n, "value")
	if !c.isScxCall(v) || v.Str["name"] != "select_cpu_dfl" {
		return Stmt{}, false, false
	}
	defer func() { // a refused form leaves its targets poisoned (no follow-on 'not defined' at their reads)
		if !ok {
			c.poisonTargets(n)
		}
	}()
	if !c.scxPlaceOK(v) {
		return Stmt{}, false, true
	}
	if len(ts) != 2 || ts[0].Type != "LocalVariableTargetNode" || ts[1].Type != "LocalVariableTargetNode" || c.a.ref(n, "rest") != nil || len(c.a.arr(n, "rights")) != 0 {
		c.add(Rejected, SB001UnsupportedConstruct, n, "`cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)` assigns two plain locals")
		return Stmt{}, false, true
	}
	cpu, idle := ts[0].Str["name"], ts[1].Str["name"]
	for _, name := range []string{cpu, idle} {
		if name == "_" || name == c.param || c.refs[name] != nil || c.wins[name] != nil || c.kptrs[name] != nil {
			c.add(Rejected, SB001UnsupportedConstruct, n, "`%s` cannot receive a value of `BPF::Scx.select_cpu_dfl` — use a plain local", name)
			return Stmt{}, false, true
		}
		if !c.wideRebindOK(name, n) {
			return Stmt{}, false, true
		}
	}
	t, kt, es, ok := c.scxArgs(v, refVar)
	if !ok {
		return Stmt{}, false, true
	}
	c.env[cpu] = &varInfo{Iv: i32Range()}
	c.env[idle] = &varInfo{Bool: true}
	return Stmt{Kind: "scxsel", Var: t, KT: kt, Path: cpu + "," + idle, ScxArgs: es, Pos: c.z.pos(c.a, n)}, true, true
}

// scxMultiRefused is the struct_ops message for any other multiple assignment.
func (c *progCtx) scxMultiRefused(n *Node) {
	c.poisonTargets(n)
	c.add(Rejected, SB001UnsupportedConstruct, n, "a multiple assignment in a struct_ops program is accepted only as `cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)`")
}

// usesScx reports whether a program calls a sched_ext op (the module then carries ebpf.scx_kfuncs = "insert").
func usesScx(progs []*Program) bool {
	for _, p := range progs {
		if p.Scx {
			return true
		}
	}
	return false
}

// scxOperands lowers the Integer operands to the op's widths (an i32 operand is narrowed with one trunci).
func (l *lowerer) scxOperands(es []*Expr, bits []int, pos Pos) ([]string, []string, error) {
	var names, tys []string
	for i, e := range es {
		x, err := l.expr(e)
		if err != nil {
			return nil, nil, err
		}
		v := x.name
		if bits[i] < 64 {
			v = l.val()
			l.emit("%s = arith.trunci %s : i64 to i%d %s", v, x.name, bits[i], loc(pos))
		}
		names = append(names, v)
		tys = append(tys, fmt.Sprintf("i%d", bits[i]))
	}
	return names, tys, nil
}

func (l *lowerer) scxStmt(s Stmt) error {
	switch s.Op {
	case "error":
		bits := make([]int, len(s.ScxArgs))
		for i := range bits {
			bits[i] = 64
		}
		vs, tys, err := l.scxOperands(s.ScxArgs, bits, s.Pos)
		if err != nil {
			return err
		}
		if len(vs) == 0 {
			l.emit("ebpf.scx.error %q () %s", s.Path, loc(s.Pos))
		} else {
			l.emit("ebpf.scx.error %q (%s) : %s %s", s.Path, strings.Join(vs, ", "), strings.Join(tys, ", "), loc(s.Pos))
		}
		return nil
	case "dsq_move_to_local": // the Bool is dropped (whether a task was moved — not a status)
		vs, _, err := l.scxOperands(s.ScxArgs, scxOps[s.Op].Args, s.Pos)
		if err != nil {
			return err
		}
		r := l.val()
		l.emit("%s = ebpf.scx.dsq_move_to_local %s : i64 -> i1 %s", r, vs[0], loc(s.Pos))
		return nil
	}
	vs, tys, err := l.scxOperands(s.ScxArgs, scxOps[s.Op].Args, s.Pos)
	if err != nil {
		return err
	}
	l.emit("ebpf.scx.%s %s, %s : !ebpf.kptr<%q>, %s %s", s.Op, l.env[s.Var].name, strings.Join(vs, ", "), s.KT.Name, strings.Join(tys, ", "), loc(s.Pos))
	return nil
}

func (l *lowerer) scxSelect(s Stmt) error {
	vs, _, err := l.scxOperands(s.ScxArgs, scxOps["select_cpu_dfl"].Args, s.Pos)
	if err != nil {
		return err
	}
	r := l.val()
	l.emit("%s:2 = ebpf.scx.select_cpu_dfl %s, %s, %s : !ebpf.kptr<%q>, i32, i64 -> i32, i1 %s", r, l.env[s.Var].name, vs[0], vs[1], s.KT.Name, loc(s.Pos))
	x := l.val()
	l.emit("%s = arith.extsi %s#0 : i32 to i64 %s", x, r, loc(s.Pos))
	names := strings.Split(s.Path, ",")
	l.env[names[0]] = ssaVal{x, "i64"}
	l.env[names[1]] = ssaVal{r + "#1", "i1"}
	return nil
}

// scxExit lowers BPF::Scx.exit_info(ctx, U): the exit info argument, its check, and ebpf.scx.exit_info in the present region.
func (l *lowerer) scxExit(s Stmt) {
	n := l.val()
	l.emit("%s = ebpf.ctx.arg %%ctx[0] : !ebpf.ctx<\"struct_ops\"> -> !ebpf.kptr_or_null<\"scx_exit_info\"> %s", n, loc(s.Pos))
	l.emit("ebpf.kptr.check %s : !ebpf.kptr_or_null<\"scx_exit_info\"> present {", n)
	e := l.val()
	l.emit("^present(%s: !ebpf.kptr<\"scx_exit_info\">):", e)
	l.emit("  ebpf.scx.exit_info %s, @%s : !ebpf.kptr<\"scx_exit_info\"> %s", e, s.Glob.Name, loc(s.Pos))
	l.emit("  ebpf.yield %s", loc(s.Pos))
	l.emit("} absent {")
	l.emit("  ebpf.yield %s", loc(s.Pos))
	l.emit("} %s", loc(s.Pos))
}

func (l *lowerer) scxExpr(e *Expr) (ssaVal, error) {
	vs, tys, err := l.scxOperands(e.Args, scxOps[e.Op].Args, e.Pos)
	if err != nil {
		return ssaVal{}, err
	}
	r := l.val()
	if e.Op == "dsq_move_to_local" {
		l.emit("%s = ebpf.scx.dsq_move_to_local %s : i64 -> i1 %s", r, vs[0], loc(e.Pos))
		return ssaVal{r, "i1"}, nil
	}
	l.emit("%s = ebpf.scx.create_dsq %s : %s -> i32 %s", r, strings.Join(vs, ", "), strings.Join(tys, ", "), loc(e.Pos))
	x := l.val()
	l.emit("%s = arith.extsi %s : i32 to i64 %s", x, r, loc(e.Pos))
	return ssaVal{x, "i64"}, nil
}

// The exit record: bpf-mlir's user_exit_info (7.3.1 tools/sched_ext/include/scx/user_exit_info_common.h without
// the dump), the .data global that ebpf.scx.exit_info fills, and the scx_exit_info kernel type with the four fields the op reads.
const userExitInfoSymbol = "user_exit_info"

const userExitInfoRecord = `{"symbol":"user_exit_info","id":0,"size":1168,"min_size":1168,"alignment":8,"required_through":"","note":"the C struct user_exit_info (tools/sched_ext/include/scx/user_exit_info_common.h) without the dump","fields":[{"name":"kind","type":{"kind":"int","bits":32,"signed":true,"endianness":"little","alignment":4},"offset":0},{"name":"exit_cpu","type":{"kind":"int","bits":32,"signed":true,"endianness":"little","alignment":4},"offset":4},{"name":"exit_code","type":{"kind":"int","bits":64,"signed":true,"endianness":"little","alignment":8},"offset":8},{"name":"reason","type":{"kind":"array","count":128,"element":{"kind":"int","bits":8,"signed":true,"endianness":"little","alignment":1}},"offset":16},{"name":"msg","type":{"kind":"array","count":1024,"element":{"kind":"int","bits":8,"signed":true,"endianness":"little","alignment":1}},"offset":144}]}`

// schemaDataGlobal is a core.globals entry of a .data record global.
type schemaDataGlobal struct {
	Name    string `json:"name"`
	Section string `json:"section"`
	Record  string `json:"record"`
	Note    string `json:"note"`
}

type schemaKindBits struct {
	Kind string `json:"kind"`
	Bits int    `json:"bits"`
}

type schemaKindOnly struct {
	Kind string `json:"kind"`
}

func scxExitInfoKernelType() schemaKernelType {
	return schemaKernelType{Name: "scx_exit_info", Note: "the fields ebpf.scx.exit_info reads (owned by the frontend)", Fields: []schemaKField{
		{Name: "kind", Type: schemaKindBits{"enum", 32}},
		{Name: "exit_code", Type: schemaInt{"int", 64, true, "little", 8}},
		{Name: "reason", Type: schemaKindOnly{"strptr"}},
		{Name: "msg", Type: schemaKindOnly{"strptr"}},
	}}
}

// usesExitInfo reports whether a used global is a BPF::ExitInfo.
func usesExitInfo(res *Result) bool {
	for _, g := range res.Globals {
		if g.Class == "ExitInfo" {
			return true
		}
	}
	return false
}

// poisonTargets marks the plain local targets of a refused multiple assignment, so their later reads add no diagnostic.
func (c *progCtx) poisonTargets(n *Node) {
	for _, t := range c.a.arr(n, "lefts") {
		if t.Type == "LocalVariableTargetNode" {
			c.poisoned[t.Str["name"]] = true
		}
	}
}
