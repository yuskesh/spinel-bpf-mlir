package frontend

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const uprobeShape = "`BPF.uprobe :name, \"target/binary\", \"symbol\", params: {1 => :user_str, 2 => :i32}`"

const uretprobeShape = "`BPF.uretprobe :name, \"target/binary\", \"symbol\", ret: :i64`"

func (z *analyzer) uprobeDecl(a *AST, n *Node, as []*Node, bad func(string, ...any) (rootDecl, bool)) (rootDecl, bool) {
	if len(as) != 4 || as[0].Type != "SymbolNode" || as[1].Type != "StringNode" || as[2].Type != "StringNode" || as[3].Type != "KeywordHashNode" ||
		as[1].Str["content"] == "" || as[2].Str["content"] == "" {
		if n.Str["name"] == "uretprobe" {
			return bad("a uretprobe program is declared as %s — a Symbol, the target binary's path and symbol as non-empty String literals, and `ret:`", uretprobeShape)
		}
		return bad("a uprobe program is declared as %s — a Symbol, the target binary's path and symbol as non-empty String literals, and `params:`", uprobeShape)
	}
	path := as[1].Str["content"]
	clean := filepath.Clean(path)
	full := filepath.Join(z.srcDir, clean)
	if filepath.IsAbs(path) {
		if clean != path {
			return bad("the uprobe target %q must be a clean absolute path (no `.`, `..` or repeated `/`) or a path relative to the source's directory — the build reads it and puts only its SHA-256 in the schema", path)
		}
		full = path
	} else if clean == ".." || strings.HasPrefix(clean, "../") {
		return bad("the uprobe target %q must be a path relative to the source's directory that stays inside it (no `..` out of it) or a clean absolute path — the build reads it and puts only its SHA-256 in the schema", path)
	}
	st, err := os.Stat(full)
	if err != nil || !st.Mode().IsRegular() {
		return bad("the uprobe target %q is not a readable regular file — the build needs it to compute binary_sha256", path)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return bad("the uprobe target %q cannot be read: %v", path, err)
	}
	sum := sha256.Sum256(b)
	kind := n.Str["name"]
	r := rootDecl{Name: as[0].Str["value"], Kind: kind, Pos: z.pos(a, n), Target: as[2].Str["content"], BinarySHA: hex.EncodeToString(sum[:]), BinaryPath: full}
	if filepath.IsAbs(path) {
		r.SysTarget = path
	}
	if kind == "uretprobe" {
		var rv *Node
		for _, e := range a.arr(as[3], "elements") {
			k, v := a.ref(e, "key"), a.ref(e, "value")
			if e.Type != "AssocNode" || k == nil || k.Type != "SymbolNode" || k.Str["value"] != "ret" || rv != nil {
				return bad("the options of %s are exactly `ret:`", uretprobeShape)
			}
			rv = v
		}
		if rv == nil || rv.Type != "SymbolNode" {
			return bad("%s needs `ret:` (a Symbol :i8 … :u64 — the kernel does not check it; the value is the return register cut to this width)", uretprobeShape)
		}
		if _, ok := recordTypes[rv.Str["value"]]; !ok {
			return bad("`ret:` of %s is one of :i8 … :i64 / :u8 … :u64", uretprobeShape)
		}
		r.Ret = rv.Str["value"]
		return r, true
	}
	var pv *Node
	for _, e := range a.arr(as[3], "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || k.Type != "SymbolNode" || k.Str["value"] != "params" || pv != nil {
			return bad("the options of %s are exactly `params:`", uprobeShape)
		}
		pv = v
	}
	if pv == nil || pv.Type != "HashNode" {
		return bad("%s needs `params:` with a Hash literal of argument number (1..6) => type", uprobeShape)
	}
	seenN := map[int]bool{}
	for _, e := range a.arr(pv, "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || k.Type != "IntegerNode" {
			return bad("each uprobe parameter is `n => :type` with n an Integer literal 1..6")
		}
		nb, ok := z.literal(a, k)
		if !ok || !nb.IsInt64() || nb.Int64() < 1 || nb.Int64() > 6 || seenN[int(nb.Int64())] {
			return bad("a uprobe parameter number is 1..6 (the x86_64 argument registers, 1-origin like the schema's n) and appears once")
		}
		t := ""
		if v != nil && v.Type == "SymbolNode" {
			t = v.Str["value"]
		}
		if _, isInt := recordTypes[t]; !isInt && t != "user_str" && t != "ptr" && t != "user_buf" {
			return bad("a uprobe parameter type is one of :i8 … :i64 / :u8 … :u64, :user_str (a `const char *` — read with ctx.str_arg(n)), :ptr (a pointer's raw value as i64 — read with ctx.arg(n)) or :user_buf (a buffer — read with ctx.buf_arg(n) in R.output_buf)")
		}
		seenN[int(nb.Int64())] = true
		r.Params = append(r.Params, KParam{N: int(nb.Int64()), Type: t})
	}
	return r, true
}

func (c *progCtx) uprobeParam(n *Node, as []*Node) *KParam {
	if len(as) != 1 || as[0].Type != "IntegerNode" {
		c.add(Rejected, SB028TracingKind, n, "`%s.%s(n)` takes one Integer literal n — a declared parameter number", c.param, n.Str["name"])
		return nil
	}
	nb, ok := c.z.literal(c.a, as[0])
	if !ok {
		return nil
	}
	for i, kp := range c.prog.Params {
		if nb.IsInt64() && int64(kp.N) == nb.Int64() {
			return &c.prog.Params[i]
		}
	}
	c.add(Rejected, SB028TracingKind, as[0], "`%s.%s(%s)`: %s is not a parameter number declared in `BPF.uprobe … params:` (1..6, 1-origin like the schema's n)", c.param, n.Str["name"], nb, nb)
	return nil
}

func (c *progCtx) isOutputStr(n *Node) bool {
	return n != nil && n.Type == "CallNode" && (n.Str["name"] == "output_str" || n.Str["name"] == "output_str_or_discard" || n.Str["name"] == "output_comm" || n.Str["name"] == "output_argv" || n.Str["name"] == "output_buf") && c.ringOf(c.a.ref(n, "receiver")) != nil
}

func outputStrShape(r *RingDecl) string {
	return fmt.Sprintf("`r = %s.output_str(%s.new(…), :<u8 array member>, ctx.str_arg(n), :<i64 status member>)` then `if r` (read `r.status` inside), or `_ = %s.output_str(…)`", r.Const, r.Record.Const, r.Const)
}

func (c *progCtx) outputStr(call *Node, name, refVar string) (Stmt, bool) {
	if call.Str["name"] == "output_comm" {
		return c.outputComm(call, name, refVar)
	}
	if call.Str["name"] == "output_argv" {
		return c.outputArgv(call, name, refVar)
	}
	if call.Str["name"] == "output_buf" {
		return c.outputBuf(call, name, refVar)
	}
	r := c.ringOf(c.a.ref(call, "receiver"))
	tpStr := c.prog.Kind == "tracepoint"
	if sa := args(c.a, call); c.prog.Kind != "uprobe" && c.prog.Kind != "ksyscall" && !tpStr && !(len(sa) >= 3 && sa[2].Type == "CallNode" && sa[2].Str["name"] == "str") {
		c.add(Rejected, SB028TracingKind, call, "`%s.%s` reads a user string (`ctx.str_arg(n)` in a uprobe or ksyscall program, `ctx.str_field(:f)` in a tracepoint program), or a kernel string (`q.str(:m)` — a :strptr member of a present kernel pointer)", r.Const, call.Str["name"])
		return Stmt{}, false
	}
	callee, ok := c.callee(call)
	if !ok {
		return Stmt{}, false
	}
	meth := call.Str["name"]
	if callee != "RingBuf#"+meth {
		c.add(Rejected, SB011ShadowedName, call, "`%s` resolves to %s, not BPF::RingBuf#%s", meth, callee, meth)
		return Stmt{}, false
	}
	as := args(c.a, call)
	member := func(x *Node) *RecordField {
		if x == nil || x.Type != "SymbolNode" {
			return nil
		}
		for i := range r.Record.Fields {
			if r.Record.Fields[i].Name == x.Str["value"] {
				return &r.Record.Fields[i]
			}
		}
		return nil
	}
	if len(as) == 3 || len(as) == 4 && member(as[3]) == nil {
		c.add(Rejected, SB024RecordShape, call, "%s needs a status member: add `status: :i64` to BPF.record(%s, …) and pass it as the fourth argument — a failed read leaves the string member zeroed, the same bytes as an empty string, so only the status tells them apart — %s", call.Str["name"], r.Record.Const, outputStrShape(r))
		return Stmt{}, false
	}
	if len(as) != 4 {
		c.add(Rejected, SB002UnsupportedCall, call, "output_str takes four arguments — %s", outputStrShape(r))
		return Stmt{}, false
	}
	f, st := member(as[1]), member(as[3])
	if f == nil || f.Count == 0 || f.Bits != 8 || f.Signed {
		c.add(Rejected, SB024RecordShape, as[1], "the string member of output_str must be a :u8 array member of %s (`name: [:u8, 32]` — bpf-mlir's user.read_str fills a 1-dimensional 8-bit array)", r.Record.Const)
		return Stmt{}, false
	}
	if st.Count != 0 || st.Bits != 64 || !st.Signed {
		c.add(Rejected, SB024RecordShape, as[3], "the status member %s of output_str must be :i64 (the raw status of probe_read_user_str — length with NUL, or a negative errno)", st.Name)
		return Stmt{}, false
	}
	sa := as[2]
	if sa.Type == "CallNode" && sa.Str["name"] == "str" {
		return c.outputKStr(call, as, r, meth, f, st, name, refVar)
	}
	if tpStr {
		return c.outputTpStr(call, as, r, meth, f, st, name, refVar)
	}
	if sa.Type != "CallNode" || sa.Str["name"] != "str_arg" || !c.isVarRead(c.a.ref(sa, "receiver"), c.param) {
		c.add(Rejected, SB028TracingKind, sa, "the third argument of output_str is `%s.str_arg(n)` itself (a user string is not a value on the eBPF side — not through a local)", c.param)
		return Stmt{}, false
	}
	want := ctxClass[c.prog.Kind] + "#str_arg"
	if cs, ok := c.callee(sa); !ok || cs != want {
		if ok {
			c.add(Rejected, SB011ShadowedName, sa, "`str_arg` resolves to %s, not BPF::%s", cs, want)
		}
		return Stmt{}, false
	}
	kp := c.uprobeParam(sa, args(c.a, sa))
	if kp == nil {
		return Stmt{}, false
	}
	if kp.Type != "user_str" {
		c.add(Rejected, SB028TracingKind, sa, "`%s.str_arg(%d)`: parameter %d is declared :%s — read it with `%s.arg(%d)`", c.param, kp.N, kp.N, kp.Type, c.param, kp.N)
		return Stmt{}, false
	}
	os, ok := c.outputStrMake(call, as, r, meth, f, st, name, refVar)
	os.Len = int64(kp.N)
	return os, ok
}

func (c *progCtx) outputStrMake(call *Node, as []*Node, r *RingDecl, meth string, f, st *RecordField, name, refVar string) (Stmt, bool) {
	mkn := as[0]
	if mkn.Type == "CallNode" && mkn.Str["name"] == "new" && constName(c.a, c.a.ref(mkn, "receiver")) == r.Record.Const {
		vs := args(c.a, mkn)
		for i := range r.Record.Fields {
			if &r.Record.Fields[i] != st || i >= len(vs) {
				continue
			}
			if lit, ok := c.z.literal(c.a, vs[i]); vs[i].Type != "IntegerNode" || !ok || lit.Sign() != 0 {
				c.add(Rejected, SB024RecordShape, vs[i], "the status member %s is written by %s — give the literal 0 in %s.new", st.Name, meth, r.Record.Const)
				return Stmt{}, false
			}
		}
	}
	mk := c.recordMake(mkn, r.Record, &MapDecl{Name: r.Name, Record: r.Record}, refVar)
	if mk == nil {
		return Stmt{}, false
	}
	c.usedRings[r] = true
	op := ""
	if meth == "output_str_or_discard" {
		op = "discard"
	}
	return Stmt{Kind: "ostr", Op: op, Ring: r, Value: mk, Var: name, Path: f.Name, Field: st, Pos: c.z.pos(c.a, call)}, true
}

func (c *progCtx) outputStrCheck(w, ifn *Node, refVar string) ([]Stmt, bool) {
	name := w.Str["name"]
	if v := c.a.ref(w, "value"); v != nil && v.Str["name"] == "output_argv" {
		c.add(Rejected, SB025DroppedEvent, w, "the result of output_argv is not bound — it emits up to 20 events (one per present argv slot), so write `_ = %s.output_argv(…)`", constName(c.a, c.a.ref(v, "receiver")))
		return nil, false
	}
	if _, used := c.env[name]; used || name == c.param || c.refs[name] != nil || c.wins[name] != nil || c.ostrs[name] {
		c.add(Rejected, SB005RefCheckShape, w, "`%s` is already bound — an output_str result needs a fresh name", name)
		return nil, false
	}
	if !c.typed(w) || !c.typed(c.a.ref(ifn, "predicate")) {
		return nil, false
	}
	if t := c.rbs(w); !strings.Contains(t, "OutputStr") {
		c.add(Rejected, SB005RefCheckShape, w, "`%s` is typed %q, not BPF::OutputStr (or nil)", name, t)
		return nil, false
	}
	s, ok := c.outputStr(c.a.ref(w, "value"), name, refVar)
	if !ok {
		return nil, false
	}
	c.ostrs[name] = true
	pre := c.env
	c.env = copyEnv(pre)
	c.env[name+"#status"] = &varInfo{Iv: fullI64}
	c.env[name+"#sent"] = &varInfo{Bool: true}
	c.ostrLive[name] = true
	var then []*Node
	if st := c.a.ref(ifn, "statements"); st != nil {
		then = c.a.arr(st, "body")
	}
	thenS := c.stmts(then, refVar)
	delete(c.ostrLive, name)
	delete(c.env, name+"#status")
	delete(c.env, name+"#sent")
	thenEnv := c.env
	c.env = copyEnv(pre)
	var elseS []Stmt
	if sub := c.a.ref(ifn, "subsequent"); sub != nil {
		if sub.Type != "ElseNode" {
			c.add(Rejected, SB005RefCheckShape, sub, "`elsif` is not accepted after `if %s`", name)
			return nil, false
		}
		var els []*Node
		if st := c.a.ref(sub, "statements"); st != nil {
			els = c.a.arr(st, "body")
		}
		elseS = c.stmts(els, refVar)
	}
	c.env = joinArms(pre, thenEnv, c.env, escapes(thenS), escapes(elseS))
	cond := &Expr{Kind: "var", Var: name, Bool: true, Pos: c.z.pos(c.a, c.a.ref(ifn, "predicate"))}
	return []Stmt{s, {Kind: "if", Cond: cond, Then: thenS, Else: elseS, Pos: c.z.pos(c.a, ifn)}}, true
}

func (c *progCtx) ostrStatus(n *Node, recv *Node, p Pos) *Expr {
	name := recv.Str["name"]
	m := n.Str["name"]
	if !c.ostrLive[name] {
		c.add(Rejected, SB005RefCheckShape, n, "`%s.%s` is read only inside `if %s` right after `%s = R.output_str(…)`", name, m, name, name)
		return nil
	}
	if cs, ok := c.callee(n); !ok || cs != "OutputStr#"+m {
		if ok {
			c.add(Rejected, SB011ShadowedName, n, "`%s` resolves to %s, not BPF::OutputStr#%s", m, cs, m)
		}
		return nil
	}
	if len(args(c.a, n)) != 0 {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.%s` takes no arguments", name, m)
		return nil
	}
	if m == "sent" {
		return &Expr{Kind: "var", Var: name + "#sent", Bool: true, Pos: p}
	}
	return &Expr{Kind: "var", Var: name + "#status", Iv: fullI64, Pos: p}
}

func (l *lowerer) outputStr(s Stmt) error {
	if s.Argv {
		return l.outputArgv(s)
	}
	rec := s.Ring.Record.MLIRType()
	sv, lv := "", ssaVal{}
	if s.Buf {
		var err error
		if lv, err = l.expr(s.BufLen); err != nil {
			return err
		}
		if mutation("user-read-len-abs") {
			z, neg, m, sel := l.val(), l.val(), l.val(), l.val()
			l.emit("%s = arith.constant 0 : %s %s", z, lv.ty, loc(s.Pos))
			l.emit("%s = arith.cmpi slt, %s, %s : %s %s", neg, lv.name, z, lv.ty, loc(s.Pos))
			l.emit("%s = arith.subi %s, %s : %s %s", m, z, lv.name, lv.ty, loc(s.Pos))
			l.emit("%s = arith.select %s, %s, %s : %s %s", sel, neg, m, lv.name, lv.ty, loc(s.Pos))
			lv.name = sel
		}
		sv = l.val()
		l.emit("%s = ebpf.uprobe.arg %%ctx %d : !ebpf.ctx<\"uprobe\"> -> !ebpf.user_buf %s", sv, s.Len, loc(s.Pos))
	} else if s.StrSSA != "" {
		sv = s.StrSSA
	} else if s.TpStr != nil {
		sv = l.val()
		l.emit("%s = ebpf.tp.field %%ctx %q [%d] : !ebpf.ctx<\"tracepoint\"> -> !ebpf.user_str %s", sv, s.TpStr.Name, s.TpStr.Offset, loc(s.Pos))
	} else if s.KStr == "" && !s.Comm {
		sv = l.val()
		if l.kind == "ksyscall" {
			l.emit("%s = ebpf.ksyscall.arg %%ctx %d : !ebpf.ctx<\"ksyscall\"> -> !ebpf.user_str %s", sv, s.Len, loc(s.Pos))
		} else {
			l.emit("%s = ebpf.uprobe.arg %%ctx %d : !ebpf.ctx<\"uprobe\"> -> !ebpf.user_str %s", sv, s.Len, loc(s.Pos))
		}
	}
	rv := l.val()
	l.emit("%s = ebpf.ringbuf.reserve %q : !ebpf.maybe_reservation<%s> %s", rv, s.Ring.Name, rec, loc(s.Pos))
	ok, st, sn := "", "", ""
	if s.Var != "" {
		ok, st = l.val(), l.val()
		if s.Op == "discard" {
			sn = l.val()
		}
	}
	res := l.val()
	var b strings.Builder
	saved, savedIndent := l.b, l.indent
	l.b, l.indent = &b, l.indent+"  "
	v, err := l.valueOperand(s.Value, &MapDecl{Name: s.Ring.Name, Record: s.Ring.Record})
	if err != nil {
		l.b, l.indent = saved, savedIndent
		return err
	}
	l.emit("ebpf.ringbuf.store_record %s, %s : !ebpf.reservation<%s>, %s %s", res, v, rec, rec, loc(s.Pos))
	if s.StrSSA != "" && s.Index != nil {
		iv := l.val()
		l.emit("%s = arith.constant %d : i32 %s", iv, s.IndexV, loc(s.Pos))
		l.emit("ebpf.ringbuf.store_field %s[%d], %s : !ebpf.reservation<%s>, i32 %s", res, s.Index.Offset, iv, rec, loc(s.Pos))
	}
	rs := l.val()
	if s.Comm && mutation("comm-skip") {
		l.emit("%s = arith.constant 0 : i64 %s", rs, loc(s.Pos))
	} else if s.Comm {
		l.emit("%s = ebpf.task.comm %s %q : !ebpf.reservation<%s> -> i64 %s", rs, res, s.Path, rec, loc(s.Pos))
	} else if s.KStr != "" {
		l.emit("%s = ebpf.kernel.read_str %s %q, %s %q : !ebpf.reservation<%s>, !ebpf.kptr<%q> -> i64 %s", rs, res, s.Path, l.env[s.PtrOf].name, s.KStr, rec, s.PtrOfKT.Name, loc(s.Pos))
	} else if s.Buf {
		cv := l.val()
		l.emit("%s, %s = ebpf.user.read %s %q, %s, %s : !ebpf.reservation<%s>, !ebpf.user_buf, %s -> i64, i32 %s", rs, cv, res, s.Path, sv, lv.name, rec, lv.ty, loc(s.Pos))
		l.emit("ebpf.ringbuf.store_field %s[%d], %s : !ebpf.reservation<%s>, i32 %s", res, s.CountF.Offset, cv, rec, loc(s.Pos))
	} else {
		l.emit("%s = ebpf.user.read_str %s %q, %s : !ebpf.reservation<%s>, !ebpf.user_str -> i64 %s", rs, res, s.Path, sv, rec, loc(s.Pos))
	}
	if (s.KStr == "" || !mutation("kstr-no-status")) && (s.TpStr == nil || !mutation("tpstr-no-status")) && (l.kind != "ksyscall" || !mutation("ksysstr-no-status")) {
		l.emit("ebpf.ringbuf.store_field %s[%d], %s : !ebpf.reservation<%s>, i64 %s", res, s.Field.Offset, rs, rec, loc(s.Pos))
	}
	if s.Op == "discard" {
		z, neg := l.val(), l.val()
		l.emit("%s = arith.constant 0 : i64 %s", z, loc(s.Pos))
		l.emit("%s = arith.cmpi slt, %s, %s : i64 %s", neg, rs, z, loc(s.Pos))
		sent := ""
		if s.Var != "" {
			sent = l.val()
			l.emit("%s = ebpf.if %s -> i1 {", sent, neg)
		} else {
			l.emit("ebpf.if %s {", neg)
		}
		l.emit("  ebpf.ringbuf.discard %s : !ebpf.reservation<%s> %s", res, rec, loc(s.Pos))
		if s.Var != "" {
			f := l.val()
			l.emit("  %s = arith.constant false %s", f, loc(s.Pos))
			l.emit("  ebpf.if.yield %s : i1 %s", f, loc(s.Pos))
		} else {
			l.emit("  ebpf.if.yield %s", loc(s.Pos))
		}
		l.emit("} else {")
		l.emit("  ebpf.ringbuf.submit %s : !ebpf.reservation<%s> %s", res, rec, loc(s.Pos))
		if s.Var != "" {
			t := l.val()
			l.emit("  %s = arith.constant true %s", t, loc(s.Pos))
			l.emit("  ebpf.if.yield %s : i1 %s", t, loc(s.Pos))
		} else {
			l.emit("  ebpf.if.yield %s", loc(s.Pos))
		}
		l.emit("} %s", loc(s.Pos))
		if s.Var != "" {
			t := l.val()
			l.emit("%s = arith.constant true %s", t, loc(s.Pos))
			l.emit("ebpf.yield %s, %s, %s : i1, i64, i1 %s", t, rs, sent, loc(s.Pos))
		} else {
			l.emit("ebpf.yield %s", loc(s.Pos))
		}
	} else {
		l.emit("ebpf.ringbuf.submit %s : !ebpf.reservation<%s> %s", res, rec, loc(s.Pos))
	}
	if s.Op == "discard" {
	} else if s.Var != "" {
		t := l.val()
		l.emit("%s = arith.constant true %s", t, loc(s.Pos))
		l.emit("ebpf.yield %s, %s : i1, i64 %s", t, rs, loc(s.Pos))
	} else {
		l.emit("ebpf.yield %s", loc(s.Pos))
	}
	present := b.String()
	var ab strings.Builder
	l.b = &ab
	if s.Var != "" && s.Op == "discard" {
		f, z := l.val(), l.val()
		l.emit("%s = arith.constant false %s", f, loc(s.Pos))
		l.emit("%s = arith.constant 0 : i64 %s", z, loc(s.Pos))
		l.emit("ebpf.yield %s, %s, %s : i1, i64, i1 %s", f, z, f, loc(s.Pos))
	} else if s.Var != "" {
		f, z := l.val(), l.val()
		l.emit("%s = arith.constant false %s", f, loc(s.Pos))
		l.emit("%s = arith.constant 0 : i64 %s", z, loc(s.Pos))
		l.emit("ebpf.yield %s, %s : i1, i64 %s", f, z, loc(s.Pos))
	} else {
		l.emit("ebpf.yield %s", loc(s.Pos))
	}
	absent := ab.String()
	l.b, l.indent = saved, savedIndent
	decl, head := "", ""
	if s.Var != "" {
		decl, head = " -> i1, i64", ok+", "+st+" = "
		if s.Op == "discard" {
			decl, head = " -> i1, i64, i1", ok+", "+st+", "+sn+" = "
		}
	}
	l.emit("%sebpf.ringbuf.if_reserved %s : !ebpf.maybe_reservation<%s>%s present {", head, rv, rec, decl)
	l.emit("^present(%s: !ebpf.reservation<%s>):", res, rec)
	l.b.WriteString(present)
	l.emit("} absent {")
	l.b.WriteString(absent)
	l.emit("} %s", loc(s.Pos))
	if s.Var != "" {
		l.env[s.Var] = ssaVal{ok, "i1"}
		l.env[s.Var+"#status"] = ssaVal{st, "i64"}
		l.env[s.Var+"#sent"] = ssaVal{ok, "i1"}
		if s.Op == "discard" {
			l.env[s.Var+"#sent"] = ssaVal{sn, "i1"}
		}
	}
	return nil
}

func (c *progCtx) outputKStr(call *Node, as []*Node, r *RingDecl, meth string, f, st *RecordField, name, refVar string) (Stmt, bool) {
	sa := as[2]
	if k := c.prog.Kind; k != "fentry" && k != "tp_btf" && k != "netfilter" {
		c.add(Rejected, SB028TracingKind, sa, "`….str(:m)` reads a kernel string through a kernel pointer — a %s program has none (fentry / tp_btf arguments and netfilter's state / skb do)", k)
		return Stmt{}, false
	}
	recv := c.a.ref(sa, "receiver")
	if recv == nil || recv.Type != "LocalVariableReadNode" || c.kptrs[recv.Str["name"]] == nil {
		c.add(Rejected, SB033KernelTypeShape, sa, "`….str(:m)` reads a kernel string through a present kernel pointer — `q = %s.kptr_or_null(i, T)` and `if q`, then `q.str(:m)`", c.param)
		return Stmt{}, false
	}
	if cs, ok := c.callee(sa); !ok || cs != "KPtr#str" {
		if ok {
			c.add(Rejected, SB011ShadowedName, sa, "`str` resolves to %s, not BPF::KPtr#str", cs)
		}
		return Stmt{}, false
	}
	q := recv.Str["name"]
	kt := c.kptrs[q]
	sas := args(c.a, sa)
	if len(sas) != 1 || sas[0].Type != "SymbolNode" {
		c.add(Rejected, SB033KernelTypeShape, sa, "`%s.str(:m)` takes one Symbol literal — a :strptr member of %s", q, kt.Const)
		return Stmt{}, false
	}
	kf := kt.field(sas[0].Str["value"])
	if kf == nil || kf.Kind != "strptr" {
		c.add(Rejected, SB033KernelTypeShape, sas[0], "`%s.str(:%s)`: %s is not a :strptr member of %s (declare `%s: :strptr` in BPF.kernel_type — a char * member)", q, sas[0].Str["value"], sas[0].Str["value"], kt.Const, sas[0].Str["value"])
		return Stmt{}, false
	}
	os, ok := c.outputStrMake(call, as, r, meth, f, st, name, refVar)
	os.PtrOf, os.PtrOfKT, os.KStr = q, kt, kf.Name
	return os, ok
}
