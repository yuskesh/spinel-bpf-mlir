package frontend

import "math/big"

const kreadMaxOffset = 4095

func (c *progCtx) kreadStmt(n *Node) (Stmt, bool) {
	s, ok := c.kreadBind(n)
	if !ok {
		for _, t := range c.a.arr(n, "lefts") {
			if t.Type == "LocalVariableTargetNode" {
				c.poisoned[t.Str["name"]] = true
			}
		}
	}
	return s, ok
}

func (c *progCtx) kreadBind(n *Node) (Stmt, bool) {
	bad := func(at *Node, format string, x ...any) (Stmt, bool) {
		c.add(Rejected, SB028TracingKind, at, format, x...)
		return Stmt{}, false
	}
	ts, v := c.a.arr(n, "lefts"), c.a.ref(n, "value")
	if c.prog.Kind != "kprobe" || v == nil || v.Type != "CallNode" || v.Str["name"] != "read" || len(ts) != 2 || c.a.ref(n, "rest") != nil || len(c.a.arr(n, "rights")) != 0 {
		return bad(n, "a multiple assignment is accepted only as `v, st = %s.read(n, offset, :type)` in a kprobe program (two locals — the value and the status)", c.param)
	}
	for _, t := range ts {
		if t.Type != "LocalVariableTargetNode" {
			return bad(t, "`… = %s.read(…)` assigns two plain locals (the value and the status)", c.param)
		}
	}
	callee, ok := c.callee(v)
	if !ok {
		return Stmt{}, false
	}
	if callee != "KprobeCtx#read" {
		c.add(Rejected, SB011ShadowedName, v, "`read` resolves to %q, not BPF::KprobeCtx#read", callee)
		return Stmt{}, false
	}
	as := args(c.a, v)
	if len(as) != 3 || as[0].Type != "IntegerNode" || as[1].Type != "IntegerNode" || as[2].Type != "SymbolNode" {
		return bad(v, "`%s.read(n, offset, :type)` takes a parameter number, an offset (Integer literals) and a type Symbol :i8 … :u64", c.param)
	}
	nb, ok1 := c.z.literal(c.a, as[0])
	ob, ok2 := c.z.literal(c.a, as[1])
	if !ok1 || !ok2 {
		return Stmt{}, false
	}
	var kp *KParam
	for k := range c.prog.Params {
		if nb.IsInt64() && int64(c.prog.Params[k].N) == nb.Int64() {
			kp = &c.prog.Params[k]
		}
	}
	if kp == nil || kp.Type != "ptr" {
		return bad(as[0], "`%s.read(%s, …)`: parameter %s is not declared :ptr in `BPF.kprobe … params:`", c.param, nb, nb)
	}
	if !ob.IsInt64() || ob.Int64() < 0 || ob.Int64() > kreadMaxOffset {
		return bad(as[1], "`%s.read(%s, %s, …)`: the offset is 0..%d", c.param, nb, ob, kreadMaxOffset)
	}
	t := as[2].Str["value"]
	rt, ok := recordTypes[t]
	if !ok {
		return bad(as[2], "`%s.read(…, :%s)`: the type is one of :i8 … :i64 / :u8 … :u64", c.param, t)
	}
	vn, sn := ts[0].Str["name"], ts[1].Str["name"]
	if sn == "_" {
		c.add(Rejected, SB026StatusIgnored, ts[1], "the status of `%s.read` is dropped — a failed read returns 0 like a real 0; receive it as `v, st = %s.read(…)` and read `st` (e.g. `if st == 0`)", c.param, c.param)
		return Stmt{}, false
	}
	for _, name := range []string{vn, sn} {
		if name == "_" {
			continue
		}
		if _, used := c.env[name]; used || name == c.param || c.refs[name] != nil || c.wins[name] != nil || c.kptrs[name] != nil {
			return bad(n, "`%s` is already bound — `v, st = %s.read(…)` binds two fresh names", name, c.param)
		}
	}
	if !c.kreadStatusOK(ts[1], sn, c.param+".read", "a failed read returns 0 like a real 0") {
		return Stmt{}, false
	}
	f := &RecordField{Name: t, Bits: rt[0], Signed: rt[1] == 1}
	if vn != "_" {
		vi := &varInfo{Iv: widthRange(f.Bits, f.Signed)}
		if f.Bits == 64 && !f.Signed {
			vi.Iv = iv(new(big.Int), new(big.Int).Set(u64Max))
		}
		c.env[vn] = vi
	}
	c.env[sn] = &varInfo{Iv: iv(new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 63)), new(big.Int))}
	return Stmt{Kind: "kread", Var: vn, Path: sn, Field: f, Count: nb.Int64(), Len: ob.Int64(), Pos: c.z.pos(c.a, n)}, true
}

func (c *progCtx) kreadStatusOK(t *Node, name, what, failed string) bool {
	writes, reads := 0, 0
	walk(c.a, c.def, func(x *Node) bool {
		if x.Str["name"] != name {
			return true
		}
		switch x.Type {
		case "LocalVariableWriteNode", "LocalVariableOperatorWriteNode", "LocalVariableOrWriteNode", "LocalVariableAndWriteNode", "LocalVariableTargetNode":
			writes++
		case "LocalVariableReadNode":
			reads++
		}
		return true
	})
	switch {
	case writes != 1:
		c.add(Rejected, SB026StatusIgnored, t, "`%s` holds the status of `%s` but is assigned %d times — a status local is assigned once", name, what, writes)
		return false
	case reads == 0:
		c.add(Rejected, SB026StatusIgnored, t, "`%s` holds the status of `%s` but is never read — check it (e.g. `if %s == 0`): %s", name, what, name, failed)
		return false
	}
	return true
}
