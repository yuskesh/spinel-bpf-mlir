package frontend

import "math/big"

const skAssignAbsent = -2

func (c *progCtx) isSkAssign(v *Node) bool {
	return v != nil && v.Type == "CallNode" && v.Str["name"] == "assign" && c.a.ref(v, "receiver") != nil && c.a.ref(v, "receiver").Type == "ConstantReadNode"
}

func (c *progCtx) skAssignStmt(w *Node) (Stmt, bool) {
	name, v := w.Str["name"], c.a.ref(w, "value")
	if c.prog.Kind != "sk_lookup" {
		c.add(Rejected, SB028TracingKind, v, "`assign` (bpf_sk_assign) is accepted only in an sk_lookup program — a %s program has no socket lookup", c.prog.Kind)
		return Stmt{}, false
	}
	m := c.mapOf(c.a.ref(v, "receiver"), v)
	if m == nil {
		return Stmt{}, false
	}
	if m.Kind != "sockmap" {
		c.add(Rejected, SB002UnsupportedCall, v, "`%s.assign` needs a sockmap (`BPF::SockMap.new`) — %s is a %s", m.Const, m.Const, m.MapKind())
		return Stmt{}, false
	}
	if callee, ok := c.callee(v); !ok || callee != "SockMap#assign" {
		if ok {
			c.add(Rejected, SB011ShadowedName, v, "`assign` resolves to %s, not BPF::SockMap#assign", callee)
		}
		return Stmt{}, false
	}
	as := args(c.a, v)
	if len(as) != 2 || !c.isVarRead(as[0], c.param) {
		c.add(Rejected, SB028TracingKind, v, "`%s.assign(%s, k)` takes the program's context and a slot key", m.Const, c.param)
		return Stmt{}, false
	}
	if name == "_" {
		c.add(Rejected, SB026StatusIgnored, w, "the status of `%s.assign` is dropped — receive it as `st = %s.assign(%s, k)` and read `st` (0 is assigned, a negative errno or %d (no socket in the slot) is not)", m.Const, m.Const, c.param, skAssignAbsent)
		return Stmt{}, false
	}
	if _, used := c.env[name]; used || name == c.param || c.refs[name] != nil || c.wins[name] != nil {
		c.add(Rejected, SB026StatusIgnored, w, "`%s` is already bound — the status of `%s.assign` takes a fresh local", name, m.Const)
		return Stmt{}, false
	}
	if !c.kreadStatusOK(w, name, m.Const+".assign", "an empty slot or a refused socket is not an assigned one") {
		return Stmt{}, false
	}
	k := c.expr(as[1], "")
	if k == nil {
		return Stmt{}, false
	}
	if k.Bool {
		c.add(Rejected, SB001UnsupportedConstruct, as[1], "the key of `%s.assign` is an Integer (a sockmap slot), not a bool", m.Const)
		return Stmt{}, false
	}
	if !c.valueOK(k, as[1]) {
		return Stmt{}, false
	}
	c.env[name] = &varInfo{Iv: iv(new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 63)), new(big.Int))}
	return Stmt{Kind: "skassign", Var: name, Map: m, Key: k, Pos: c.z.pos(c.a, w)}, true
}

func (l *lowerer) skAssign(s Stmt) error {
	k, err := l.expr(s.Key)
	if err != nil {
		return err
	}
	k32, sr, st, ab := l.val(), l.val(), l.val(), l.val()
	l.emit("%s = arith.trunci %s : i64 to i32 %s", k32, k.name, loc(s.Pos))
	absent := skAssignAbsent
	if mutation("skassign-absent-zero") {
		absent = 0
	}
	l.emit("%s = arith.constant %d : i64 %s", ab, absent, loc(s.Pos))
	l.emit("%s = ebpf.sock.map_lookup %s[%s] : %s, i32 -> !ebpf.sock_ref_or_null %s", sr, l.maps[s.Map], k32, mapType(s.Map), loc(s.Pos))
	p, a := l.val(), l.val()
	l.emit("%s = ebpf.sock.ref_check %s : !ebpf.sock_ref_or_null -> i64 present {", st, sr)
	l.emit("^%s(%s: !ebpf.sock_ref):", p[1:], p)
	l.emit("  %s = ebpf.sk.assign %%ctx, %s : !ebpf.ctx<\"sk_lookup\">, !ebpf.sock_ref -> i64 %s", a, p, loc(s.Pos))
	l.emit("  ebpf.sock.release %s : !ebpf.sock_ref %s", p, loc(s.Pos))
	l.emit("  ebpf.yield %s : i64 %s", a, loc(s.Pos))
	l.emit("} absent {")
	l.emit("  ebpf.yield %s : i64 %s", ab, loc(s.Pos))
	l.emit("} %s", loc(s.Pos))
	l.env[s.Var] = ssaVal{st, "i64"}
	return nil
}
