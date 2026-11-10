package frontend

func (c *progCtx) outputTpStr(call *Node, as []*Node, r *RingDecl, meth string, f, st *RecordField, name, refVar string) (Stmt, bool) {
	sa := as[2]
	if sa.Type != "CallNode" || sa.Str["name"] != "str_field" || !c.isVarRead(c.a.ref(sa, "receiver"), c.param) {
		c.add(Rejected, SB028TracingKind, sa, "the third argument of %s in a tracepoint program is `%s.str_field(:f)` itself (a user string is not a value on the eBPF side — not through a local)", meth, c.param)
		return Stmt{}, false
	}
	if cs, ok := c.callee(sa); !ok || cs != "TracepointCtx#str_field" {
		if ok {
			c.add(Rejected, SB011ShadowedName, sa, "`str_field` resolves to %s, not BPF::TracepointCtx#str_field", cs)
		}
		return Stmt{}, false
	}
	sas := args(c.a, sa)
	if len(sas) != 1 || sas[0].Type != "SymbolNode" {
		c.add(Rejected, SB028TracingKind, sa, "`%s.str_field(:f)` takes one Symbol literal — a :user_str field declared in `BPF.tracepoint … fields:`", c.param)
		return Stmt{}, false
	}
	fn := sas[0].Str["value"]
	var tf *TpField
	for i := range c.prog.TFields {
		if c.prog.TFields[i].Name == fn {
			tf = &c.prog.TFields[i]
		}
	}
	if tf == nil {
		c.add(Rejected, SB028TracingKind, sas[0], "`%s.str_field(:%s)`: %s is not declared in `BPF.tracepoint … fields:` (declare `%s: [offset, :user_str]` from the tracefs format)", c.param, fn, fn, fn)
		return Stmt{}, false
	}
	if tf.Type != "user_str" {
		c.add(Rejected, SB028TracingKind, sas[0], "`%s.str_field(:%s)`: %s is declared :%s — read it with `%s.field(:%s)`", c.param, fn, fn, tf.Type, c.param, fn)
		return Stmt{}, false
	}
	os, ok := c.outputStrMake(call, as, r, meth, f, st, name, refVar)
	os.TpStr = tf
	return os, ok
}
