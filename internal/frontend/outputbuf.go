package frontend

import "fmt"

func outputBufForm(param string) string {
	return fmt.Sprintf("`r = R.output_buf(S.new(…), :<u8 array member>, %s.buf_arg(n), <length>, :<i64 status member>, :<i32 count member>)` then `if r`, or `_ = R.output_buf(…)`", param)
}

func (c *progCtx) outputBuf(call *Node, name, refVar string) (Stmt, bool) {
	r := c.ringOf(c.a.ref(call, "receiver"))
	if c.prog.Kind != "uprobe" {
		c.add(Rejected, SB028TracingKind, call, "`%s.output_buf` reads a user buffer (`ctx.buf_arg(n)` of a :user_buf parameter in a uprobe program) — a %s program has none", r.Const, c.prog.Kind)
		return Stmt{}, false
	}
	callee, ok := c.callee(call)
	if !ok {
		return Stmt{}, false
	}
	if callee != "RingBuf#output_buf" {
		c.add(Rejected, SB011ShadowedName, call, "`output_buf` resolves to %s, not BPF::RingBuf#output_buf", callee)
		return Stmt{}, false
	}
	as := args(c.a, call)
	if len(as) != 6 {
		c.add(Rejected, SB024RecordShape, call, "output_buf takes six arguments — %s", outputBufForm(c.param))
		return Stmt{}, false
	}
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
	f, st, cn := member(as[1]), member(as[4]), member(as[5])
	if f == nil || f.Count == 0 || f.Bits != 8 || f.Signed {
		c.add(Rejected, SB024RecordShape, as[1], "the buffer member of output_buf must be a :u8 array member of %s (`data: [:u8, 64]` — bpf-mlir's user.read fills a 1-dimensional 8-bit array)", r.Record.Const)
		return Stmt{}, false
	}
	if st == nil || st.Count != 0 || st.Bits != 64 || !st.Signed {
		c.add(Rejected, SB024RecordShape, as[4], "the status member of output_buf must be an :i64 member of %s (the raw status of probe_read_user — 0 or a negative errno)", r.Record.Const)
		return Stmt{}, false
	}
	if cn == nil || cn.Count != 0 || cn.Bits != 32 || !cn.Signed {
		c.add(Rejected, SB024RecordShape, as[5], "the count member of output_buf must be an :i32 member of %s (the clamped length max(0, min(length, N)) — not the bytes read)", r.Record.Const)
		return Stmt{}, false
	}
	sa := as[2]
	if sa.Type != "CallNode" || sa.Str["name"] != "buf_arg" || !c.isVarRead(c.a.ref(sa, "receiver"), c.param) {
		c.add(Rejected, SB028TracingKind, sa, "the third argument of output_buf is `%s.buf_arg(n)` itself (a user buffer is not a value on the eBPF side — not through a local)", c.param)
		return Stmt{}, false
	}
	if cs, ok := c.callee(sa); !ok || cs != "UprobeCtx#buf_arg" {
		if ok {
			c.add(Rejected, SB011ShadowedName, sa, "`buf_arg` resolves to %s, not BPF::UprobeCtx#buf_arg", cs)
		}
		return Stmt{}, false
	}
	kp := c.uprobeParam(sa, args(c.a, sa))
	if kp == nil {
		return Stmt{}, false
	}
	if kp.Type != "user_buf" {
		c.add(Rejected, SB028TracingKind, sa, "`%s.buf_arg(%d)`: parameter %d is declared :%s, not :user_buf", c.param, kp.N, kp.N, kp.Type)
		return Stmt{}, false
	}
	ln := c.expr(as[3], refVar)
	if ln == nil {
		return Stmt{}, false
	}
	os, ok := c.outputStrMake(call, []*Node{as[0], as[1], as[2], as[4]}, r, "output_buf", f, st, name, refVar)
	if !ok {
		return Stmt{}, false
	}
	os.Buf, os.BufLen, os.CountF, os.Len = true, ln, cn, int64(kp.N)
	return os, true
}
