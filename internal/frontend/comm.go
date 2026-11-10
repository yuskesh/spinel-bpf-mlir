package frontend

import "fmt"

func outputCommShape(r *RingDecl) string {
	return fmt.Sprintf("`r = %s.output_comm(%s.new(…), :<[:u8, 16] member>, :<i64 status member>)` then `if r` (read `r.status` inside), or `_ = %s.output_comm(…)`", r.Const, r.Record.Const, r.Const)
}

func hasComm(res *Result) bool {
	var in func(ss []Stmt) bool
	in = func(ss []Stmt) bool {
		for _, s := range ss {
			if s.Comm || in(s.Then) || in(s.Else) {
				return true
			}
		}
		return false
	}
	for _, p := range res.Programs {
		if in(p.Body) {
			return true
		}
	}
	return false
}

func (c *progCtx) outputComm(call *Node, name, refVar string) (Stmt, bool) {
	r := c.ringOf(c.a.ref(call, "receiver"))
	callee, ok := c.callee(call)
	if !ok {
		return Stmt{}, false
	}
	if callee != "RingBuf#output_comm" {
		c.add(Rejected, SB011ShadowedName, call, "`output_comm` resolves to %s, not BPF::RingBuf#output_comm", callee)
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
	if len(as) == 2 || len(as) == 3 && member(as[2]) == nil {
		c.add(Rejected, SB024RecordShape, call, "output_comm needs a status member: add `status: :i64` to BPF.record(%s, …) and pass it as the third argument — the raw status of bpf_get_current_comm — %s", r.Record.Const, outputCommShape(r))
		return Stmt{}, false
	}
	if len(as) != 3 {
		c.add(Rejected, SB002UnsupportedCall, call, "output_comm takes three arguments — %s", outputCommShape(r))
		return Stmt{}, false
	}
	f, st := member(as[1]), member(as[2])
	if f == nil || f.Count != 16 || f.Bits != 8 || f.Signed {
		c.add(Rejected, SB024RecordShape, as[1], "the comm member of output_comm must be a [:u8, 16] member of %s (TASK_COMM_LEN — bpf_get_current_comm fills 16 bytes)", r.Record.Const)
		return Stmt{}, false
	}
	if st.Count != 0 || st.Bits != 64 || !st.Signed {
		c.add(Rejected, SB024RecordShape, as[2], "the status member %s of output_comm must be :i64 (the raw status of bpf_get_current_comm)", st.Name)
		return Stmt{}, false
	}
	os, ok := c.outputStrMake(call, as[:1], r, "output_comm", f, st, name, refVar)
	os.Comm = true
	return os, ok
}
