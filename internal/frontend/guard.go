package frontend

func (c *progCtx) guardOf(n *Node) *Node {
	if n.Type != "IfNode" && n.Type != "UnlessNode" {
		return nil
	}
	if n.Type == "IfNode" && c.a.ref(n, "subsequent") != nil || n.Type == "UnlessNode" && c.a.ref(n, "else_clause") != nil {
		return nil
	}
	st := c.a.ref(n, "statements")
	if st == nil || len(c.a.arr(st, "body")) != 1 {
		return nil
	}
	r := c.a.arr(st, "body")[0]
	if r.Type != "ReturnNode" {
		return nil
	}
	return r
}

func (c *progCtx) guardStmts(ns []*Node) []Stmt {
	for i, n := range ns {
		r := c.guardOf(n)
		if r == nil {
			continue
		}
		out := c.stmts(ns[:i], "")
		c.guardReturns[r] = true
		var as []*Node
		if args := c.a.ref(r, "arguments"); args != nil {
			as = c.a.arr(args, "arguments")
		}
		table := verdictsOf(c.prog.Kind)
		if len(as) != 1 {
			c.add(Rejected, SB008ProgramShape, r, "a guard `return` must return one %s (%s)", verdictWant(c.prog.Kind, "BPF::XDP_* constant"), verdictWant(c.prog.Kind, "`return BPF::XDP_DROP if cond`"))
			return out
		}
		cn := constName(c.a, as[0])
		v := ""
		if c.prog.Kind == "fmod_ret" && c.isFmodReturn(as[0]) {
			lit, ok := c.fmodGuardValue(r, as[0])
			if !ok {
				return out
			}
			if c.prog.FmodGuard != nil && c.prog.FmodGuard.Cmp(lit) != 0 {
				c.add(Rejected, SB008ProgramShape, r, "the early returns return BPF.fmod_return(%s) and BPF.fmod_return(%s) — the terminal arith.select chooses between only two values (the early one and the last one), so every guard returns the same value", c.prog.FmodGuard, lit)
				return out
			}
			c.prog.FmodGuard, v = lit, "value"
		} else if as[0].Type != "ConstantPathNode" || len(cn) < 5 || cn[:5] != "BPF::" || table[cn[5:]] == "" {
			c.add(Rejected, SB008ProgramShape, r, "a guard `return` must return one %s, got %s", verdictWant(c.prog.Kind, "BPF::XDP_* constant"), as[0].Type)
			return out
		} else {
			v = table[cn[5:]]
		}
		if c.prog.GuardVerdict != "" && c.prog.GuardVerdict != v {
			c.add(Rejected, SB008ProgramShape, r, "the early returns return %s and %s — bpf-mlir's ebpf.verdict.if chooses between only two verdicts (the early one and the last one), so every guard returns the same verdict", c.prog.GuardVerdict, v)
			return out
		}
		c.prog.GuardVerdict = v
		cond := c.cond(c.a.ref(n, "predicate"), "")
		if cond == nil {
			return out
		}
		if n.Type == "UnlessNode" {
			cond = &Expr{Kind: "not", Args: []*Expr{cond}, Bool: true, Pos: cond.Pos}
		}
		pre := c.env
		c.env = narrowEnv(pre, cond, false)
		rest := c.guardStmts(ns[i+1:])
		return append(out, Stmt{Kind: "guard", Cond: cond, Else: rest, Op: v, Pos: c.z.pos(c.a, n)})
	}
	return c.stmts(ns, "")
}
