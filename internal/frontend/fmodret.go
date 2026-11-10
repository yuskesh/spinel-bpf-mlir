package frontend

import "math/big"

func (z *analyzer) fmodRetDecl(a *AST, n *Node, as []*Node, bad func(string, ...any) (rootDecl, bool)) (rootDecl, bool) {
	shape := "`BPF.fmod_ret :name, \"kernel_function\", nargs: N, args: {0 => :i32}`"
	if len(as) != 3 || as[0].Type != "SymbolNode" || as[1].Type != "StringNode" || as[1].Str["content"] == "" || as[2].Type != "KeywordHashNode" {
		return bad("a fmod_ret program is declared as %s — a Symbol, a non-empty String literal and `nargs:`", shape)
	}
	r := rootDecl{Name: as[0].Str["value"], Kind: "fmod_ret", Pos: z.pos(a, n), Target: as[1].Str["content"], Nargs: -1, Ret: "i32"}
	var hv *Node
	for _, e := range a.arr(as[2], "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || v == nil || k.Type != "SymbolNode" {
			return bad("the options of %s are `nargs:` and `args:`", shape)
		}
		switch k.Str["value"] {
		case "nargs":
			nb, ok := z.literal(a, v)
			if v.Type != "IntegerNode" || !ok || !nb.IsInt64() || nb.Int64() < 0 || nb.Int64() > 12 || r.Nargs >= 0 {
				return bad("`nargs:` of %s is the target function's argument count, an Integer literal 0..12, given once", shape)
			}
			r.Nargs = int(nb.Int64())
		case "args":
			if hv != nil {
				return bad("`args:` of %s is given once", shape)
			}
			hv = v
		default:
			return bad("the options of %s are `nargs:` and `args:` — the return type is i32", shape)
		}
	}
	if r.Nargs < 0 {
		return bad("%s needs `nargs:` — the target function's argument count", shape)
	}
	if hv == nil {
		return r, true
	}
	badArg := func(format string, x ...any) (rootDecl, bool) {
		z.add(Rejected, SB033KernelTypeShape, z.pos(a, n), format, x...)
		return rootDecl{}, false
	}
	if hv.Type != "HashNode" || len(a.arr(hv, "elements")) == 0 {
		return badArg("`args:` of %s is a non-empty Hash literal of argument index => integer type", shape)
	}
	seen := map[int]bool{}
	for _, e := range a.arr(hv, "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || k.Type != "IntegerNode" || v == nil {
			return badArg("each fmod_ret argument is `i => :i32` with i an Integer literal")
		}
		nb, ok := z.literal(a, k)
		if !ok || !nb.IsInt64() || nb.Int64() < 0 || nb.Int64() >= int64(r.Nargs) || seen[int(nb.Int64())] {
			return badArg("a fmod_ret argument index is 0..nargs−1 (%d) and appears once", r.Nargs-1)
		}
		i := int(nb.Int64())
		seen[i] = true
		if v.Type != "SymbolNode" {
			return badArg("argument %d: a fmod_ret argument is an integer type Symbol (:i8 … :u64) — bpf-mlir's fmod_ret reads integer arguments only (IntArgs)", i)
		}
		if _, ok := recordTypes[v.Str["value"]]; !ok {
			return badArg("argument %d: an integer argument's type is one of :i8 … :i64 / :u8 … :u64", i)
		}
		r.TArgs = append(r.TArgs, TpArg{Idx: i, Type: v.Str["value"]})
	}
	return r, true
}

func (c *progCtx) isFmodReturn(n *Node) bool {
	return n != nil && n.Type == "CallNode" && n.Str["name"] == "fmod_return" && constName(c.a, c.a.ref(n, "receiver")) == "BPF"
}

func (c *progCtx) fmodReturnArg(v *Node) *Node {
	callee, ok := c.callee(v)
	if !ok {
		return nil
	}
	as := args(c.a, v)
	if callee != "BPF.fmod_return" || len(as) != 1 {
		c.add(Rejected, SB011ShadowedName, v, "`BPF.fmod_return` resolves to %q (with %d arguments), not the library's BPF.fmod_return(e)", callee, len(as))
		return nil
	}
	return as[0]
}

func (c *progCtx) fmodNonZeroI32(iv Ival, n *Node) bool {
	if iv.Lo.Sign() <= 0 && iv.Hi.Sign() >= 0 {
		c.add(Rejected, SB014SemanticGap, n, "the value of `BPF.fmod_return(e)` may be 0 (its range is %s) — 0 means \"call the original function\", so a replaced return value must be provably non-zero; return BPF::FMOD_CALL for that path instead", iv)
		return false
	}
	if iv.Lo.Cmp(i32Min) < 0 || iv.Hi.Cmp(i32Max) > 0 {
		c.add(Rejected, SB014SemanticGap, n, "the value of `BPF.fmod_return(e)` may not fit the i32 return value (its range is %s) — narrow it first", iv)
		return false
	}
	return true
}

func (c *progCtx) fmodVerdict(n, v *Node) {
	if c.prog.Kind != "fmod_ret" {
		c.add(Rejected, SB028TracingKind, v, "`BPF.fmod_return` ends only a fmod_ret program — %s", verdictReturns(c.prog.Kind))
		return
	}
	en := c.fmodReturnArg(v)
	if en == nil {
		return
	}
	if c.prog.GuardVerdict != "" && en.Type != "IntegerNode" {
		c.add(Rejected, SB006NonConstant, en, "with a guard `return … if cond`, the last `BPF.fmod_return(e)` takes an integer literal — the terminal arith.select of bpf-mlir's ebpf.return chooses between program-level values")
		return
	}
	e := c.expr(en, "")
	if e == nil {
		return
	}
	if e.Bool {
		c.add(Rejected, SB001UnsupportedConstruct, en, "`BPF.fmod_return(e)` takes an Integer, not a bool")
		return
	}
	if !c.valueOK(e, en) || !c.fmodNonZeroI32(e.Iv, en) {
		return
	}
	c.prog.Verdict, c.prog.FmodVal, c.prog.VerdictPos = "done", e, c.z.pos(c.a, n)
}

func (c *progCtx) fmodGuardValue(r, v *Node) (*big.Int, bool) {
	en := c.fmodReturnArg(v)
	if en == nil {
		return nil, false
	}
	if en.Type != "IntegerNode" || !c.typed(en) {
		c.add(Rejected, SB006NonConstant, en, "a guard `return BPF.fmod_return(e) if cond` takes an integer literal e — the terminal arith.select of bpf-mlir's ebpf.return chooses between program-level values")
		return nil, false
	}
	lit, ok := c.z.literal(c.a, en)
	if !ok || !c.fmodNonZeroI32(Ival{lit, lit}, en) {
		return nil, false
	}
	return lit, true
}

func (l *lowerer) lowerFmodReturn(p *Program) error {
	last := l.val()
	if p.FmodVal != nil {
		x, err := l.expr(p.FmodVal)
		if err != nil {
			return err
		}
		l.emit("%s = arith.trunci %s : i64 to i32 %s", last, x.name, loc(p.VerdictPos))
	} else {
		l.emit("%s = arith.constant 0 : i32 %s", last, loc(p.VerdictPos))
	}
	r := last
	if p.GuardVerdict != "" {
		g := l.val()
		gv := big.NewInt(0)
		if p.FmodGuard != nil {
			gv = p.FmodGuard
		}
		l.emit("%s = arith.constant %s : i32 %s", g, gv, loc(p.VerdictPos))
		t, f := g, last
		if mutation("fmod-select-swap") {
			t, f = f, t
		}
		r = l.val()
		l.emit("%s = arith.select %s, %s, %s : i32 %s", r, l.fired, t, f, loc(p.VerdictPos))
	}
	l.emit("ebpf.return %s : i32 %s", r, loc(p.VerdictPos))
	return nil
}

func fmodArgsSchema(p *Program) []any {
	if len(p.TArgs) == 0 {
		return nil
	}
	out := make([]any, p.Nargs)
	for _, a := range p.TArgs {
		out[a.Idx] = traceInt(a.Type)
	}
	return out
}

func fmodUses(p *Program) bool {
	return p.Kind == "fmod_ret" && (p.FmodVal != nil || p.FmodGuard != nil)
}
