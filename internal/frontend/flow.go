package frontend

import "math/big"

type flowField struct {
	Bits  int
	Count int
}

var flowFields = map[string]flowField{
	"nhoff": {16, 1}, "thoff": {16, 1}, "addr_proto": {16, 1}, "is_frag": {8, 1}, "is_first_frag": {8, 1}, "is_encap": {8, 1}, "ip_proto": {8, 1},
	"n_proto": {16, 1}, "sport": {16, 1}, "dport": {16, 1}, "ipv4_src": {32, 1}, "ipv4_dst": {32, 1}, "ipv6_src": {32, 4}, "ipv6_dst": {32, 4},
	"flags": {32, 1}, "flow_label": {32, 1},
}

func (c *progCtx) flowFieldArgs(n *Node, as []*Node, what string) (string, flowField, int64, bool) {
	if len(as) < 1 || as[0].Type != "SymbolNode" {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.%s` takes the flow key's name as a Symbol literal (`:nhoff`, `:ipv4_src`, `:ipv6_src` with an index …)", c.param, what)
		return "", flowField{}, 0, false
	}
	name := as[0].Str["value"]
	f, ok := flowFields[name]
	if !ok {
		c.add(Rejected, SB002UnsupportedCall, as[0], "`:%s` is not a field of struct bpf_flow_keys (nhoff thoff addr_proto is_frag is_first_frag is_encap ip_proto n_proto sport dport ipv4_src ipv4_dst ipv6_src[i] ipv6_dst[i] flags flow_label)", name)
		return "", flowField{}, 0, false
	}
	idx := int64(-1)
	switch {
	case f.Count == 4 && len(as) == 2:
		b, lok := c.z.literal(c.a, as[1])
		if as[1].Type != "IntegerNode" || !lok || !b.IsInt64() || b.Int64() < 0 || b.Int64() > 3 {
			c.add(Rejected, SB014SemanticGap, as[1], "the index of `:%s` is an Integer literal 0..3", name)
			return "", flowField{}, 0, false
		}
		idx = b.Int64()
	case f.Count == 4:
		c.add(Rejected, SB002UnsupportedCall, n, "`:%s` has 4 elements — give an Integer literal index 0..3 (`%s.%s(:%s, i…)`)", name, c.param, what, name)
		return "", flowField{}, 0, false
	case len(as) != 1:
		c.add(Rejected, SB002UnsupportedCall, n, "`:%s` has no index", name)
		return "", flowField{}, 0, false
	}
	return name, f, idx, true
}

func (c *progCtx) flowKeyRead(n *Node, refVar string) *Expr {
	callee, ok := c.callee(n)
	if !ok {
		return nil
	}
	if callee != "FlowCtx#key" {
		c.add(Rejected, SB011ShadowedName, n, "`key` resolves to %s, not BPF::FlowCtx#key", callee)
		return nil
	}
	name, f, idx, ok := c.flowFieldArgs(n, args(c.a, n), "key")
	if !ok {
		return nil
	}
	return &Expr{Kind: "fkload", Field: &RecordField{Name: name, Bits: f.Bits}, Idx: idx, Iv: widthRange(f.Bits, false), Pos: c.z.pos(c.a, n)}
}

func (c *progCtx) flowKeyStore(n *Node, refVar string) (Stmt, bool) {
	callee, ok := c.callee(n)
	if !ok {
		return Stmt{}, false
	}
	if callee != "FlowCtx#set_key" {
		c.add(Rejected, SB011ShadowedName, n, "`set_key` resolves to %s, not BPF::FlowCtx#set_key", callee)
		return Stmt{}, false
	}
	as := args(c.a, n)
	if len(as) < 2 {
		c.add(Rejected, SB002UnsupportedCall, n, "`%s.set_key(:f, [i,] v)` takes the key's name, an index for ipv6_src / ipv6_dst, and the value", c.param)
		return Stmt{}, false
	}
	name, f, idx, ok := c.flowFieldArgs(n, as[:len(as)-1], "set_key")
	if !ok {
		return Stmt{}, false
	}
	vn := as[len(as)-1]
	e := c.expr(vn, refVar)
	if e == nil {
		return Stmt{}, false
	}
	r := widthRange(f.Bits, false)
	if e.Bool || e.Wide || !e.Iv.within(new(big.Int).Set(r.Lo), new(big.Int).Set(r.Hi)) {
		c.add(Rejected, SB014SemanticGap, vn, "the value's range %s does not fit bpf_flow_keys.%s (u%d %s) — the store would truncate silently; narrow it", e.Iv, name, f.Bits, r)
		return Stmt{}, false
	}
	return Stmt{Kind: "fkstore", Path: name, Count: idx, Val: e, Pos: c.z.pos(c.a, n)}, true
}
