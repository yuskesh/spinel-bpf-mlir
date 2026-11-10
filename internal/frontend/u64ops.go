package frontend

import (
	"fmt"
	"math/big"
)

// The u64 intrinsics: modular u64 arithmetic on the eBPF side (BPF.u64_add / u64_sub / u64_mul / u64_div, BPF.time_before).
// Wrapping is their meaning, so no interval check guards the result; a u64 operand is a Wide value or an Integer in
// [0, 2^63 − 1] (the same 64 bits), and u64_div's divisor is an Integer whose interval is within [1, 2^63 − 1].
var u64Ops = map[string]bool{"u64_add": true, "u64_sub": true, "u64_mul": true, "u64_div": true, "time_before": true}

// u64Op reads `BPF.<op>(a, b)`.
func (c *progCtx) u64Op(n *Node, name string, as []*Node, refVar string, p Pos) *Expr {
	if len(as) != 2 {
		c.add(Rejected, SB001UnsupportedConstruct, n, "`BPF.%s` takes two operands, got %d", name, len(as))
		return nil
	}
	callee, ok := c.callee(n)
	if !ok {
		return nil
	}
	if callee != "BPF."+name {
		c.add(Rejected, SB011ShadowedName, n, "`BPF.%s` resolves to %q, not the library's BPF.%s", name, callee, name)
		return nil
	}
	a := c.u64Operand(name, 1, as[0], refVar)
	var b *Expr
	if name == "u64_div" {
		b = c.u64Divisor(as[1], refVar)
	} else {
		b = c.u64Operand(name, 2, as[1], refVar)
	}
	if a == nil || b == nil {
		return nil
	}
	e := &Expr{Kind: "u64op", Op: name, Args: []*Expr{a, b}, Pos: p}
	if name == "time_before" {
		e.Bool = true
		return e
	}
	e.Iv, e.Wide = iv(new(big.Int), new(big.Int).Set(u64Max)), true
	return e
}

// u64Operand reads a u64 operand: a Wide value, or an Integer in [0, 2^63 − 1].
func (c *progCtx) u64Operand(op string, i int, x *Node, refVar string) *Expr {
	e := c.expr(x, refVar)
	if e == nil {
		return nil
	}
	if e.Bool {
		c.add(Rejected, SB014SemanticGap, x, "operand %d of `BPF.%s` is a bool, not a u64 value", i, op)
		return nil
	}
	if e.Wide {
		return e
	}
	r := widthRange(64, false)
	if !e.Iv.within(r.Lo, r.Hi) {
		c.add(Rejected, SB014SemanticGap, x, "operand %d of `BPF.%s` is an Integer that may be negative (its interval %s is not within %s) — a u64 operand is a u64 value or a non-negative Integer", i, op, e.Iv, r)
		return nil
	}
	return e
}

// u64Divisor reads u64_div's divisor: an Integer whose interval is within [1, 2^63 − 1] (Ruby's `/` by 0 raises; the subset never
// turns 0 into 1).
func (c *progCtx) u64Divisor(x *Node, refVar string) *Expr {
	e := c.expr(x, refVar)
	if e == nil {
		return nil
	}
	if e.Bool {
		c.add(Rejected, SB014SemanticGap, x, "the divisor of `BPF.u64_div` is a bool, not an Integer")
		return nil
	}
	if e.Wide {
		c.add(Rejected, SB014SemanticGap, x, "the divisor of `BPF.u64_div` is a u64 value, which may be 0 — narrow it into an Integer within [1, 2^63 − 1] with an `if`")
		return nil
	}
	hi := widthRange(64, false).Hi
	if !e.Iv.within(bigOne, hi) {
		c.add(Rejected, SB014SemanticGap, x, "the divisor of `BPF.u64_div` may be 0 (its interval %s is not within [1, %s]) — narrow it with an `if`, e.g. `d = 1` / `if w > 0` / `d = w`", e.Iv, hi)
		return nil
	}
	return e
}

// u64Expr lowers a u64 intrinsic (i64 operations without nsw / nuw / exact flags).
func (l *lowerer) u64Expr(e *Expr) (ssaVal, error) {
	a, err := l.expr(e.Args[0])
	if err != nil {
		return ssaVal{}, err
	}
	b, err := l.expr(e.Args[1])
	if err != nil {
		return ssaVal{}, err
	}
	at := loc(e.Pos)
	v := l.val()
	switch e.Op {
	case "u64_add", "u64_sub", "u64_mul":
		op := map[string]string{"u64_add": "arith.addi", "u64_sub": "arith.subi", "u64_mul": "arith.muli"}[e.Op]
		l.emit("%s = %s %s, %s : i64 %s", v, op, a.name, b.name, at)
		return ssaVal{v, "i64"}, nil
	case "time_before": // (s64)(a − b) < 0
		z := l.val()
		l.emit("%s = arith.subi %s, %s : i64 %s", v, a.name, b.name, at)
		l.emit("%s = arith.constant 0 : i64 %s", z, at)
		r := l.val()
		l.emit("%s = arith.cmpi slt, %s, %s : i64 %s", r, v, z, at)
		return ssaVal{r, "i1"}, nil
	case "u64_div": // maxui serves bpf-mlir's ArithLegality proof; it is the identity on the divisor the frontend proved ≥ 1
		one := v
		l.emit("%s = arith.constant 1 : i64 %s", one, at)
		d := l.val()
		l.emit("%s = arith.maxui %s, %s : i64 %s", d, b.name, one, at)
		q := l.val()
		l.emit("%s = arith.divui %s, %s : i64 %s", q, a.name, d, at)
		return ssaVal{q, "i64"}, nil
	}
	return ssaVal{}, fmt.Errorf("u64 intrinsic %q has no lowering", e.Op)
}
