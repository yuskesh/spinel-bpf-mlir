package frontend

import (
	"fmt"
	"math/big"
)

// Interval analysis: the closed interval of the mathematical value of a Ruby Integer expression, held in math/big.
// An operation whose result may not fit in i64 is rejected — when it fits, nothing wraps, so Ruby (CRuby's arbitrary precision,
// Spinel's i64) and BPF (i64) compute the same value.

// Ival is the closed interval [Lo, Hi].
type Ival struct{ Lo, Hi *big.Int }

var (
	bigZero   = big.NewInt(0)
	bigOne    = big.NewInt(1)
	i64Min    = new(big.Int).Neg(new(big.Int).Lsh(bigOne, 63))
	i64Max    = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 63), bigOne)
	u32Max    = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 32), bigOne)
	i32Min    = new(big.Int).Neg(new(big.Int).Lsh(bigOne, 31))
	i32Max    = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 31), bigOne)
	u64Max    = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 64), bigOne)
	fullI64   = Ival{i64Min, i64Max}
	literalLo = new(big.Int).Add(i64Min, bigOne) // literals exclude −2^63 (Spinel's nil marker)
)

func point(v *big.Int) Ival { return Ival{new(big.Int).Set(v), new(big.Int).Set(v)} }

func iv(lo, hi *big.Int) Ival { return Ival{lo, hi} }

func (a Ival) String() string { return fmt.Sprintf("[%s, %s]", a.Lo, a.Hi) }

// within reports whether a lies inside [lo, hi].
func (a Ival) within(lo, hi *big.Int) bool { return a.Lo.Cmp(lo) >= 0 && a.Hi.Cmp(hi) <= 0 }

func (a Ival) fitsI64() bool { return a.within(i64Min, i64Max) }

func (a Ival) nonNeg() bool { return a.Lo.Sign() >= 0 }

func (a Ival) isPoint() (*big.Int, bool) {
	if a.Lo.Cmp(a.Hi) == 0 {
		return a.Lo, true
	}
	return nil, false
}

func union(a, b Ival) Ival {
	lo, hi := a.Lo, a.Hi
	if b.Lo.Cmp(lo) < 0 {
		lo = b.Lo
	}
	if b.Hi.Cmp(hi) > 0 {
		hi = b.Hi
	}
	return Ival{lo, hi}
}

func minMax(vs ...*big.Int) Ival {
	lo, hi := vs[0], vs[0]
	for _, v := range vs[1:] {
		if v.Cmp(lo) < 0 {
			lo = v
		}
		if v.Cmp(hi) > 0 {
			hi = v
		}
	}
	return Ival{new(big.Int).Set(lo), new(big.Int).Set(hi)}
}

func ivAdd(a, b Ival) Ival { return Ival{new(big.Int).Add(a.Lo, b.Lo), new(big.Int).Add(a.Hi, b.Hi)} }
func ivSub(a, b Ival) Ival { return Ival{new(big.Int).Sub(a.Lo, b.Hi), new(big.Int).Sub(a.Hi, b.Lo)} }
func ivMul(a, b Ival) Ival {
	m := func(x, y *big.Int) *big.Int { return new(big.Int).Mul(x, y) }
	return minMax(m(a.Lo, b.Lo), m(a.Lo, b.Hi), m(a.Hi, b.Lo), m(a.Hi, b.Hi))
}
func ivNeg(a Ival) Ival { return Ival{new(big.Int).Neg(a.Hi), new(big.Int).Neg(a.Lo)} }

// ivNot returns ~a = −a − 1.
func ivNot(a Ival) Ival {
	return Ival{new(big.Int).Sub(new(big.Int).Neg(a.Hi), bigOne), new(big.Int).Sub(new(big.Int).Neg(a.Lo), bigOne)}
}

// pow2m1 returns 2^bitlen(x) − 1 (the upper bound of | and ^ over all values in [0, x]).
func pow2m1(x *big.Int) *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(bigOne, uint(x.BitLen())), bigOne)
}

// ivBit returns the interval of & | ^. An operand that may be negative gives the whole i64 range (which fits in i64 — accepted).
func ivBit(op string, a, b Ival) Ival {
	switch op {
	case "&":
		switch {
		case a.nonNeg() && b.nonNeg():
			hi := a.Hi
			if b.Hi.Cmp(hi) < 0 {
				hi = b.Hi
			}
			return Ival{new(big.Int), new(big.Int).Set(hi)}
		case a.nonNeg():
			return Ival{new(big.Int), new(big.Int).Set(a.Hi)}
		case b.nonNeg():
			return Ival{new(big.Int), new(big.Int).Set(b.Hi)}
		}
	case "|", "^":
		if a.nonNeg() && b.nonNeg() {
			hi := a.Hi
			if b.Hi.Cmp(hi) > 0 {
				hi = b.Hi
			}
			return Ival{new(big.Int), pow2m1(hi)}
		}
	}
	return fullI64
}

// floorDiv is Ruby's Integer#/ (rounding toward −∞).
func floorDiv(x, d *big.Int) *big.Int {
	q, m := new(big.Int).DivMod(x, d, new(big.Int)) // Euclidean: 0 ≤ m < |d|
	if d.Sign() < 0 && m.Sign() != 0 {              // 7 / −2: Euclidean q = −3 (7 = 6 + 1), floor is −4
		q.Sub(q, bigOne)
	}
	return q
}

// isPow2Mag reports whether |d| is a power of 2.
func isPow2Mag(d *big.Int) bool {
	a := new(big.Int).Abs(d)
	return a.Sign() > 0 && new(big.Int).And(a, new(big.Int).Sub(a, bigOne)).Sign() == 0
}
