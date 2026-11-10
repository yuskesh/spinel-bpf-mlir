package frontend

import (
	"fmt"
	"math/big"
)

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
	literalLo = new(big.Int).Add(i64Min, bigOne)
)

func point(v *big.Int) Ival { return Ival{new(big.Int).Set(v), new(big.Int).Set(v)} }

func iv(lo, hi *big.Int) Ival { return Ival{lo, hi} }

func (a Ival) String() string { return fmt.Sprintf("[%s, %s]", a.Lo, a.Hi) }

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

func ivNot(a Ival) Ival {
	return Ival{new(big.Int).Sub(new(big.Int).Neg(a.Hi), bigOne), new(big.Int).Sub(new(big.Int).Neg(a.Lo), bigOne)}
}

func pow2m1(x *big.Int) *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(bigOne, uint(x.BitLen())), bigOne)
}

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

func floorDiv(x, d *big.Int) *big.Int {
	q, m := new(big.Int).DivMod(x, d, new(big.Int))
	if d.Sign() < 0 && m.Sign() != 0 {
		q.Sub(q, bigOne)
	}
	return q
}

func isPow2Mag(d *big.Int) bool {
	a := new(big.Int).Abs(d)
	return a.Sign() > 0 && new(big.Int).And(a, new(big.Int).Sub(a, bigOne)).Sign() == 0
}
