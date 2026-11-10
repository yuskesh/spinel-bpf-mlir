package frontend

import "math/big"

// Narrowing intervals by conditions: at the entry of an if / unless arm, the comparison in the condition intersects the
// intervals of locals.
// - `x op y` (op is < <= > >= ==, and x or y is a read of a local — the other side is a literal, a local or any other expression,
//   whose interval is used as the bound); != does not narrow
// - in the true arm of && both sides narrow; the false arm does not narrow. || does not narrow. not swaps true and false
// - an arm whose intersection is empty is not narrowed (it keeps the original intervals — errors inside an unreachable arm are
//   still rejected as before)
// - at a join the intervals are united by the existing joinEnv; a reassignment inside an arm gives a new interval (the narrowing
//   no longer applies)
// Lowering does not change — the kernel-side checks (the ref.index comparison, the min of a loop bound) stay in the ELF whatever
// the narrowing says.

// narrowEnv applies the narrowing of cond (positive: the true arm) to a copy of env. If an interval would become empty it returns
// an unnarrowed copy.
func narrowEnv(env map[string]*varInfo, cond *Expr, positive bool) map[string]*varInfo {
	out := copyEnv(env)
	if cond == nil || !narrowInto(out, cond, positive) {
		return copyEnv(env)
	}
	return out
}

// narrowInto narrows env (false if an interval becomes empty).
func narrowInto(env map[string]*varInfo, e *Expr, pos bool) bool {
	switch e.Kind {
	case "not":
		return narrowInto(env, e.Args[0], !pos)
	case "and":
		if !pos {
			return true // !(a && b) does not narrow
		}
		return narrowInto(env, e.Args[0], true) && narrowInto(env, e.Args[1], true)
	case "cmp":
		op := e.Op
		if !pos {
			op = map[string]string{"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}[op]
		}
		return narrowCmp(env, e.Args[0], op, e.Args[1])
	}
	return true
}

// side returns the interval of one side of a comparison and, if that side is a read of a local, its name.
func side(env map[string]*varInfo, x *Expr) (Ival, string, bool) {
	if x.Bool || x.Wide {
		return Ival{}, "", false
	}
	if x.Kind == "var" {
		if v, ok := env[x.Var]; ok && !v.Bool {
			return v.Iv, x.Var, true
		}
		return Ival{}, "", false
	}
	if x.Iv.Lo == nil {
		return Ival{}, "", false
	}
	return x.Iv, "", true
}

func bigMin(a, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return a
	}
	return b
}

func bigMax(a, b *big.Int) *big.Int {
	if a.Cmp(b) > 0 {
		return a
	}
	return b
}

// narrowCmp writes the intervals that hold when `l op r` is true into the local side(s).
func narrowCmp(env map[string]*varInfo, l *Expr, op string, r *Expr) bool {
	L, ln, ok1 := side(env, l)
	R, rn, ok2 := side(env, r)
	if !ok1 || !ok2 || (ln == "" && rn == "") {
		return true
	}
	one := big.NewInt(1)
	nl, nr := L, R
	switch op {
	case "<": // hi(l) ≤ hi(r) − 1, lo(r) ≥ lo(l) + 1
		nl = Ival{L.Lo, bigMin(L.Hi, new(big.Int).Sub(R.Hi, one))}
		nr = Ival{bigMax(R.Lo, new(big.Int).Add(L.Lo, one)), R.Hi}
	case "<=":
		nl = Ival{L.Lo, bigMin(L.Hi, R.Hi)}
		nr = Ival{bigMax(R.Lo, L.Lo), R.Hi}
	case ">":
		nl = Ival{bigMax(L.Lo, new(big.Int).Add(R.Lo, one)), L.Hi}
		nr = Ival{R.Lo, bigMin(R.Hi, new(big.Int).Sub(L.Hi, one))}
	case ">=":
		nl = Ival{bigMax(L.Lo, R.Lo), L.Hi}
		nr = Ival{R.Lo, bigMin(R.Hi, L.Hi)}
	case "==":
		nl = Ival{bigMax(L.Lo, R.Lo), bigMin(L.Hi, R.Hi)}
		nr = nl
	default:
		return true
	}
	if nl.Lo.Cmp(nl.Hi) > 0 || nr.Lo.Cmp(nr.Hi) > 0 {
		return false
	}
	if ln != "" {
		v := *env[ln]
		v.Iv = Ival{new(big.Int).Set(nl.Lo), new(big.Int).Set(nl.Hi)}
		env[ln] = &v
	}
	if rn != "" && rn != ln {
		v := *env[rn]
		v.Iv = Ival{new(big.Int).Set(nr.Lo), new(big.Int).Set(nr.Hi)}
		env[rn] = &v
	}
	return true
}
