/* interval.c — internal/frontend/interval.go (Ival and its arithmetic) and narrow.go (the narrowing of locals by a condition).
 * Go's bounds are *big.Int; here they are intv, and a result that leaves 128 bits sets fe_iv_overflow (a not-ported stop). */
#include "core.h"

#include <stdlib.h>
#include <string.h>

int fe_iv_overflow;

#define I128(neg_, mag_) {(neg_), (mag_)}
const intv fe_i64_min = I128(true, (intv_u128)1 << 63);
const intv fe_i64_max = I128(false, ((intv_u128)1 << 63) - 1);
const intv fe_u32_max = I128(false, ((intv_u128)1 << 32) - 1);
const intv fe_i32_min = I128(true, (intv_u128)1 << 31);
const intv fe_i32_max = I128(false, ((intv_u128)1 << 31) - 1);
const intv fe_u64_max = I128(false, ~(intv_u128)0 >> 64);
const fe_ival fe_full_i64 = {1, I128(true, (intv_u128)1 << 63), I128(false, ((intv_u128)1 << 63) - 1)};

int fe_streq(sr_str s, const char *c)
{
	size_t n = strlen(c);
	return s.n == n && (n == 0 || memcmp(s.p, c, n) == 0);
}

intv fe_iv_add1(intv a, intv b)
{
	intv r;
	if (intv_add(a, b, &r) != INTV_OK) {
		fe_iv_overflow = 1;
		return intv_from_i64(0);
	}
	return r;
}

intv fe_iv_sub1(intv a, intv b)
{
	intv r;
	if (intv_sub(a, b, &r) != INTV_OK) {
		fe_iv_overflow = 1;
		return intv_from_i64(0);
	}
	return r;
}

intv fe_iv_mul1(intv a, intv b)
{
	intv r;
	if (intv_mul(a, b, &r) != INTV_OK) {
		fe_iv_overflow = 1;
		return intv_from_i64(0);
	}
	return r;
}

fe_ival fe_point(intv v) { return (fe_ival){1, v, v}; }
fe_ival fe_iv(intv lo, intv hi) { return (fe_ival){1, lo, hi}; }

int fe_iv_within(fe_ival a, intv lo, intv hi) { return intv_cmp(a.lo, lo) >= 0 && intv_cmp(a.hi, hi) <= 0; }
int fe_iv_fits_i64(fe_ival a) { return fe_iv_within(a, fe_i64_min, fe_i64_max); }
int fe_iv_non_neg(fe_ival a) { return intv_sign(a.lo) >= 0; }

int fe_iv_is_point(fe_ival a, intv *v)
{
	if (intv_cmp(a.lo, a.hi) == 0) {
		if (v)
			*v = a.lo;
		return 1;
	}
	return 0;
}

fe_ival fe_union(fe_ival a, fe_ival b)
{
	intv lo = a.lo, hi = a.hi;
	if (intv_cmp(b.lo, lo) < 0)
		lo = b.lo;
	if (intv_cmp(b.hi, hi) > 0)
		hi = b.hi;
	return fe_iv(lo, hi);
}

static fe_ival min_max(const intv *vs, size_t n)
{
	intv lo = vs[0], hi = vs[0];
	for (size_t i = 1; i < n; i++) {
		if (intv_cmp(vs[i], lo) < 0)
			lo = vs[i];
		if (intv_cmp(vs[i], hi) > 0)
			hi = vs[i];
	}
	return fe_iv(lo, hi);
}

fe_ival fe_iv_add(fe_ival a, fe_ival b) { return fe_iv(fe_iv_add1(a.lo, b.lo), fe_iv_add1(a.hi, b.hi)); }
fe_ival fe_iv_sub(fe_ival a, fe_ival b) { return fe_iv(fe_iv_sub1(a.lo, b.hi), fe_iv_sub1(a.hi, b.lo)); }

fe_ival fe_iv_mul(fe_ival a, fe_ival b)
{
	intv v[4] = {fe_iv_mul1(a.lo, b.lo), fe_iv_mul1(a.lo, b.hi), fe_iv_mul1(a.hi, b.lo), fe_iv_mul1(a.hi, b.hi)};
	return min_max(v, 4);
}

fe_ival fe_iv_neg(fe_ival a) { return fe_iv(intv_neg(a.hi), intv_neg(a.lo)); }

fe_ival fe_iv_not(fe_ival a)
{
	intv one = intv_from_i64(1);
	return fe_iv(fe_iv_sub1(intv_neg(a.hi), one), fe_iv_sub1(intv_neg(a.lo), one));
}

/* pow2m1: 2^bitlen(x) - 1 */
static intv pow2m1(intv x)
{
	int bl = intv_bitlen(x);
	if (bl >= 128) {
		fe_iv_overflow = 1;
		return intv_from_i64(0);
	}
	intv r = {false, ((intv_u128)1 << bl) - 1};
	return r;
}

fe_ival fe_iv_bit(const char *op, fe_ival a, fe_ival b)
{
	intv zero = intv_from_i64(0);
	if (strcmp(op, "&") == 0) {
		if (fe_iv_non_neg(a) && fe_iv_non_neg(b))
			return fe_iv(zero, intv_cmp(b.hi, a.hi) < 0 ? b.hi : a.hi);
		if (fe_iv_non_neg(a))
			return fe_iv(zero, a.hi);
		if (fe_iv_non_neg(b))
			return fe_iv(zero, b.hi);
	} else if (strcmp(op, "|") == 0 || strcmp(op, "^") == 0) {
		if (fe_iv_non_neg(a) && fe_iv_non_neg(b))
			return fe_iv(zero, pow2m1(intv_cmp(b.hi, a.hi) > 0 ? b.hi : a.hi));
	}
	return fe_full_i64;
}

intv fe_floor_div(intv x, intv d) { return intv_floor_div(x, d); }
int fe_is_pow2_mag(intv d) { return intv_is_pow2_mag(d); }

sr_str fe_ival_string(fe_ival a)
{
	if (!a.set)
		return sr_cstr("[<nil>, <nil>]");
	char lo[48], hi[48];
	sr_buf b = {0};
	sr_printf(&b, "[%s, %s]", intv_string(a.lo, lo), intv_string(a.hi, hi));
	return sr_bufstr(&b);
}

intv fe_intv_of_big(const bigint *x, int *ok)
{
	char *s = bigint_string(x);
	intv v = intv_from_i64(0);
	*ok = intv_parse_dec(s, &v);
	free(s);
	return v;
}

bigint *fe_big_of_intv(intv v)
{
	char buf[48];
	intv_string(v, buf);
	bigint *x = sr_alloc(sizeof *x);
	bigint_parse_dec(x, buf, strlen(buf));
	return x;
}

/* ---- narrow.go ---- */

static fe_var_info *var_copy(const fe_var_info *v)
{
	fe_var_info *c = sr_alloc(sizeof *c);
	*c = *v;
	return c;
}

/* copyEnv (program.go) */
fe_name_table fe_copy_env(const fe_name_table *e)
{
	fe_name_table out = {0};
	for (size_t i = 0; i < e->n; i++)
		if (!e->e[i].removed)
			fe_name_set(&out, e->e[i].key, var_copy(e->e[i].val));
	return out;
}

static size_t live(const fe_name_table *t)
{
	size_t n = 0;
	for (size_t i = 0; i < t->n; i++)
		n += !t->e[i].removed;
	return n;
}

/* unionRefs (program.go): the sets are immutable, so a side is shared as Go shares it */
fe_name_table fe_union_refs(const fe_name_table *a, const fe_name_table *b)
{
	if (live(a) == 0)
		return *b;
	if (live(b) == 0)
		return *a;
	fe_name_table out = {0};
	static int one = 1;
	for (size_t i = 0; i < a->n; i++)
		if (!a->e[i].removed)
			fe_name_set(&out, a->e[i].key, &one);
	for (size_t i = 0; i < b->n; i++)
		if (!b->e[i].removed)
			fe_name_set(&out, b->e[i].key, &one);
	return out;
}

/* joinEnv (program.go) */
fe_name_table fe_join_env(const fe_name_table *a, const fe_name_table *b)
{
	fe_name_table out = {0};
	for (size_t i = 0; i < a->n; i++) {
		if (a->e[i].removed)
			continue;
		const fe_var_info *va = a->e[i].val, *vb = fe_name_get(b, a->e[i].key);
		if (!vb || va->bool_ != vb->bool_)
			continue;
		fe_var_info *v = var_copy(va);
		if (!v->bool_)
			v->iv = fe_union(va->iv, vb->iv);
		v->from = fe_union_refs(&va->from, &vb->from);
		if (va->mixed || vb->mixed || va->wide != vb->wide) {
			v->wide = 0;
			v->mixed = 1;
		}
		fe_name_set(&out, a->e[i].key, v);
	}
	return out;
}

/* joinArms (program.go) */
fe_name_table fe_join_arms(const fe_name_table *pre, const fe_name_table *a, const fe_name_table *b, int esc_a, int esc_b)
{
	if (esc_a && esc_b)
		return fe_copy_env(pre);
	if (esc_a)
		return *b;
	if (esc_b)
		return *a;
	return fe_join_env(a, b);
}

/* side (narrow.go) */
static int side(const fe_name_table *env, const fe_expr *x, fe_ival *iv, sr_str *name)
{
	*name = (sr_str){0};
	if (x->bool_ || x->wide)
		return 0;
	if (fe_streq(x->kind, "var")) {
		const fe_var_info *v = fe_name_get(env, x->var);
		if (v && !v->bool_) {
			*iv = v->iv;
			*name = x->var;
			return 1;
		}
		return 0;
	}
	if (!x->iv.set)
		return 0;
	*iv = x->iv;
	return 1;
}

static intv bmin(intv a, intv b) { return intv_cmp(a, b) < 0 ? a : b; }
static intv bmax(intv a, intv b) { return intv_cmp(a, b) > 0 ? a : b; }

/* narrowCmp (narrow.go) */
static int narrow_cmp(fe_name_table *env, const fe_expr *l, const char *op, const fe_expr *r)
{
	fe_ival L, R;
	sr_str ln, rn;
	if (!side(env, l, &L, &ln) || !side(env, r, &R, &rn) || (ln.n == 0 && rn.n == 0))
		return 1;
	intv one = intv_from_i64(1);
	fe_ival nl, nr;
	if (strcmp(op, "<") == 0) {
		nl = fe_iv(L.lo, bmin(L.hi, fe_iv_sub1(R.hi, one)));
		nr = fe_iv(bmax(R.lo, fe_iv_add1(L.lo, one)), R.hi);
	} else if (strcmp(op, "<=") == 0) {
		nl = fe_iv(L.lo, bmin(L.hi, R.hi));
		nr = fe_iv(bmax(R.lo, L.lo), R.hi);
	} else if (strcmp(op, ">") == 0) {
		nl = fe_iv(bmax(L.lo, fe_iv_add1(R.lo, one)), L.hi);
		nr = fe_iv(R.lo, bmin(R.hi, fe_iv_sub1(L.hi, one)));
	} else if (strcmp(op, ">=") == 0) {
		nl = fe_iv(bmax(L.lo, R.lo), L.hi);
		nr = fe_iv(R.lo, bmin(R.hi, L.hi));
	} else if (strcmp(op, "==") == 0) {
		nl = fe_iv(bmax(L.lo, R.lo), bmin(L.hi, R.hi));
		nr = nl;
	} else {
		return 1;
	}
	if (intv_cmp(nl.lo, nl.hi) > 0 || intv_cmp(nr.lo, nr.hi) > 0)
		return 0;
	if (ln.n) {
		fe_var_info *v = var_copy(fe_name_get(env, ln));
		v->iv = nl;
		fe_name_set(env, ln, v);
	}
	if (rn.n && !sr_eq(rn, ln)) {
		fe_var_info *v = var_copy(fe_name_get(env, rn));
		v->iv = nr;
		fe_name_set(env, rn, v);
	}
	return 1;
}

static const char *neg_op(sr_str op)
{
	static const char *const m[][2] = {{"<", ">="}, {"<=", ">"}, {">", "<="}, {">=", "<"}, {"==", "!="}, {"!=", "=="}};
	for (size_t i = 0; i < sizeof m / sizeof m[0]; i++)
		if (fe_streq(op, m[i][0]))
			return m[i][1];
	return ""; /* Go's map gives "" for any other operator */
}

/* narrowInto (narrow.go) */
static int narrow_into(fe_name_table *env, const fe_expr *e, int pos)
{
	if (fe_streq(e->kind, "not"))
		return narrow_into(env, e->args[0], !pos);
	if (fe_streq(e->kind, "and")) {
		if (!pos)
			return 1;
		return narrow_into(env, e->args[0], 1) && narrow_into(env, e->args[1], 1);
	}
	if (fe_streq(e->kind, "cmp")) {
		char opbuf[8] = {0};
		const char *op;
		if (pos) {
			size_t n = e->op.n < sizeof opbuf - 1 ? e->op.n : sizeof opbuf - 1;
			memcpy(opbuf, e->op.p, n);
			op = opbuf;
		} else {
			op = neg_op(e->op);
		}
		return narrow_cmp(env, e->args[0], op, e->args[1]);
	}
	return 1;
}

/* narrowEnv (narrow.go) */
fe_name_table fe_narrow_env(const fe_name_table *env, const fe_expr *cond, int positive)
{
	fe_name_table out = fe_copy_env(env);
	if (!cond || !narrow_into(&out, cond, positive))
		return fe_copy_env(env);
	return out;
}
