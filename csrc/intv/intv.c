/* intv: sign and unsigned 128-bit magnitude, each operation checked, with Go math/big's results. No signed shift, no signed overflow and no
 * signed negation of a minimum is ever evaluated: every operation works on the unsigned magnitude. */
#include "intv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const intv_u128 U128_MAX = ~(intv_u128)0;

static intv mk(bool neg, intv_u128 mag) {
	intv r = {neg && mag != 0, mag};
	return r;
}

static void assert_fail(const char *op, const char *what) {
	fprintf(stderr, "intv: internal assertion in %s: %s\n", op, what);
	exit(INTV_ASSERT_EXIT);
}

intv intv_from_i64(int64_t v) {
	/* the magnitude of a negative value through unsigned arithmetic: -(uint64)v is defined for INT64_MIN too */
	return v < 0 ? mk(true, (intv_u128)(0 - (uint64_t)v)) : mk(false, (intv_u128)(uint64_t)v);
}

intv intv_from_u64(uint64_t v) { return mk(false, v); }

intv_status intv_add(intv a, intv b, intv *out) {
	if (a.neg == b.neg) {
		intv_u128 s;
		if (__builtin_add_overflow(a.mag, b.mag, &s))
			return INTV_OVERFLOW;
		*out = mk(a.neg, s);
		return INTV_OK;
	}
	/* different signs: the larger magnitude keeps its sign */
	if (a.mag >= b.mag)
		*out = mk(a.neg, a.mag - b.mag);
	else
		*out = mk(b.neg, b.mag - a.mag);
	return INTV_OK;
}

/* Sub(a, b) = Add(a, Neg(b)), and then Add's sign rule applies */
intv_status intv_sub(intv a, intv b, intv *out) { return intv_add(a, intv_neg(b), out); }

intv_status intv_mul(intv a, intv b, intv *out) {
	intv_u128 p;
#ifdef INTV_MUTANT_WRAP_MUL
	/* overflow-control mutant: the magnitude product mod 2^128 (defined: unsigned), sign and zero handled as in the product code */
	p = a.mag * b.mag;
#else
	if (__builtin_mul_overflow(a.mag, b.mag, &p))
		return INTV_OVERFLOW;
#endif
	*out = mk(a.neg != b.neg, p);
	return INTV_OK;
}

intv intv_neg(intv a) { return mk(!a.neg, a.mag); }

intv intv_abs(intv a) { return mk(false, a.mag); }

intv intv_quo(intv x, intv d) {
	if (d.mag == 0)
		assert_fail("Quo", "division by zero");
	return mk(x.neg != d.neg, x.mag / d.mag);
}

void intv_divmod(intv x, intv d, intv *q, intv *m) {
	if (d.mag == 0)
		assert_fail("DivMod", "division by zero");
	intv_u128 tq = x.mag / d.mag, tr = x.mag % d.mag;
	if (!x.neg || tr == 0) {
		/* x = q*d + m with m = tr >= 0 (x >= 0), or exact division (m = 0) */
		*q = mk(x.neg != d.neg, tq);
		*m = mk(false, tr);
		return;
	}
	/* x < 0 and tr != 0: m = |d| - tr, |q| = tq + 1. tr != 0 means |d| >= 2, so tq + 1 <= |x| and cannot overflow. */
	*q = mk(!d.neg, tq + 1);
	*m = mk(false, d.mag - tr);
}

intv intv_floor_div(intv x, intv d) {
	/* interval.go floorDiv: q, m := DivMod(x, d); if d < 0 && m != 0 { q = q - 1 } */
	intv q, m;
	intv_divmod(x, d, &q, &m);
	if (d.neg && m.mag != 0) {
		intv r;
		if (intv_sub(q, intv_from_i64(1), &r) != INTV_OK)
			assert_fail("floorDiv", "q - 1 left the domain"); /* unreachable: |q| <= |x| / 2 + 1 here */
		q = r;
	}
	return q;
}

bool intv_is_pow2_mag(intv d) { return d.mag != 0 && (d.mag & (d.mag - 1)) == 0; }

int intv_bitlen(intv x) {
	uint64_t hi = (uint64_t)(x.mag >> 64), lo = (uint64_t)x.mag;
	if (hi)
		return 128 - __builtin_clzll(hi);
	if (lo)
		return 64 - __builtin_clzll(lo);
	return 0;
}

intv_status intv_lsh(intv x, uint64_t n, intv *out) {
	/* the count is checked before any C shift, counts >= 128 included; zero stays zero for any count */
	if (x.mag == 0) {
		*out = mk(false, 0);
		return INTV_OK;
	}
	if (n >= 128 || (uint64_t)intv_bitlen(x) + n > 128)
		return INTV_OVERFLOW;
	*out = mk(x.neg, x.mag << n);
	return INTV_OK;
}

intv intv_rsh(intv x, uint64_t n) {
	if (!x.neg)
		return mk(false, n >= 128 ? 0 : x.mag >> n);
	/* floor for x < 0: -(((|x| - 1) >> n) + 1); for n >= 128 that is -1. |x| >= 1, so |x| - 1 is defined, and the result's
	 * magnitude is at most |x|. */
	if (n >= 128)
		return mk(true, 1);
	return mk(true, ((x.mag - 1) >> n) + 1);
}

intv_status intv_and(intv a, intv b, intv *out) {
	/* two's complement of infinite width: for x < 0 the bits are ~(|x| - 1) */
	if (!a.neg && !b.neg) {
		*out = mk(false, a.mag & b.mag);
		return INTV_OK;
	}
	if (!a.neg) {
		*out = mk(false, a.mag & ~(b.mag - 1));
		return INTV_OK;
	}
	if (!b.neg) {
		*out = mk(false, b.mag & ~(a.mag - 1));
		return INTV_OK;
	}
	/* both negative: ~(a-1) & ~(b-1) = ~((a-1) | (b-1)), which is -(((a-1) | (b-1)) + 1) */
	intv_u128 o = (a.mag - 1) | (b.mag - 1);
	if (o == U128_MAX)
		return INTV_OVERFLOW; /* the result is -2^128 */
	*out = mk(true, o + 1);
	return INTV_OK;
}

bool intv_is_int64(intv x) {
	if (x.neg)
		return x.mag <= (intv_u128)1 << 63;
	return x.mag <= (intv_u128)INT64_MAX;
}

bool intv_is_uint64(intv x) { return !x.neg && x.mag <= (intv_u128)UINT64_MAX; }

int64_t intv_int64(intv x) {
	/* Go: v := int64(low64(x.abs)); if x.neg { v = -v } — done in unsigned arithmetic, then converted */
	uint64_t lo = (uint64_t)x.mag;
	if (x.neg)
		lo = 0 - lo;
	int64_t v;
	memcpy(&v, &lo, sizeof v); /* two's-complement reinterpretation without an implementation-defined conversion */
	return v;
}

uint64_t intv_uint64(intv x) { return (uint64_t)x.mag; }

int intv_sign(intv x) { return x.mag == 0 ? 0 : (x.neg ? -1 : 1); }

int intv_cmp(intv a, intv b) {
	if (a.neg != b.neg)
		return a.neg ? -1 : 1;
	int c = a.mag < b.mag ? -1 : (a.mag > b.mag ? 1 : 0);
	return a.neg ? -c : c;
}

char *intv_string(intv x, char *buf) {
	char tmp[48];
	int i = (int)sizeof tmp;
	tmp[--i] = 0;
	intv_u128 m = x.mag;
	do {
		tmp[--i] = (char)('0' + (int)(m % 10));
		m /= 10;
	} while (m);
	if (x.neg)
		tmp[--i] = '-';
	strcpy(buf, tmp + i);
	return buf;
}

bool intv_parse_dec(const char *s, intv *out) {
	bool neg = false;
	if (*s == '-') {
		neg = true;
		s++;
	}
	if (!*s)
		return false;
	intv_u128 m = 0;
	for (; *s; s++) {
		if (*s < '0' || *s > '9')
			return false;
		if (__builtin_mul_overflow(m, (intv_u128)10, &m) || __builtin_add_overflow(m, (intv_u128)(*s - '0'), &m))
			return false;
	}
	*out = mk(neg, m);
	return true;
}
