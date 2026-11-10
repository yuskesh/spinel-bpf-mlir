/* bigint: the unbounded integer for integer literals, checked against Go's parseRubyInt, SetString and String. It parses in bases
 * 2, 8, 10 and 16, negates, compares and prints decimal, as Go's math/big does for these operations. Nothing else is needed on the literal path. */
#include "intv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *xrealloc(void *p, size_t n) {
	void *q = realloc(p, n ? n : 1);
	if (!q) {
		fprintf(stderr, "intv: out of memory\n");
		exit(INTV_ASSERT_EXIT);
	}
	return q;
}

void bigint_free(bigint *x) {
	free(x->l);
	x->l = NULL;
	x->n = 0;
	x->neg = false;
}

static void norm(bigint *x) {
	while (x->n && x->l[x->n - 1] == 0)
		x->n--;
	if (x->n == 0)
		x->neg = false;
}

/* x = x * m + a, for small m and a */
static void mul_add(bigint *x, uint32_t m, uint32_t a) {
	uint64_t carry = a;
	for (size_t i = 0; i < x->n; i++) {
		uint64_t t = (uint64_t)x->l[i] * m + carry;
		x->l[i] = (uint32_t)t;
		carry = t >> 32;
	}
	if (carry) {
		x->l = xrealloc(x->l, (x->n + 1) * sizeof *x->l);
		x->l[x->n++] = (uint32_t)carry;
	}
}

static int digit(char c, int base) {
	int d;
	if (c >= '0' && c <= '9')
		d = c - '0';
	else if (c >= 'a' && c <= 'z')
		d = c - 'a' + 10;
	else if (c >= 'A' && c <= 'Z')
		d = c - 'A' + 10;
	else
		return -1;
	return d < base ? d : -1;
}

bool bigint_set_string(bigint *x, const char *s, size_t len, int base) {
	bigint_free(x);
	bool neg = false;
	size_t i = 0;
	if (i < len && (s[i] == '+' || s[i] == '-')) {
		neg = s[i] == '-';
		i++;
	}
	if (i == len)
		return false;
	for (; i < len; i++) {
		int d = digit(s[i], base);
		if (d < 0) {
			bigint_free(x);
			return false;
		}
		mul_add(x, (uint32_t)base, (uint32_t)d);
	}
	x->neg = neg;
	norm(x);
	return true;
}

bool bigint_parse_ruby_int(bigint *x, const char *s0, size_t len0) {
	/* analyze.go parseRubyInt: s = strings.ReplaceAll(s, "_", "") first */
	char *s = xrealloc(NULL, len0 + 1);
	size_t len = 0;
	for (size_t i = 0; i < len0; i++)
		if (s0[i] != '_')
			s[len++] = s0[i];
	s[len] = 0;
	const char *p = s;
	bool neg = false;
	if (len && p[0] == '-') {
		neg = true;
		p++, len--;
	} else if (len && p[0] == '+') {
		p++, len--;
	}
	int base = 10;
	if (len >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		base = 16, p += 2, len -= 2;
	else if (len >= 2 && p[0] == '0' && (p[1] == 'b' || p[1] == 'B'))
		base = 2, p += 2, len -= 2;
	else if (len >= 2 && p[0] == '0' && (p[1] == 'o' || p[1] == 'O'))
		base = 8, p += 2, len -= 2;
	else if (len >= 2 && p[0] == '0' && (p[1] == 'd' || p[1] == 'D'))
		base = 10, p += 2, len -= 2;
	else if (len > 1 && p[0] == '0')
		base = 8, p += 1, len -= 1;
	bool ok = len != 0 && bigint_set_string(x, p, len, base); /* SetString takes a sign of its own too: "--5" is 5, "0x-1" is -1 */
	free(s);
	if (!ok)
		return false;
	if (neg)
		bigint_neg(x);
	return true;
}

bool bigint_parse_dec(bigint *x, const char *s, size_t len) { return bigint_set_string(x, s, len, 10); }

void bigint_neg(bigint *x) {
	if (x->n)
		x->neg = !x->neg;
}

static int cmp_mag(const bigint *a, const bigint *b) {
	if (a->n != b->n)
		return a->n < b->n ? -1 : 1;
	for (size_t i = a->n; i-- > 0;)
		if (a->l[i] != b->l[i])
			return a->l[i] < b->l[i] ? -1 : 1;
	return 0;
}

int bigint_cmp(const bigint *a, const bigint *b) {
	if (a->neg != b->neg)
		return a->neg ? -1 : 1;
	int c = cmp_mag(a, b);
	return a->neg ? -c : c;
}

char *bigint_string(const bigint *x) {
	/* repeated division of a copy by 10^9 */
	size_t n = x->n;
	uint32_t *t = xrealloc(NULL, (n ? n : 1) * sizeof *t);
	if (n) /* zero has no limbs, and l may be NULL (memcpy from NULL is undefined even for 0 bytes) */
		memcpy(t, x->l, n * sizeof *t);
	size_t cap = n * 10 + 3, len = 0;
	char *out = xrealloc(NULL, cap);
	do {
		uint64_t r = 0;
		for (size_t i = n; i-- > 0;) {
			uint64_t cur = (r << 32) | t[i];
			t[i] = (uint32_t)(cur / 1000000000u);
			r = cur % 1000000000u;
		}
		while (n && t[n - 1] == 0)
			n--;
		for (int k = 0; k < 9; k++) {
			out[len++] = (char)('0' + (int)(r % 10));
			r /= 10;
			if (n == 0 && r == 0)
				break;
		}
	} while (n);
	if (x->neg)
		out[len++] = '-';
	out[len] = 0;
	for (size_t i = 0, j = len - 1; i < j; i++, j--) {
		char c = out[i];
		out[i] = out[j];
		out[j] = c;
	}
	free(t);
	return out;
}
