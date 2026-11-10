/* spinelread: the arena, byte strings, results, the int map, and the parts of Go's strconv, unicode/utf8 and strings that the
 * reader needs. */
#include "sr.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* ---- arena ---- */

#define SR_CHUNK (1u << 20)
static char *arena_p;
static size_t arena_left;

void *sr_alloc(size_t n)
{
	n = (n + 15) & ~(size_t)15;
	if (n == 0)
		n = 16;
	if (n > arena_left) {
		size_t c = n > SR_CHUNK ? n : SR_CHUNK;
		arena_p = calloc(1, c);
		if (!arena_p) {
			fputs("spinelread: out of memory\n", stderr);
			exit(3);
		}
		arena_left = c;
	}
	void *p = arena_p;
	arena_p += n;
	arena_left -= n;
	return p;
}

void *sr_grow(void *p, size_t old_n, size_t new_n)
{
	void *q = sr_alloc(new_n);
	if (old_n)
		memcpy(q, p, old_n);
	return q;
}

/* ---- byte strings ---- */

sr_str sr_dup(const char *p, size_t n)
{
	char *q = sr_alloc(n + 1);
	if (n)
		memcpy(q, p, n);
	return (sr_str){q, n};
}

sr_str sr_cstr(const char *s) { return (sr_str){s, strlen(s)}; }

int sr_eq(sr_str a, sr_str b) { return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0); }

int sr_eqc(sr_str a, const char *s) { return sr_eq(a, sr_cstr(s)); }

int sr_cmp(sr_str a, sr_str b)
{
	size_t m = a.n < b.n ? a.n : b.n;
	int c = m ? memcmp(a.p, b.p, m) : 0;
	if (c)
		return c;
	return a.n < b.n ? -1 : a.n > b.n;
}

void sr_put(sr_buf *b, const void *p, size_t n)
{
	if (b->n + n + 1 > b->cap) {
		size_t c = b->cap ? b->cap * 2 : 256;
		while (c < b->n + n + 1)
			c *= 2;
		b->p = sr_grow(b->p, b->n, c);
		b->cap = c;
	}
	if (n)
		memcpy(b->p + b->n, p, n);
	b->n += n;
	b->p[b->n] = 0;
}

void sr_puts(sr_buf *b, const char *s) { sr_put(b, s, strlen(s)); }

void sr_putc(sr_buf *b, char c) { sr_put(b, &c, 1); }

void sr_putstr(sr_buf *b, sr_str s) { sr_put(b, s.p, s.n); }

static void sr_vprintf(sr_buf *b, const char *fmt, va_list ap)
{
	va_list ap2;
	va_copy(ap2, ap);
	int n = vsnprintf(NULL, 0, fmt, ap2);
	va_end(ap2);
	if (n < 0)
		return;
	char *t = sr_alloc((size_t)n + 1);
	vsnprintf(t, (size_t)n + 1, fmt, ap);
	sr_put(b, t, (size_t)n);
}

void sr_printf(sr_buf *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	sr_vprintf(b, fmt, ap);
	va_end(ap);
}

sr_str sr_bufstr(const sr_buf *b) { return (sr_str){b->p ? b->p : "", b->n}; }

/* ---- results ---- */

const sr_result sr_ok = {SR_OK, {"", 0}};

sr_result sr_err(const char *fmt, ...)
{
	sr_buf b = {0};
	va_list ap;
	va_start(ap, fmt);
	sr_vprintf(&b, fmt, ap);
	va_end(ap);
	return (sr_result){SR_ERR, sr_bufstr(&b)};
}

sr_result sr_err_str(sr_str s) { return (sr_result){SR_ERR, s}; }

sr_result sr_not_ported(const char *fmt, ...)
{
	sr_buf b = {0};
	sr_puts(&b, "not ported: ");
	va_list ap;
	va_start(ap, fmt);
	sr_vprintf(&b, fmt, ap);
	va_end(ap);
	return (sr_result){SR_NOT_PORTED, sr_bufstr(&b)};
}

/* ---- strconv.ParseInt(s, 10, 64) ---- */

int sr_parse_int64(sr_str s, int64_t *out)
{
	size_t i = 0;
	int neg = 0;
	if (s.n == 0)
		return 0;
	if (s.p[0] == '+' || s.p[0] == '-') {
		neg = s.p[0] == '-';
		i = 1;
	}
	if (i == s.n)
		return 0;
	uint64_t u = 0;
	for (; i < s.n; i++) {
		unsigned char c = (unsigned char)s.p[i];
		if (c < '0' || c > '9')
			return 0;
		if (u > (UINT64_MAX - (c - '0')) / 10) /* ParseUint's range error */
			return 0;
		u = u * 10 + (c - '0');
	}
	const uint64_t lim = (uint64_t)1 << 63;
	if (!neg && u >= lim)
		return 0;
	if (neg && u > lim)
		return 0;
	*out = neg ? (int64_t)(0 - u) : (int64_t)u;
	return 1;
}

/* ---- unicode/utf8 ---- */

int32_t sr_decode_rune(const char *s, size_t n, size_t *width)
{
	const unsigned char *p = (const unsigned char *)s;
	if (n < 1) {
		*width = 0;
		return 0xFFFD;
	}
	unsigned c = p[0];
	if (c < 0x80) {
		*width = 1;
		return (int32_t)c;
	}
	size_t sz;
	unsigned lo = 0x80, hi = 0xBF;
	if (c >= 0xC2 && c <= 0xDF)
		sz = 2;
	else if (c >= 0xE0 && c <= 0xEF) {
		sz = 3;
		if (c == 0xE0)
			lo = 0xA0;
		else if (c == 0xED)
			hi = 0x9F;
	} else if (c >= 0xF0 && c <= 0xF4) {
		sz = 4;
		if (c == 0xF0)
			lo = 0x90;
		else if (c == 0xF4)
			hi = 0x8F;
	} else {
		*width = 1;
		return 0xFFFD;
	}
	*width = 1;
	if (n < sz)
		return 0xFFFD;
	if (p[1] < lo || p[1] > hi)
		return 0xFFFD;
	if (sz == 2) {
		*width = 2;
		return (int32_t)((c & 0x1F) << 6 | (p[1] & 0x3F));
	}
	if (p[2] < 0x80 || p[2] > 0xBF)
		return 0xFFFD;
	if (sz == 3) {
		*width = 3;
		return (int32_t)((c & 0x0F) << 12 | (p[1] & 0x3F) << 6 | (p[2] & 0x3F));
	}
	if (p[3] < 0x80 || p[3] > 0xBF)
		return 0xFFFD;
	*width = 4;
	return (int32_t)((c & 0x07) << 18 | (p[1] & 0x3F) << 12 | (p[2] & 0x3F) << 6 | (p[3] & 0x3F));
}

void sr_append_rune(sr_buf *b, int32_t r)
{
	unsigned char t[4];
	if (r < 0 || r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF))
		r = 0xFFFD;
	if (r < 0x80) {
		t[0] = (unsigned char)r;
		sr_put(b, t, 1);
	} else if (r < 0x800) {
		t[0] = (unsigned char)(0xC0 | r >> 6);
		t[1] = (unsigned char)(0x80 | (r & 0x3F));
		sr_put(b, t, 2);
	} else if (r < 0x10000) {
		t[0] = (unsigned char)(0xE0 | r >> 12);
		t[1] = (unsigned char)(0x80 | (r >> 6 & 0x3F));
		t[2] = (unsigned char)(0x80 | (r & 0x3F));
		sr_put(b, t, 3);
	} else {
		t[0] = (unsigned char)(0xF0 | r >> 18);
		t[1] = (unsigned char)(0x80 | (r >> 12 & 0x3F));
		t[2] = (unsigned char)(0x80 | (r >> 6 & 0x3F));
		t[3] = (unsigned char)(0x80 | (r & 0x3F));
		sr_put(b, t, 4);
	}
}

/* ---- strconv.QuoteToASCII (appendQuotedWith with ASCIIonly) ---- */

static const char lowerhex[] = "0123456789abcdef";

static void put_hex(sr_buf *b, const char *prefix, uint32_t v, int digits)
{
	sr_puts(b, prefix);
	for (int s = (digits - 1) * 4; s >= 0; s -= 4)
		sr_putc(b, lowerhex[v >> s & 0xF]);
}

void sr_quote_ascii(sr_buf *b, sr_str s)
{
	sr_putc(b, '"');
	for (size_t i = 0; i < s.n;) {
		size_t w;
		int32_t r = sr_decode_rune(s.p + i, s.n - i, &w);
		if (w == 1 && r == 0xFFFD) {
			put_hex(b, "\\x", (unsigned char)s.p[i], 2);
			i++;
			continue;
		}
		i += w;
		if (r == '"' || r == '\\') {
			sr_putc(b, '\\');
			sr_putc(b, (char)r);
			continue;
		}
		if (r >= 0x20 && r < 0x7F) {
			sr_putc(b, (char)r);
			continue;
		}
		switch (r) {
		case '\a': sr_puts(b, "\\a"); break;
		case '\b': sr_puts(b, "\\b"); break;
		case '\f': sr_puts(b, "\\f"); break;
		case '\n': sr_puts(b, "\\n"); break;
		case '\r': sr_puts(b, "\\r"); break;
		case '\t': sr_puts(b, "\\t"); break;
		case '\v': sr_puts(b, "\\v"); break;
		default:
			if (r < ' ' || r == 0x7F)
				put_hex(b, "\\x", (uint32_t)r, 2);
			else if (r < 0x10000)
				put_hex(b, "\\u", (uint32_t)r, 4);
			else
				put_hex(b, "\\U", (uint32_t)r, 8);
		}
	}
	sr_putc(b, '"');
}

int sr_quote_go_ascii(sr_buf *b, sr_str s)
{
	for (size_t i = 0; i < s.n; i++)
		if ((unsigned char)s.p[i] >= 0x80)
			return 0;
	/* for ASCII text, strconv.Quote and QuoteToASCII write the same bytes */
	sr_quote_ascii(b, s);
	return 1;
}

/* ---- strings.TrimSpace ---- */

static int is_space_rune(int32_t r)
{
	switch (r) {
	case '\t': case '\n': case '\v': case '\f': case '\r': case ' ':
	case 0x85: case 0xA0: case 0x1680: case 0x2028: case 0x2029: case 0x202F: case 0x205F: case 0x3000:
		return 1;
	}
	return r >= 0x2000 && r <= 0x200A;
}

/* utf8.DecodeLastRune */
static int32_t decode_last_rune(const char *s, size_t n, size_t *width)
{
	if (n == 0) {
		*width = 0;
		return 0xFFFD;
	}
	size_t end = n, start = end - 1;
	if ((unsigned char)s[start] < 0x80) {
		*width = 1;
		return (unsigned char)s[start];
	}
	size_t lim = end >= 4 ? end - 4 : 0;
	while (start > lim && ((unsigned char)s[start] & 0xC0) == 0x80)
		start--;
	/* Go starts the search one byte earlier and may stop one byte further back; every case where that differs ends in
	 * RuneError width 1 on both, since no valid rune ends at a lead byte or spans 5 bytes */
	size_t w;
	int32_t r = sr_decode_rune(s + start, end - start, &w);
	if (start + w != end) {
		*width = 1;
		return 0xFFFD;
	}
	*width = w;
	return r;
}

sr_str sr_trim_space(sr_str s)
{
	size_t a = 0, z = s.n;
	while (a < z) {
		size_t w;
		int32_t r = sr_decode_rune(s.p + a, z - a, &w);
		if (!is_space_rune(r))
			break;
		a += w;
	}
	while (z > a) {
		size_t w;
		int32_t r = decode_last_rune(s.p + a, z - a, &w);
		if (!is_space_rune(r))
			break;
		z -= w;
	}
	return (sr_str){s.p + a, z - a};
}

/* ---- int map ---- */

static size_t imap_hash(int64_t k)
{
	uint64_t x = (uint64_t)k + 0x9E3779B97F4A7C15ull;
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
	x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
	return (size_t)(x ^ (x >> 31));
}

static void imap_rehash(sr_imap *m, size_t cap)
{
	sr_imap n = {sr_alloc(cap * sizeof(int64_t)), sr_alloc(cap * sizeof(void *)), sr_alloc(cap), 0, cap};
	for (size_t i = 0; i < m->cap; i++) {
		if (!m->used[i])
			continue;
		size_t j = imap_hash(m->keys[i]) & (cap - 1);
		while (n.used[j])
			j = (j + 1) & (cap - 1);
		n.used[j] = 1;
		n.keys[j] = m->keys[i];
		n.vals[j] = m->vals[i];
		n.n++;
	}
	*m = n;
}

void **sr_imap_slot(sr_imap *m, int64_t k, int *created)
{
	if ((m->n + 1) * 2 > m->cap)
		imap_rehash(m, m->cap ? m->cap * 2 : 64);
	size_t j = imap_hash(k) & (m->cap - 1);
	while (m->used[j]) {
		if (m->keys[j] == k) {
			if (created)
				*created = 0;
			return &m->vals[j];
		}
		j = (j + 1) & (m->cap - 1);
	}
	m->used[j] = 1;
	m->keys[j] = k;
	m->vals[j] = NULL;
	m->n++;
	if (created)
		*created = 1;
	return &m->vals[j];
}

void *sr_imap_get(const sr_imap *m, int64_t k)
{
	if (!m->cap)
		return NULL;
	size_t j = imap_hash(k) & (m->cap - 1);
	while (m->used[j]) {
		if (m->keys[j] == k)
			return m->vals[j];
		j = (j + 1) & (m->cap - 1);
	}
	return NULL;
}

static int cmp_i64(const void *a, const void *b)
{
	int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
	return x < y ? -1 : x > y;
}

int64_t *sr_imap_sorted_keys(const sr_imap *m)
{
	int64_t *ks = sr_alloc((m->n ? m->n : 1) * sizeof *ks);
	size_t k = 0;
	for (size_t i = 0; i < m->cap; i++)
		if (m->used[i])
			ks[k++] = m->keys[i];
	qsort(ks, k, sizeof *ks, cmp_i64);
	return ks;
}
