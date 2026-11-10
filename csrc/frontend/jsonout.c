/* jsonout — see jsonout.h. Follows encoding/json (encode.go appendString, indent.go) of the pinned Go toolchain. */
#include "jsonout.h"

#include <stdlib.h>
#include <string.h>

static const char hexd[] = "0123456789abcdef";

static void u_escape(sr_buf *b, unsigned v)
{
	sr_puts(b, "\\u");
	sr_putc(b, hexd[(v >> 12) & 15]);
	sr_putc(b, hexd[(v >> 8) & 15]);
	sr_putc(b, hexd[(v >> 4) & 15]);
	sr_putc(b, hexd[v & 15]);
}

/* utf8.DecodeRune: the rune and its width; an invalid sequence gives (0xFFFD, 1). */
static int decode_rune(const unsigned char *p, size_t n, uint32_t *r)
{
	unsigned char c = p[0];
	if (c < 0x80) {
		*r = c;
		return 1;
	}
	int need;
	uint32_t v, min;
	if (c >= 0xc2 && c <= 0xdf) {
		need = 1, v = c & 0x1f, min = 0x80;
	} else if (c >= 0xe0 && c <= 0xef) {
		need = 2, v = c & 0x0f, min = 0x800;
	} else if (c >= 0xf0 && c <= 0xf4) {
		need = 3, v = c & 0x07, min = 0x10000;
	} else {
		*r = 0xfffd;
		return 1;
	}
	if (n < (size_t)need + 1) {
		*r = 0xfffd;
		return 1;
	}
	for (int i = 1; i <= need; i++) {
		if ((p[i] & 0xc0) != 0x80) {
			*r = 0xfffd;
			return 1;
		}
		v = (v << 6) | (p[i] & 0x3f);
	}
	if (v < min || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) {
		*r = 0xfffd;
		return 1;
	}
	*r = v;
	return need + 1;
}

void fe_json_quote(sr_buf *b, sr_str s)
{
	const unsigned char *p = (const unsigned char *)s.p;
	size_t n = s.n;
	sr_putc(b, '"');
	for (size_t i = 0; i < n;) {
		unsigned char c = p[i];
		if (c < 0x80) {
			switch (c) {
			case '"': sr_puts(b, "\\\""); break;
			case '\\': sr_puts(b, "\\\\"); break;
			case '\n': sr_puts(b, "\\n"); break;
			case '\r': sr_puts(b, "\\r"); break;
			case '\t': sr_puts(b, "\\t"); break;
			case '\b': sr_puts(b, "\\b"); break;
			case '\f': sr_puts(b, "\\f"); break;
			case '<': case '>': case '&': u_escape(b, c); break;
			default:
				if (c < 0x20)
					u_escape(b, c);
				else
					sr_putc(b, (char)c);
			}
			i++;
			continue;
		}
		uint32_t r;
		int w = decode_rune(p + i, n - i, &r);
		if (r == 0xfffd && w == 1) {
			sr_put(b, "\xef\xbf\xbd", 3);
		} else if (r == 0x2028 || r == 0x2029) {
			u_escape(b, r);
		} else {
			sr_put(b, p + i, (size_t)w);
		}
		i += (size_t)w;
	}
	sr_putc(b, '"');
}

void fe_jw_init(fe_jw *w, sr_buf *b)
{
	memset(w, 0, sizeof *w);
	w->b = b;
}

static void indent(fe_jw *w)
{
	sr_putc(w->b, '\n');
	for (int i = 0; i < w->depth; i++)
		sr_puts(w->b, "  ");
}

/* the separator before a value: nothing at the top and after a key; in an array "," (after the first) and a new line */
static void pre(fe_jw *w)
{
	if (w->after_key) {
		w->after_key = 0;
		return;
	}
	if (w->depth == 0)
		return;
	if (w->count[w->depth - 1]++ > 0)
		sr_putc(w->b, ',');
	indent(w);
}

static void begin(fe_jw *w, int obj)
{
	pre(w);
	sr_putc(w->b, obj ? '{' : '[');
	if (w->depth >= FE_JW_DEPTH - 1)
		abort();
	w->is_obj[w->depth] = (char)obj;
	w->count[w->depth] = 0;
	w->depth++;
}

static void end(fe_jw *w)
{
	w->depth--;
	if (w->count[w->depth] > 0)
		indent(w);
	sr_putc(w->b, w->is_obj[w->depth] ? '}' : ']');
}

void fe_jw_obj_begin(fe_jw *w) { begin(w, 1); }
void fe_jw_obj_end(fe_jw *w) { end(w); }
void fe_jw_arr_begin(fe_jw *w) { begin(w, 0); }
void fe_jw_arr_end(fe_jw *w) { end(w); }

void fe_jw_key(fe_jw *w, sr_str k)
{
	if (w->count[w->depth - 1]++ > 0)
		sr_putc(w->b, ',');
	indent(w);
	fe_json_quote(w->b, k);
	sr_puts(w->b, ": ");
	w->after_key = 1;
}

void fe_jw_keyc(fe_jw *w, const char *k) { fe_jw_key(w, sr_cstr(k)); }

void fe_jw_str(fe_jw *w, sr_str s)
{
	pre(w);
	fe_json_quote(w->b, s);
}

void fe_jw_strc(fe_jw *w, const char *s) { fe_jw_str(w, sr_cstr(s)); }

void fe_jw_i64(fe_jw *w, int64_t v)
{
	pre(w);
	sr_printf(w->b, "%lld", (long long)v);
}

void fe_jw_u64(fe_jw *w, uint64_t v)
{
	pre(w);
	sr_printf(w->b, "%llu", (unsigned long long)v);
}

void fe_jw_bool(fe_jw *w, int v)
{
	pre(w);
	sr_puts(w->b, v ? "true" : "false");
}

void fe_jw_null(fe_jw *w)
{
	pre(w);
	sr_puts(w->b, "null");
}

static int key_cmp(const void *a, const void *b) { return sr_cmp(*(const sr_str *)a, *(const sr_str *)b); }

void fe_json_sort_keys(sr_str *keys, size_t n)
{
	if (n > 1)
		qsort(keys, n, sizeof *keys, key_cmp);
}
