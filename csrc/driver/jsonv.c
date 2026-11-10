/* csrc/driver/jsonv.c - see jsonv.h. */
#include "jsonv.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "util.h"

struct parser {
	const char *p, *end;
	int bad;
};

static void ws(struct parser *ps)
{
	while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
		ps->p++;
}

static int hexv(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void put_utf8(struct sb *b, unsigned cp)
{
	char t[4];
	if (cp < 0x80) {
		t[0] = (char)cp;
		sb_put(b, t, 1);
	} else if (cp < 0x800) {
		t[0] = (char)(0xc0 | (cp >> 6));
		t[1] = (char)(0x80 | (cp & 0x3f));
		sb_put(b, t, 2);
	} else if (cp < 0x10000) {
		t[0] = (char)(0xe0 | (cp >> 12));
		t[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
		t[2] = (char)(0x80 | (cp & 0x3f));
		sb_put(b, t, 3);
	} else {
		t[0] = (char)(0xf0 | (cp >> 18));
		t[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
		t[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
		t[3] = (char)(0x80 | (cp & 0x3f));
		sb_put(b, t, 4);
	}
}

static int u4(struct parser *ps, unsigned *out)
{
	if (ps->end - ps->p < 4)
		return -1;
	unsigned v = 0;
	for (int i = 0; i < 4; i++) {
		int h = hexv(ps->p[i]);
		if (h < 0)
			return -1;
		v = v * 16 + (unsigned)h;
	}
	ps->p += 4;
	*out = v;
	return 0;
}

static char *str(struct parser *ps, size_t *len)
{
	struct sb b = {0};
	ps->p++; /* the opening quote */
	while (ps->p < ps->end && *ps->p != '"') {
		if (*ps->p != '\\') {
			sb_putc(&b, *ps->p++);
			continue;
		}
		ps->p++;
		if (ps->p >= ps->end)
			break;
		char c = *ps->p++;
		switch (c) {
		case '"': sb_putc(&b, '"'); break;
		case '\\': sb_putc(&b, '\\'); break;
		case '/': sb_putc(&b, '/'); break;
		case 'b': sb_putc(&b, '\b'); break;
		case 'f': sb_putc(&b, '\f'); break;
		case 'n': sb_putc(&b, '\n'); break;
		case 'r': sb_putc(&b, '\r'); break;
		case 't': sb_putc(&b, '\t'); break;
		case 'u': {
			unsigned cp;
			if (u4(ps, &cp)) {
				ps->bad = 1;
				return sb_take(&b);
			}
			if (cp >= 0xd800 && cp < 0xdc00 && ps->end - ps->p >= 6 && ps->p[0] == '\\' && ps->p[1] == 'u') {
				const char *save = ps->p;
				unsigned lo;
				ps->p += 2;
				if (u4(ps, &lo) == 0 && lo >= 0xdc00 && lo < 0xe000) {
					cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
				} else {
					ps->p = save;
					cp = 0xfffd;
				}
			} else if (cp >= 0xd800 && cp < 0xe000) {
				cp = 0xfffd; /* a lone surrogate decodes to U+FFFD, as Go */
			}
			put_utf8(&b, cp);
			break;
		}
		default:
			ps->bad = 1;
			return sb_take(&b);
		}
	}
	if (ps->p >= ps->end)
		ps->bad = 1;
	else
		ps->p++;
	*len = b.n;
	return sb_take(&b);
}

static void value(struct parser *ps, struct jv *v);

static void array_or_object(struct parser *ps, struct jv *v, int obj)
{
	ps->p++;
	size_t cap = 0;
	ws(ps);
	if (ps->p < ps->end && *ps->p == (obj ? '}' : ']')) {
		ps->p++;
		return;
	}
	for (;;) {
		ws(ps);
		if (v->n == cap) {
			cap = cap ? cap * 2 : 4;
			v->items = xrealloc(v->items, cap * sizeof *v->items);
			if (obj)
				v->keys = xrealloc(v->keys, cap * sizeof *v->keys);
		}
		if (obj) {
			if (ps->p >= ps->end || *ps->p != '"') {
				ps->bad = 1;
				return;
			}
			size_t kl;
			v->keys[v->n] = str(ps, &kl);
			ws(ps);
			if (ps->p >= ps->end || *ps->p != ':') {
				ps->bad = 1;
				return;
			}
			ps->p++;
		}
		memset(&v->items[v->n], 0, sizeof v->items[v->n]);
		value(ps, &v->items[v->n]);
		v->n++;
		if (ps->bad)
			return;
		ws(ps);
		if (ps->p < ps->end && *ps->p == ',') {
			ps->p++;
			continue;
		}
		if (ps->p < ps->end && *ps->p == (obj ? '}' : ']')) {
			ps->p++;
			return;
		}
		ps->bad = 1;
		return;
	}
}

static void value(struct parser *ps, struct jv *v)
{
	ws(ps);
	if (ps->p >= ps->end) {
		ps->bad = 1;
		return;
	}
	const char *start = ps->p;
	switch (*ps->p) {
	case '{':
		v->t = JV_OBJ;
		array_or_object(ps, v, 1);
		break;
	case '[':
		v->t = JV_ARR;
		array_or_object(ps, v, 0);
		break;
	case '"':
		v->t = JV_STR;
		v->s = str(ps, &v->slen);
		break;
	case 't':
	case 'f':
	case 'n': {
		const char *w = *ps->p == 't' ? "true" : *ps->p == 'f' ? "false" : "null";
		size_t l = strlen(w);
		if ((size_t)(ps->end - ps->p) < l || memcmp(ps->p, w, l)) {
			ps->bad = 1;
			return;
		}
		ps->p += l;
		v->t = *w == 'n' ? JV_NULL : JV_BOOL;
		v->b = *w == 't';
		break;
	}
	default: {
		const char *s = ps->p;
		while (ps->p < ps->end && strchr("+-0123456789.eE", *ps->p))
			ps->p++;
		if (ps->p == s) {
			ps->bad = 1;
			return;
		}
		v->t = JV_NUM;
		v->s = xstrndup(s, (size_t)(ps->p - s));
	}
	}
	v->raw = start;
	v->rawlen = (size_t)(ps->p - start);
}

struct jv *jv_parse(const char *data, size_t len)
{
	struct parser ps = {data, data + len, 0};
	struct jv *v = xmalloc(sizeof *v);
	memset(v, 0, sizeof *v);
	value(&ps, v);
	ws(&ps);
	if (ps.bad || ps.p != ps.end)
		return NULL;
	return v;
}

/* Go's json.Unmarshal into a struct: every member whose key folds (ASCII case) to the field's name sets the field, so the last
 * such member in document order wins. */
const struct jv *jv_get(const struct jv *o, const char *key)
{
	if (!o || o->t != JV_OBJ)
		return NULL;
	const struct jv *hit = NULL;
	for (size_t i = 0; i < o->n; i++)
		if (strcasecmp(o->keys[i], key) == 0 && strlen(o->keys[i]) == strlen(key))
			hit = &o->items[i];
	return hit;
}

static const struct jv *typed(const struct jv *o, const char *key, enum jv_type t, const char *where)
{
	const struct jv *v = jv_get(o, key);
	if (!v || v->t == JV_NULL)
		return NULL;
	if (v->t != t)
		not_ported("%s.%s: a JSON value of another type than the Go field (json.Unmarshal's type error)", where, key);
	return v;
}

const char *jv_str(const struct jv *o, const char *key, const char *where)
{
	const struct jv *v = typed(o, key, JV_STR, where);
	return v ? v->s : "";
}

int64_t jv_int(const struct jv *o, const char *key, const char *where)
{
	const struct jv *v = typed(o, key, JV_NUM, where);
	if (!v)
		return 0;
	char *end;
	long long x = strtoll(v->s, &end, 10);
	if (*end || end == v->s)
		not_ported("%s.%s: the number %s is not an integer Go's int reads", where, key, v->s);
	return x;
}

int jv_bool(const struct jv *o, const char *key, const char *where)
{
	const struct jv *v = typed(o, key, JV_BOOL, where);
	return v ? v->b : 0;
}

const struct jv *jv_arr(const struct jv *o, const char *key, const char *where) { return typed(o, key, JV_ARR, where); }
const struct jv *jv_obj(const struct jv *o, const char *key, const char *where) { return typed(o, key, JV_OBJ, where); }
