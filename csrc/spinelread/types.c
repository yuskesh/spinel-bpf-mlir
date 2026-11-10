/* spinelread: ParseTypes, the index and TypeOf / CodegenOf (internal/frontend/types.go).
 *
 * Step 1: bml_build_json_check_any, the C form of requirements.DecodeStrictJSON into `any`.
 * Step 2: on a document that passed it, encoding/json's plain Unmarshal into Types, as Go 1.27 does it (rules read from its
 * source, v1 legacy semantics): members in document order; a key matches a field exactly, else when strings.EqualFold holds;
 * null is a no-op on a scalar and sets a pointer or a slice to nil; an array into a nil or empty slice fills fresh elements (a
 * null element is the zero value); an int takes only an integer literal in int64's range. A JSON type Go refuses, and an array
 * decoded into a slice that already holds elements (Go reuses them), stop as "not ported". */
#include "sr.h"

#include <bml/build.h>
#include <stdlib.h>
#include <string.h>

/* ---- a small tree reader for a document that already passed the strict check ---- */

enum { J_NULL, J_FALSE, J_TRUE, J_NUMBER, J_STRING, J_ARRAY, J_OBJECT };
typedef struct jv jv;
typedef struct {
	sr_str key;
	jv *val;
} jmember;
struct jv {
	int t;
	sr_str s; /* a string's decoded bytes, a number's text */
	jv **elems;
	jmember *members;
	size_t n;
};

typedef struct {
	const char *p;
	size_t n, i;
} jparser;

static void ws(jparser *j)
{
	while (j->i < j->n && (j->p[j->i] == ' ' || j->p[j->i] == '\t' || j->p[j->i] == '\n' || j->p[j->i] == '\r'))
		j->i++;
}

static unsigned hex4(const char *p)
{
	unsigned v = 0;
	for (int k = 0; k < 4; k++) {
		char c = p[k];
		v <<= 4;
		v |= c <= '9' ? (unsigned)(c - '0') : (unsigned)((c | 0x20) - 'a' + 10);
	}
	return v;
}

/* encoding/json's unquoting under the v1 options: invalid UTF-8 and unpaired surrogates become U+FFFD */
static sr_str jstring(jparser *j)
{
	sr_buf b = {0};
	j->i++; /* the opening quote */
	for (;;) {
		unsigned char c = (unsigned char)j->p[j->i];
		if (c == '"') {
			j->i++;
			break;
		}
		if (c == '\\') {
			char e = j->p[j->i + 1];
			j->i += 2;
			switch (e) {
			case 'b': sr_putc(&b, '\b'); break;
			case 'f': sr_putc(&b, '\f'); break;
			case 'n': sr_putc(&b, '\n'); break;
			case 'r': sr_putc(&b, '\r'); break;
			case 't': sr_putc(&b, '\t'); break;
			case 'u': {
				int32_t r = (int32_t)hex4(j->p + j->i);
				j->i += 4;
				if (r >= 0xD800 && r <= 0xDFFF) {
					int32_t pair = 0xFFFD;
					if (r <= 0xDBFF && j->i + 6 <= j->n && j->p[j->i] == '\\' && j->p[j->i + 1] == 'u') {
						int32_t lo = (int32_t)hex4(j->p + j->i + 2);
						if (lo >= 0xDC00 && lo <= 0xDFFF) {
							pair = 0x10000 + ((r - 0xD800) << 10) + (lo - 0xDC00);
							j->i += 6;
						}
					}
					r = pair;
				}
				sr_append_rune(&b, r);
				break;
			}
			default: sr_putc(&b, e); /* '"', '\\', '/' */
			}
			continue;
		}
		size_t w;
		int32_t r = sr_decode_rune(j->p + j->i, j->n - j->i, &w);
		if (r == 0xFFFD && w == 1)
			sr_append_rune(&b, 0xFFFD);
		else
			sr_put(&b, j->p + j->i, w);
		j->i += w;
	}
	return sr_bufstr(&b);
}

static jv *jvalue(jparser *j)
{
	jv *v = sr_alloc(sizeof *v);
	ws(j);
	char c = j->p[j->i];
	if (c == '{') {
		j->i++;
		ws(j);
		if (j->p[j->i] == '}') {
			j->i++;
			v->t = J_OBJECT;
			return v;
		}
		for (;;) {
			ws(j);
			sr_str k = jstring(j);
			ws(j);
			j->i++; /* ':' */
			jv *m = jvalue(j);
			v->members = sr_grow(v->members, v->n * sizeof *v->members, (v->n + 1) * sizeof *v->members);
			v->members[v->n].key = k;
			v->members[v->n++].val = m;
			ws(j);
			if (j->p[j->i++] == '}')
				break; /* else ',' */
		}
		v->t = J_OBJECT;
	} else if (c == '[') {
		j->i++;
		ws(j);
		v->t = J_ARRAY;
		if (j->p[j->i] == ']') {
			j->i++;
			return v;
		}
		for (;;) {
			jv *e = jvalue(j);
			v->elems = sr_grow(v->elems, v->n * sizeof *v->elems, (v->n + 1) * sizeof *v->elems);
			v->elems[v->n++] = e;
			ws(j);
			if (j->p[j->i++] == ']')
				break;
		}
	} else if (c == '"') {
		v->t = J_STRING;
		v->s = jstring(j);
	} else if (c == 'n') {
		v->t = J_NULL;
		j->i += 4;
	} else if (c == 't') {
		v->t = J_TRUE;
		j->i += 4;
	} else if (c == 'f') {
		v->t = J_FALSE;
		j->i += 5;
	} else {
		size_t s = j->i;
		while (j->i < j->n && strchr("+-0123456789.eE", j->p[j->i]))
			j->i++;
		v->t = J_NUMBER;
		v->s = (sr_str){j->p + s, j->i - s};
	}
	return v;
}

/* ---- the mapping ---- */

/* strings.EqualFold(key, name) for an ASCII field name: rune by rune, Unicode simple folding. Among non-ASCII runes only
 * U+212A (Kelvin sign, in k's orbit) and U+017F (long s, in s's orbit) fold to an ASCII letter. */
static int field_match(sr_str key, const char *name)
{
	size_t i = 0;
	for (const char *q = name; *q; q++) {
		if (i >= key.n)
			return 0;
		size_t w;
		int32_t r = sr_decode_rune(key.p + i, key.n - i, &w);
		i += w;
		char c = *q;
		char lc = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
		if (r == c)
			continue;
		if (lc >= 'a' && lc <= 'z') {
			if (r == lc || r == lc - 32)
				continue;
			if ((lc == 'k' && r == 0x212A) || (lc == 's' && r == 0x17F))
				continue;
		}
		return 0;
	}
	return i == key.n;
}

/* returns the field index, or -1: an exact match first, else the EqualFold match (field names here never fold together) */
static int lookup(sr_str key, const char *const *names, int n)
{
	for (int i = 0; i < n; i++)
		if (sr_eqc(key, names[i]))
			return i;
	for (int i = 0; i < n; i++)
		if (field_match(key, names[i]))
			return i;
	return -1;
}

typedef struct {
	sr_buf path;
} mctx;

static sr_result mismatch(mctx *m, const char *what, const jv *v)
{
	static const char *const tn[] = {"null", "false", "true", "number", "string", "array", "object"};
	return sr_not_ported("--emit-types JSON type mismatch at %s: %s into %s", m->path.n ? m->path.p : "(document)", tn[v->t],
			     what);
}

static size_t push_path(mctx *m, const char *seg, long idx)
{
	size_t at = m->path.n;
	if (seg) {
		if (m->path.n)
			sr_putc(&m->path, '.');
		sr_puts(&m->path, seg);
	} else {
		sr_printf(&m->path, "[%ld]", idx);
	}
	return at;
}

static void pop_path(mctx *m, size_t at)
{
	m->path.n = at;
	if (m->path.p)
		m->path.p[at] = 0;
}

static sr_result set_str(mctx *m, const jv *v, sr_str *dst)
{
	if (v->t == J_NULL)
		return sr_ok;
	if (v->t != J_STRING)
		return mismatch(m, "string", v);
	*dst = v->s;
	return sr_ok;
}

static sr_result set_int(mctx *m, const jv *v, int64_t *dst)
{
	if (v->t == J_NULL)
		return sr_ok;
	if (v->t != J_NUMBER || !sr_parse_int64(v->s, dst))
		return mismatch(m, "int", v);
	return sr_ok;
}

static sr_result set_bool(mctx *m, const jv *v, int *dst)
{
	if (v->t == J_NULL)
		return sr_ok;
	if (v->t != J_TRUE && v->t != J_FALSE)
		return mismatch(m, "bool", v);
	*dst = v->t == J_TRUE;
	return sr_ok;
}

/* the common record fields: file, line, col, end_line, end_col */
enum { RF_FILE, RF_LINE, RF_COL, RF_END_LINE, RF_END_COL };

static const char *const type_names[] = {"file", "line", "col", "end_line", "end_col", "kind", "name",
					 "type", "rbs", "owner", "signature", "singleton", "widened"};
static const char *const cg_names[] = {"file", "line", "col", "end_line", "end_col", "kind", "name",
				       "dispatch", "callee", "candidates", "inlined"};
static const char *const diag_names[] = {"file", "line", "col", "severity", "method", "slot", "param", "message"};

#define NAMES(a) (int)(sizeof(a) / sizeof(a[0]))

static sr_result type_field(mctx *m, sr_type_rec *r, int f, const jv *v)
{
	switch (f) {
	case 0: return set_str(m, v, &r->file);
	case 1: return set_int(m, v, &r->line);
	case 2: return set_int(m, v, &r->col);
	case 3: r->has_end = 1; return set_int(m, v, &r->end_line);
	case 4: r->has_end = 1; return set_int(m, v, &r->end_col);
	case 5: return set_str(m, v, &r->kind);
	case 6: return set_str(m, v, &r->name);
	case 7: return set_str(m, v, &r->type);
	case 8: return set_str(m, v, &r->rbs);
	case 9: return set_str(m, v, &r->owner);
	case 10: return set_str(m, v, &r->signature);
	case 11: return set_bool(m, v, &r->singleton);
	default: return set_bool(m, v, &r->widened);
	}
}

static sr_result diag_field(mctx *m, sr_diag_rec *r, int f, const jv *v)
{
	switch (f) {
	case 0: return set_str(m, v, &r->file);
	case 1: return set_int(m, v, &r->line);
	case 2: return set_int(m, v, &r->col);
	case 3: return set_str(m, v, &r->severity);
	case 4: return set_str(m, v, &r->method);
	case 5: return set_str(m, v, &r->slot);
	case 6: return set_str(m, v, &r->param);
	default: return set_str(m, v, &r->message);
	}
}

static sr_result candidates(mctx *m, sr_codegen_rec *r, const jv *v)
{
	if (v->t == J_NULL) {
		r->candidates = NULL;
		r->n_candidates = 0;
		r->candidates_nil = 1;
		return sr_ok;
	}
	if (v->t != J_ARRAY)
		return mismatch(m, "[]string", v);
	if (r->n_candidates > 0)
		return sr_not_ported("an array decoded again into %s, which Go fills by reusing the earlier elements", m->path.p);
	sr_str *c = sr_alloc((v->n ? v->n : 1) * sizeof *c);
	for (size_t i = 0; i < v->n; i++) {
		size_t at = push_path(m, NULL, (long)i);
		sr_result e = set_str(m, v->elems[i], &c[i]);
		pop_path(m, at);
		if (e.kind)
			return e;
	}
	r->candidates = c;
	r->n_candidates = v->n;
	r->candidates_nil = 0;
	return sr_ok;
}

static sr_result cg_field(mctx *m, sr_codegen_rec *r, int f, const jv *v)
{
	switch (f) {
	case 0: return set_str(m, v, &r->file);
	case 1: return set_int(m, v, &r->line);
	case 2: return set_int(m, v, &r->col);
	case 3: return set_int(m, v, &r->end_line);
	case 4: return set_int(m, v, &r->end_col);
	case 5: return set_str(m, v, &r->kind);
	case 6: return set_str(m, v, &r->name);
	case 7: return set_str(m, v, &r->dispatch);
	case 8: return set_str(m, v, &r->callee);
	case 9: return candidates(m, r, v);
	default:
		if (v->t == J_NULL) {
			r->inlined = -1;
			return sr_ok;
		}
		if (v->t != J_TRUE && v->t != J_FALSE)
			return mismatch(m, "*bool", v);
		r->inlined = v->t == J_TRUE;
		return sr_ok;
	}
}

/* one record object (or null, which leaves the fresh zero record) */
#define RECORD(fn_name, rec_t, names, field_fn, init)                                                                      \
	static sr_result fn_name(mctx *m, const jv *v, rec_t *r)                                                           \
	{                                                                                                                  \
		init;                                                                                                      \
		if (v->t == J_NULL)                                                                                        \
			return sr_ok;                                                                                      \
		if (v->t != J_OBJECT)                                                                                      \
			return mismatch(m, #rec_t, v);                                                                     \
		for (size_t i = 0; i < v->n; i++) {                                                                        \
			int f = lookup(v->members[i].key, names, NAMES(names));                                            \
			if (f < 0)                                                                                         \
				continue;                                                                                  \
			size_t at = push_path(m, names[f], 0);                                                             \
			sr_result e = field_fn(m, r, f, v->members[i].val);                                                \
			pop_path(m, at);                                                                                   \
			if (e.kind)                                                                                        \
				return e;                                                                                  \
		}                                                                                                          \
		return sr_ok;                                                                                              \
	}

RECORD(type_rec, sr_type_rec, type_names, type_field, (void)0)
RECORD(diag_rec, sr_diag_rec, diag_names, diag_field, (void)0)
RECORD(cg_rec, sr_codegen_rec, cg_names, cg_field, (r->inlined = -1, r->candidates_nil = 1))

/* a top-level slice: null sets nil; an array fills fresh records, unless the slice already holds some */
#define SLICE(fn_name, rec_t, rec_fn)                                                                                      \
	static sr_result fn_name(mctx *m, const jv *v, rec_t **dst, size_t *n, int *is_nil)                                \
	{                                                                                                                  \
		if (v->t == J_NULL) {                                                                                      \
			*dst = NULL;                                                                                       \
			*n = 0;                                                                                            \
			*is_nil = 1;                                                                                       \
			return sr_ok;                                                                                      \
		}                                                                                                          \
		if (v->t != J_ARRAY)                                                                                       \
			return mismatch(m, "[]" #rec_t, v);                                                                \
		if (*n > 0)                                                                                                \
			return sr_not_ported("an array decoded again into %s, which Go fills by reusing the earlier elements", \
					     m->path.p);                                                                   \
		rec_t *a = sr_alloc((v->n ? v->n : 1) * sizeof *a);                                                        \
		for (size_t i = 0; i < v->n; i++) {                                                                        \
			size_t at = push_path(m, NULL, (long)i);                                                           \
			sr_result e = rec_fn(m, v->elems[i], &a[i]);                                                       \
			pop_path(m, at);                                                                                   \
			if (e.kind)                                                                                        \
				return e;                                                                                  \
		}                                                                                                          \
		*dst = a;                                                                                                  \
		*n = v->n;                                                                                                 \
		*is_nil = 0;                                                                                               \
		return sr_ok;                                                                                              \
	}

SLICE(type_slice, sr_type_rec, type_rec)
SLICE(diag_slice, sr_diag_rec, diag_rec)
SLICE(cg_slice, sr_codegen_rec, cg_rec)

static const char *const top_names[] = {"types", "diagnostics", "codegen"};

static sr_result unmarshal(const jv *v, sr_types *t)
{
	mctx m = {{0}};
	if (v->t == J_NULL)
		return sr_ok;
	if (v->t != J_OBJECT)
		return mismatch(&m, "Types", v);
	for (size_t i = 0; i < v->n; i++) {
		int f = lookup(v->members[i].key, top_names, NAMES(top_names));
		if (f < 0)
			continue;
		size_t at = push_path(&m, top_names[f], 0);
		const jv *x = v->members[i].val;
		sr_result e = f == 0   ? type_slice(&m, x, &t->types, &t->n_types, &t->types_nil)
			      : f == 1 ? diag_slice(&m, x, &t->diags, &t->n_diags, &t->diags_nil)
				       : cg_slice(&m, x, &t->codegen, &t->n_codegen, &t->codegen_nil);
		pop_path(&m, at);
		if (e.kind)
			return e;
	}
	return sr_ok;
}

/* ---- the index: (file, line, col, end_line, end_col, kind) → record indices ---- */

typedef struct ientry {
	sr_str key;
	size_t *ids;
	size_t n;
	struct ientry *next;
} ientry;

struct sr_index {
	ientry **b;
	size_t cap;
};

static sr_str span_key(sr_str file, int64_t line, int64_t col, int64_t el, int64_t ec, sr_str kind)
{
	sr_buf b = {0};
	uint64_t nf = file.n;
	sr_put(&b, &nf, sizeof nf);
	sr_putstr(&b, file);
	sr_put(&b, &line, sizeof line);
	sr_put(&b, &col, sizeof col);
	sr_put(&b, &el, sizeof el);
	sr_put(&b, &ec, sizeof ec);
	sr_putstr(&b, kind);
	return sr_bufstr(&b);
}

static size_t str_hash(sr_str s)
{
	uint64_t h = 1469598103934665603ull;
	for (size_t i = 0; i < s.n; i++)
		h = (h ^ (unsigned char)s.p[i]) * 1099511628211ull;
	return (size_t)h;
}

static ientry *index_find(const sr_index *x, sr_str k)
{
	for (ientry *e = x->b[str_hash(k) & (x->cap - 1)]; e; e = e->next)
		if (sr_eq(e->key, k))
			return e;
	return NULL;
}

static void index_add(sr_index *x, sr_str k, size_t id)
{
	ientry *e = index_find(x, k);
	if (!e) {
		e = sr_alloc(sizeof *e);
		e->key = k;
		size_t h = str_hash(k) & (x->cap - 1);
		e->next = x->b[h];
		x->b[h] = e;
	}
	e->ids = sr_grow(e->ids, e->n * sizeof *e->ids, (e->n + 1) * sizeof *e->ids);
	e->ids[e->n++] = id;
}

static sr_index *new_index(size_t n)
{
	sr_index *x = sr_alloc(sizeof *x);
	x->cap = 64;
	while (x->cap < n * 2)
		x->cap *= 2;
	x->b = sr_alloc(x->cap * sizeof *x->b);
	return x;
}

void sr_reindex_types(sr_types *t)
{
	t->by_key = new_index(t->n_types);
	for (size_t i = 0; i < t->n_types; i++) {
		sr_type_rec *r = &t->types[i];
		index_add(t->by_key, span_key(r->file, r->line, r->col, r->end_line, r->end_col, r->kind), i);
	}
	t->cg_by_key = new_index(t->n_codegen);
	for (size_t i = 0; i < t->n_codegen; i++) {
		sr_codegen_rec *r = &t->codegen[i];
		index_add(t->cg_by_key, span_key(r->file, r->line, r->col, r->end_line, r->end_col, r->kind), i);
	}
}

static long join(const sr_index *x, const sr_ast *a, const sr_node *n, size_t *count)
{
	ientry *e = index_find(x, span_key(sr_ast_file(a, n), n->line, n->col, n->end_line, n->end_col, n->type));
	*count = e ? e->n : 0;
	return *count == 1 ? (long)e->ids[0] : -1;
}

long sr_type_of(const sr_types *t, const sr_ast *a, const sr_node *n, size_t *count) { return join(t->by_key, a, n, count); }

long sr_codegen_of(const sr_types *t, const sr_ast *a, const sr_node *n, size_t *count)
{
	return join(t->cg_by_key, a, n, count);
}

/* ---- ParseTypes ---- */

static sr_result decode_types(sr_str data, int candidates, sr_types **out, size_t **cand, size_t *n_cand)
{
	struct bml_build_error be = {0};
	int rc = bml_build_json_check_any(data.p, data.n, &be);
	if (rc == BML_BUILD_NOMEM) {
		fputs("spinelread: out of memory in bml_build_json_check_any\n", stderr);
		exit(3);
	}
	if (rc != BML_BUILD_OK) {
		sr_str text = sr_dup(be.text ? be.text : "", be.text ? strlen(be.text) : 0);
		bml_build_error_free(&be);
		if (rc == BML_BUILD_FAIL)
			return sr_err("spinel --emit-types JSON: %.*s", (int)text.n, text.p);
		return sr_not_ported("bml_build_json_check_any code %d: %.*s", rc, (int)text.n, text.p);
	}
	bml_build_error_free(&be);
	sr_types *t = sr_alloc(sizeof *t);
	t->types_nil = t->diags_nil = t->codegen_nil = 1;
	jparser j = {data.p, data.n, 0};
	jv *root = jvalue(&j);
	sr_result e = unmarshal(root, t);
	if (e.kind)
		return e;
	/* types.go decodeTypes: with candidates, a row with neither end key (and a file and a kind) is a candidate; every other row is
	 * checked as without candidates */
	size_t *c = sr_alloc((t->n_types ? t->n_types : 1) * sizeof *c), nc = 0;
	for (size_t i = 0; i < t->n_types; i++) {
		sr_type_rec *r = &t->types[i];
		if (r->file.n == 0 || r->kind.n == 0 || r->end_line == 0) {
			if (candidates && !r->has_end && r->file.n != 0 && r->kind.n != 0) {
				c[nc++] = i;
				continue;
			}
			return sr_err("spinel --emit-types JSON: type record %zu has no file / kind / end", i);
		}
	}
	*out = t;
	*cand = c;
	*n_cand = nc;
	return sr_ok;
}

sr_result sr_parse_types(sr_str data, sr_types **out)
{
	sr_types *t;
	size_t *c, nc;
	sr_result e = decode_types(data, 0, &t, &c, &nc);
	if (e.kind)
		return e;
	sr_reindex_types(t);
	*out = t;
	return sr_ok;
}

/* ---- A block parameter's rename (types.go renameRefusal) ---- */

static const sr_str *node_str(const sr_node *n, const char *k)
{
	for (size_t i = 0; i < n->n_str; i++)
		if (sr_eqc(n->str[i].k, k))
			return &n->str[i].v;
	return NULL;
}

/* the parent of child, when it has type want and holds child in field (an array field when arr) */
static const sr_node *parent_in(const sr_ast *a, const sr_node *child, const char *want, const char *field, int arr)
{
	int64_t *pid = sr_imap_get(&a->parent, child->id);
	if (!pid)
		return NULL;
	const sr_node *p = sr_imap_get(&a->nodes, *pid);
	if (!p || !sr_eqc(p->type, want))
		return NULL;
	if (arr) {
		for (size_t i = 0; i < p->n_arr; i++)
			if (sr_eqc(p->arr[i].k, field))
				for (size_t j = 0; j < p->arr[i].n; j++)
					if (p->arr[i].ids[j] == child->id)
						return p;
		return NULL;
	}
	for (size_t i = 0; i < p->n_ref; i++)
		if (sr_eqc(p->ref[i].k, field))
			return p->ref[i].v == child->id ? p : NULL;
	return NULL;
}

static int is_block_param(const sr_ast *a, const sr_node *n)
{
	const sr_node *q = parent_in(a, n, "ParametersNode", "requireds", 1);
	const sr_node *bp = q ? parent_in(a, q, "BlockParametersNode", "parameters", 0) : NULL;
	return bp && parent_in(a, bp, "BlockNode", "parameters", 0) != NULL;
}

/* ^([a-z_][A-Za-z0-9_]*)__bp(?:in|[0-9]+)$ : 1 and *base on a match */
static int rename_base(sr_str name, sr_str *base)
{
	if (name.n < 5)
		return 0;
	size_t at = (size_t)-1;
	for (size_t i = 0; i + 4 <= name.n; i++)
		if (memcmp(name.p + i, "__bp", 4) == 0)
			at = i;
	if (at == (size_t)-1 || at == 0)
		return 0;
	sr_str suf = {name.p + at + 4, name.n - at - 4};
	int ok = sr_eqc(suf, "in");
	if (!ok && suf.n > 0) {
		ok = 1;
		for (size_t i = 0; i < suf.n; i++)
			if (suf.p[i] < '0' || suf.p[i] > '9')
				ok = 0;
	}
	if (!ok)
		return 0;
	char c0 = name.p[0];
	if (!((c0 >= 'a' && c0 <= 'z') || c0 == '_'))
		return 0;
	for (size_t i = 1; i < at; i++) {
		char c = name.p[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
			return 0;
	}
	*base = (sr_str){name.p, at};
	return 1;
}

static const char *rename_refusal(const sr_ast *a, const sr_type_rec *r)
{
	if (!a)
		return "no AST";
	if (!sr_eqc(r->kind, "LocalVariableWriteNode") && !sr_eqc(r->kind, "LocalVariableReadNode"))
		return "the kind";
	sr_str base;
	if (!rename_base(r->name, &base))
		return "the name has no rename form";
	int64_t *ids = sr_imap_sorted_keys(&a->nodes);
	const sr_node *hit = NULL;
	size_t count = 0;
	for (size_t i = 0; i < a->nodes.n; i++) {
		const sr_node *n = sr_imap_get(&a->nodes, ids[i]);
		if (sr_eqc(n->type, "RequiredParameterNode") && sr_eq(sr_ast_file(a, n), r->file) && n->line == r->line &&
		    n->col == r->col && is_block_param(a, n)) {
			hit = n;
			count++;
		}
	}
	if (count == 0)
		return "no block parameter at its position";
	if (count > 1)
		return "two or more block parameters at its position";
	const sr_str *nm = node_str(hit, "name");
	if (!nm || !sr_eq(*nm, base))
		return "the base is not the parameter's name";
	return NULL;
}

sr_result sr_parse_types_ast(sr_str data, const sr_ast *a, sr_types **out, sr_type_rec **sel, size_t *n_sel)
{
	sr_types *t;
	size_t *c, nc;
	sr_result e = decode_types(data, 1, &t, &c, &nc);
	if (e.kind)
		return e;
	sr_type_rec *s = sr_alloc((nc ? nc : 1) * sizeof *s);
	for (size_t k = 0; k < nc; k++) {
		sr_type_rec *r = &t->types[c[k]];
		const char *why = rename_refusal(a, r);
		if (why)
			return sr_err("spinel --emit-types JSON: type record %zu has no file / kind / end (%.*s %.*s at %.*s:%lld:%lld is not a "
				      "block parameter's rename: %s)",
				      c[k], (int)r->kind.n, r->kind.p, (int)r->name.n, r->name.p, (int)r->file.n, r->file.p,
				      (long long)r->line, (long long)r->col, why);
		s[k] = *r;
	}
	if (nc > 0) {
		size_t w = 0, k = 0;
		for (size_t i = 0; i < t->n_types; i++) {
			if (k < nc && c[k] == i) {
				k++;
				continue;
			}
			t->types[w++] = t->types[i];
		}
		t->n_types = w;
	}
	sr_reindex_types(t);
	*out = t;
	*sel = s;
	*n_sel = nc;
	return sr_ok;
}
