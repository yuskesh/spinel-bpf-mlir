/* csrc/driver/diag.c - see diag.h. */
#include "diag.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bml/build.h"

/* internal/frontend/result.go codeNames. A gate test compares this table with Go's. */
static const struct {
	const char *code, *name;
} codes[] = {
	{"SB000", "Spinel"}, {"SB001", "UnsupportedConstruct"}, {"SB002", "UnsupportedCall"}, {"SB003", "CrossDomainUse"},
	{"SB004", "UnknownEdge"}, {"SB005", "RefCheckShape"}, {"SB006", "NonConstant"}, {"SB007", "ReservedName"},
	{"SB008", "ProgramShape"}, {"SB009", "OperatorRedefined"}, {"SB010", "TypingProbe"}, {"SB011", "ShadowedName"},
	{"SB012", "ThreadInUserSide"}, {"SB013", "MapDeclShape"}, {"SB014", "SemanticGap"}, {"SB015", "AmbiguousType"},
	{"SB016", "DynamicProgram"}, {"SB017", "InternalEmitter"}, {"SB018", "LogicalSideEffect"},
	{"SB019", "SharedReadModifyWrite"}, {"SB020", "KeyOutOfRange"}, {"SB021", "CompileWarning"}, {"SB022", "WindowIndex"},
	{"SB023", "PacketOffset"}, {"SB024", "RecordShape"}, {"SB025", "DroppedEvent"}, {"SB026", "StatusIgnored"},
	{"SB027", "ThreadInBPFSide"}, {"SB028", "TracingKind"}, {"SB029", "GlobalShape"}, {"SB030", "LoopShape"},
	{"SB031", "IndexRange"}, {"SB032", "UprobeTarget"}, {"SB033", "KernelTypeShape"}, {"SB034", "SubprogramShape"},
	{"SB035", "Recursion"},
};

const char *code_at(size_t i, const char **name)
{
	if (i >= sizeof codes / sizeof codes[0])
		return NULL;
	*name = codes[i].name;
	return codes[i].code;
}

const char *code_name(const char *code)
{
	for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++)
		if (!strcmp(codes[i].code, code))
			return codes[i].name;
	return NULL;
}

static const char *verdict_str(enum verdict v)
{
	switch (v) {
	case V_VERIFIED: return "verified";
	case V_REJECTED: return "rejected";
	case V_CONDITIONAL: return "conditional";
	case V_UNKNOWN: return "unknown";
	}
	return "verdict(?)";
}

void diags_push(struct diags *ds, struct diag d)
{
	if (ds->n == ds->cap) {
		ds->cap = ds->cap ? ds->cap * 2 : 8;
		ds->v = xrealloc(ds->v, ds->cap * sizeof *ds->v);
	}
	ds->v[ds->n++] = d;
}

int diags_blocking(const struct diags *ds)
{
	for (size_t i = 0; i < ds->n; i++)
		if (ds->v[i].verdict == V_REJECTED || ds->v[i].verdict == V_UNKNOWN)
			return 1;
	return 0;
}

static int less(const struct diag *a, const struct diag *b)
{
	int c = strcmp(a->pos.file, b->pos.file);
	if (c)
		return c < 0;
	if (a->pos.line != b->pos.line)
		return a->pos.line < b->pos.line;
	if (a->pos.col != b->pos.col)
		return a->pos.col < b->pos.col;
	return strcmp(a->code, b->code) < 0;
}

/* sort.SliceStable: an insertion sort is stable and the lists are short. */
void diags_sort(struct diags *ds)
{
	for (size_t i = 1; i < ds->n; i++) {
		struct diag t = ds->v[i];
		size_t j = i;
		while (j > 0 && less(&t, &ds->v[j - 1])) {
			ds->v[j] = ds->v[j - 1];
			j--;
		}
		ds->v[j] = t;
	}
}

char *pos_str(const struct pos *p)
{
	if (!p->file[0])
		return xstrdup("-");
	if (p->line == 0)
		return xstrdup(p->file);
	return xasprintf("%s:%lld:%lld", p->file, p->line, p->col);
}

char *diag_str(const struct diag *d)
{
	struct sb b = {0};
	const char *name = code_name(d->code);
	sb_printf(&b, "%s: %s %s (%s): %s", pos_str(&d->pos), verdict_str(d->verdict), d->code, name ? name : "", d->msg);
	if (d->path.n > 0) {
		sb_puts(&b, " [path: ");
		for (size_t i = 0; i < d->path.n; i++) {
			if (i)
				sb_puts(&b, " -> ");
			sb_puts(&b, d->path.v[i]);
		}
		sb_putc(&b, ']');
	}
	return sb_take(&b);
}

char *diags_error(const struct diags *ds)
{
	struct diags s = {0};
	for (size_t i = 0; i < ds->n; i++)
		diags_push(&s, ds->v[i]);
	diags_sort(&s);
	struct sb b = {0};
	for (size_t i = 0; i < s.n; i++) {
		if (i)
			sb_putc(&b, '\n');
		sb_puts(&b, diag_str(&s.v[i]));
	}
	return sb_take(&b);
}

/* ---- ReadDomainGraph ---- */

static const struct bml_build_shape s_str = {BML_BUILD_SHAPE_STRING, 0, NULL, NULL, 0};
static const struct bml_build_shape s_int = {BML_BUILD_SHAPE_INT, 64, NULL, NULL, 0};
static const struct bml_build_shape s_strs = {BML_BUILD_SHAPE_ARRAY, 0, &s_str, NULL, 0};
static const struct bml_build_field f_pos[] = {{"file", &s_str}, {"line", &s_int}, {"col", &s_int}};
static const struct bml_build_shape s_pos = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_pos, 3};
static const struct bml_build_field f_root[] = {{"name", &s_str}, {"kind", &s_str}, {"decl", &s_pos}, {"def", &s_pos}};
static const struct bml_build_shape s_root = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_root, 4};
static const struct bml_build_field f_func[] = {{"name", &s_str}, {"membership", &s_strs}};
static const struct bml_build_shape s_func = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_func, 2};
static const struct bml_build_field f_edge[] = {{"from", &s_str}, {"to", &s_str}, {"pos", &s_pos}, {"dispatch", &s_str}};
static const struct bml_build_shape s_edge = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_edge, 4};
static const struct bml_build_field f_diag[] = {{"verdict", &s_str}, {"code", &s_str}, {"name", &s_str},
						{"pos", &s_pos},     {"path", &s_strs}, {"message", &s_str}};
static const struct bml_build_shape s_diag = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_diag, 6};
static const struct bml_build_shape s_roots = {BML_BUILD_SHAPE_ARRAY, 0, &s_root, NULL, 0};
static const struct bml_build_shape s_funcs = {BML_BUILD_SHAPE_ARRAY, 0, &s_func, NULL, 0};
static const struct bml_build_shape s_edges = {BML_BUILD_SHAPE_ARRAY, 0, &s_edge, NULL, 0};
static const struct bml_build_shape s_diags = {BML_BUILD_SHAPE_ARRAY, 0, &s_diag, NULL, 0};
static const struct bml_build_field f_doc[] = {
	{"source", &s_str}, {"roots", &s_roots}, {"functions", &s_funcs}, {"edges", &s_edges}, {"diagnostics", &s_diags}};
static const struct bml_build_shape s_doc = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_doc, 5};

/* A string member (Go's zero value "" when absent or null). */
static char *nstr(const struct bml_build_json_node *o, const char *key)
{
	const struct bml_build_json_node *v = o ? bml_build_json_get(o, key, strlen(key)) : NULL;
	size_t l;
	const char *s = v ? bml_build_json_string_value(v, &l) : NULL;
	return s ? xstrndup(s, l) : xstrdup("");
}

static long long nint(const struct bml_build_json_node *o, const char *key)
{
	const struct bml_build_json_node *v = o ? bml_build_json_get(o, key, strlen(key)) : NULL;
	int64_t x = 0;
	if (v && bml_build_json_type(v) == BML_BUILD_JSON_NUMBER)
		bml_build_json_int64(v, &x);
	return x;
}

static struct pos npos(const struct bml_build_json_node *o, const char *key)
{
	const struct bml_build_json_node *v = o ? bml_build_json_get(o, key, strlen(key)) : NULL;
	if (v && bml_build_json_type(v) != BML_BUILD_JSON_OBJECT)
		v = NULL;
	struct pos p = {nstr(v, "file"), nint(v, "line"), nint(v, "col")};
	return p;
}

/* The array member, or NULL when absent or null (Go's nil slice). */
static const struct bml_build_json_node *narr(const struct bml_build_json_node *o, const char *key)
{
	const struct bml_build_json_node *v = bml_build_json_get(o, key, strlen(key));
	return v && bml_build_json_type(v) == BML_BUILD_JSON_ARRAY ? v : NULL;
}

err_t read_domain(const char *data, size_t len, struct roots *roots, struct diags *ds)
{
	struct bml_build_json *doc = NULL;
	struct bml_build_error e = {0};
	int rc = bml_build_json_decode(data, len, &s_doc, &doc, &e);
	if (rc == BML_BUILD_NOMEM)
		return errf("out of memory");
	if (rc != BML_BUILD_OK)
		return errf("%s", e.text ? e.text : "unknown JSON error");
	const struct bml_build_json_node *top = bml_build_json_root(doc);
	const struct bml_build_json_node *r = narr(top, "roots"), *f = narr(top, "functions"), *ed = narr(top, "edges"),
					 *dg = narr(top, "diagnostics");
	if (!r || !f || !ed || !dg)
		return errf("roots, functions, edges and diagnostics must all be arrays");
	roots->n = bml_build_json_count(r);
	roots->v = xmalloc((roots->n ? roots->n : 1) * sizeof *roots->v);
	for (size_t i = 0; i < roots->n; i++) {
		const struct bml_build_json_node *o = bml_build_json_index(r, i);
		roots->v[i] = (struct root){nstr(o, "name"), nstr(o, "kind"), npos(o, "decl"), npos(o, "def")};
	}
	size_t n = bml_build_json_count(dg);
	for (size_t i = 0; i < n; i++) {
		const struct bml_build_json_node *o = bml_build_json_index(dg, i);
		char *vs = nstr(o, "verdict");
		struct diag d = {0};
		if (!strcmp(vs, "verified"))
			d.verdict = V_VERIFIED;
		else if (!strcmp(vs, "rejected"))
			d.verdict = V_REJECTED;
		else if (!strcmp(vs, "conditional"))
			d.verdict = V_CONDITIONAL;
		else if (!strcmp(vs, "unknown"))
			d.verdict = V_UNKNOWN;
		else {
			char *q = go_quote(vs, strlen(vs));
			if (!q)
				not_ported("%%q of a non-ASCII verdict in the domain");
			return errf("diagnostics[%zu]: unknown verdict %s", i, q);
		}
		d.code = nstr(o, "code");
		char *name = nstr(o, "name");
		const char *want = code_name(d.code);
		if (!want || strcmp(want, name) != 0) {
			char *qc = go_quote(d.code, strlen(d.code)), *qn = go_quote(name, strlen(name));
			if (!qc || !qn)
				not_ported("%%q of a non-ASCII code or name in the domain");
			return errf("diagnostics[%zu]: code %s with name %s is not in the reason code table", i, qc, qn);
		}
		d.pos = npos(o, "pos");
		const struct bml_build_json_node *p = narr(o, "path");
		size_t pn = p ? bml_build_json_count(p) : 0;
		for (size_t k = 0; k < pn; k++) {
			size_t l;
			const char *s = bml_build_json_string_value(bml_build_json_index(p, k), &l);
			strv_push(&d.path, s ? xstrndup(s, l) : xstrdup(""));
		}
		d.msg = nstr(o, "message");
		diags_push(ds, d);
	}
	bml_build_json_free(doc);
	return NULL;
}
