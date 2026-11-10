/* fe.c — see fe.h. Each function names the Go it follows (internal/frontend/result.go, analyze.go). */
#include "fe.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* ---- Verdict, Code ---- */
const char *fe_verdict_string(fe_verdict v) {
	static char other[32];
	switch (v) {
	case FE_VERIFIED: return "verified";
	case FE_REJECTED: return "rejected";
	case FE_CONDITIONAL: return "conditional";
	case FE_UNKNOWN: return "unknown";
	}
	snprintf(other, sizeof other, "verdict(%d)", (int)v);
	return other;
}

static const char *const code_names[FE_NCODES] = {
	"Spinel", "UnsupportedConstruct", "UnsupportedCall", "CrossDomainUse", "UnknownEdge", "RefCheckShape", "NonConstant",
	"ReservedName", "ProgramShape", "OperatorRedefined", "TypingProbe", "ShadowedName", "ThreadInUserSide", "MapDeclShape",
	"SemanticGap", "AmbiguousType", "DynamicProgram", "InternalEmitter", "LogicalSideEffect", "SharedReadModifyWrite",
	"KeyOutOfRange", "CompileWarning", "WindowIndex", "PacketOffset", "RecordShape", "DroppedEvent", "StatusIgnored",
	"ThreadInBPFSide", "TracingKind", "GlobalShape", "LoopShape", "IndexRange", "UprobeTarget", "KernelTypeShape",
	"SubprogramShape", "Recursion",
};

const char *fe_code_text(fe_code c) {
	static char text[FE_NCODES][6];
	if ((unsigned)c >= FE_NCODES)
		abort();
	if (!text[c][0])
		snprintf(text[c], sizeof text[c], "SB%03d", (int)c);
	return text[c];
}

const char *fe_code_name(fe_code c) {
	if ((unsigned)c >= FE_NCODES)
		abort();
	return code_names[c];
}

/* ---- Pos, Diag ---- */
void fe_pos_string(sr_buf *b, fe_pos p) {
	if (p.file.n == 0) {
		sr_putc(b, '-');
		return;
	}
	sr_putstr(b, p.file);
	if (p.line == 0)
		return;
	sr_printf(b, ":%lld:%lld", (long long)p.line, (long long)p.col);
}

void fe_diag_string(sr_buf *b, const fe_diag *d) {
	fe_pos_string(b, d->pos);
	sr_printf(b, ": %s %s (%s): ", fe_verdict_string(d->verdict), fe_code_text(d->code), fe_code_name(d->code));
	sr_putstr(b, d->msg);
	if (d->n_path > 0) {
		sr_puts(b, " [path: ");
		for (size_t i = 0; i < d->n_path; i++) {
			if (i > 0)
				sr_puts(b, " -> ");
			sr_putstr(b, d->path[i]);
		}
		sr_putc(b, ']');
	}
}

void fe_diags_push(fe_diags *ds, fe_diag d) {
	if (ds->n == ds->cap) {
		size_t nc = ds->cap ? ds->cap * 2 : 16;
		ds->v = sr_grow(ds->v, ds->cap * sizeof *ds->v, nc * sizeof *ds->v);
		ds->cap = nc;
	}
	ds->v[ds->n++] = d;
}

int fe_diags_blocking(const fe_diags *ds) {
	for (size_t i = 0; i < ds->n; i++)
		if (ds->v[i].verdict == FE_REJECTED || ds->v[i].verdict == FE_UNKNOWN)
			return 1;
	return 0;
}

static int diag_less(const fe_diag *x, const fe_diag *y) {
	int c = sr_cmp(x->pos.file, y->pos.file);
	if (c != 0)
		return c < 0;
	if (x->pos.line != y->pos.line)
		return x->pos.line < y->pos.line;
	if (x->pos.col != y->pos.col)
		return x->pos.col < y->pos.col;
	/* Code is a string in Go; every code is "SB" and three digits, so the string order is the number order. */
	return x->code < y->code;
}

/* sort.SliceStable: a stable merge sort gives the same order as any stable sort under the same less. */
static void merge_sort(fe_diag *v, fe_diag *tmp, size_t n) {
	if (n < 2)
		return;
	size_t m = n / 2;
	merge_sort(v, tmp, m);
	merge_sort(v + m, tmp, n - m);
	size_t i = 0, j = m, k = 0;
	while (i < m && j < n)
		tmp[k++] = diag_less(&v[j], &v[i]) ? v[j++] : v[i++];
	while (i < m)
		tmp[k++] = v[i++];
	while (j < n)
		tmp[k++] = v[j++];
	memcpy(v, tmp, n * sizeof *v);
}

fe_diags fe_diags_sorted(const fe_diags *ds) {
	fe_diags out = {0};
	if (ds->n == 0)
		return out;
	out.v = sr_alloc(ds->n * sizeof *out.v);
	out.n = out.cap = ds->n;
	memcpy(out.v, ds->v, ds->n * sizeof *out.v);
	fe_diag *tmp = sr_alloc(ds->n * sizeof *tmp);
	merge_sort(out.v, tmp, out.n);
	return out;
}

void fe_error_string(sr_buf *b, const fe_diags *ds) {
	fe_diags s = fe_diags_sorted(ds);
	for (size_t i = 0; i < s.n; i++) {
		if (i > 0)
			sr_putc(b, '\n');
		fe_diag_string(b, &s.v[i]);
	}
}

/* ---- path/filepath on Unix ---- */
sr_str fe_path_clean(sr_str p) {
	if (p.n == 0)
		return sr_cstr(".");
	int rooted = p.p[0] == '/';
	char *out = sr_alloc(p.n + 1);
	size_t w = 0, r = 0, dotdot = 0;
	if (rooted) {
		out[w++] = '/';
		r = 1;
		dotdot = 1;
	}
	while (r < p.n) {
		if (p.p[r] == '/') {
			r++;
		} else if (p.p[r] == '.' && (r + 1 == p.n || p.p[r + 1] == '/')) {
			r++;
		} else if (p.p[r] == '.' && r + 1 < p.n && p.p[r + 1] == '.' && (r + 2 == p.n || p.p[r + 2] == '/')) {
			r += 2;
			if (w > dotdot) {
				w--;
				while (w > dotdot && out[w] != '/')
					w--;
			} else if (!rooted) {
				if (w > 0)
					out[w++] = '/';
				out[w++] = '.';
				out[w++] = '.';
				dotdot = w;
			}
		} else {
			if ((rooted && w != 1) || (!rooted && w != 0))
				out[w++] = '/';
			while (r < p.n && p.p[r] != '/')
				out[w++] = p.p[r++];
		}
	}
	if (w == 0)
		return sr_cstr(".");
	return (sr_str){out, w};
}

sr_str fe_path_base(sr_str p) {
	if (p.n == 0)
		return sr_cstr(".");
	while (p.n > 0 && p.p[p.n - 1] == '/')
		p.n--;
	size_t i = p.n;
	while (i > 0 && p.p[i - 1] != '/')
		i--;
	p = (sr_str){p.p + i, p.n - i};
	if (p.n == 0)
		return sr_cstr("/");
	return p;
}

sr_str fe_path_dir(sr_str p) {
	size_t i = p.n;
	while (i > 0 && p.p[i - 1] != '/')
		i--;
	return fe_path_clean((sr_str){p.p, i});
}

/* ---- the analyzer ---- */
sr_result fe_z_init(fe_z *z, sr_str source_path, sr_str text, sr_str lib_dir) {
	memset(z, 0, sizeof *z);
	if (lib_dir.n == 0 || lib_dir.p[0] != '/')
		return sr_not_ported("a relative library directory (filepath.Abs reads the working directory)");
	sr_buf lb = {0};
	sr_putstr(&lb, lib_dir);
	sr_puts(&lb, "/bpf.rb");
	z->lib = fe_path_clean(sr_bufstr(&lb));
	z->base = fe_path_base(source_path);
	z->src_dir = fe_path_dir(source_path);
	if (text.n == 0 || text.p[text.n - 1] != '\n') {
		sr_buf tb = {0};
		sr_putstr(&tb, text);
		sr_putc(&tb, '\n');
		text = sr_bufstr(&tb);
	}
	z->text = text;
	/* strings.Split(strings.TrimSuffix(text, "\n"), "\n") */
	sr_str t = {text.p, text.n - 1};
	size_t n = 1;
	for (size_t i = 0; i < t.n; i++)
		n += t.p[i] == '\n';
	z->lines = sr_alloc(n * sizeof *z->lines);
	size_t k = 0, s = 0;
	for (size_t i = 0; i <= t.n; i++) {
		if (i == t.n || t.p[i] == '\n') {
			z->lines[k++] = (sr_str){t.p + s, i - s};
			s = i + 1;
		}
	}
	z->n_lines = n;
	z->user_lines = (int64_t)n;
	z->np = sr_ok;
	return sr_ok;
}

void fe_add(fe_z *z, fe_verdict v, fe_code c, fe_pos p, sr_str msg) {
	fe_diags_push(&z->diags, (fe_diag){.verdict = v, .code = c, .pos = p, .msg = msg});
}

void fe_not_ported(fe_z *z, const char *fmt, ...) {
	if (z->np.kind != SR_OK)
		return;
	sr_buf b = {0};
	va_list ap;
	va_start(ap, fmt);
	char tmp[1024];
	vsnprintf(tmp, sizeof tmp, fmt, ap);
	va_end(ap);
	sr_puts(&b, tmp);
	z->np = (sr_result){SR_NOT_PORTED, sr_bufstr(&b)};
}

fe_pos fe_pos_of(const fe_z *z, const sr_ast *a, const sr_node *n) {
	sr_str f = sr_ast_file(a, n);
	if (!sr_eq(f, z->base))
		f = fe_path_base(f);
	return (fe_pos){f, n->line, n->col + 1};
}

sr_str fe_slice(const fe_z *z, const sr_node *n) {
	sr_str none = {"", 0};
	if (n->line != n->end_line || n->line < 1 || (uint64_t)n->line > z->n_lines)
		return none;
	sr_str l = z->lines[n->line - 1];
	if (n->col < 0 || (uint64_t)n->end_col > l.n || n->col > n->end_col)
		return none;
	return (sr_str){l.p + n->col, (size_t)(n->end_col - n->col)};
}

int fe_literal(fe_z *z, const sr_ast *a, const sr_node *n, bigint *out) {
	sr_str src = fe_slice(z, n);
	*out = (bigint){0};
	if (!bigint_parse_ruby_int(out, src.p, src.n)) {
		bigint_free(out);
		sr_buf b = {0};
		sr_puts(&b, "cannot read the integer literal ");
		if (!fe_fmt_q(z, &b, src))
			return 0;
		fe_add(z, FE_REJECTED, FE_SB001, fe_pos_of(z, a, n), sr_bufstr(&b));
		return 0;
	}
	int ok;
	sr_str iv = fe_node_inttext(n, "value", &ok);
	bigint astv = {0};
	int ok2 = bigint_parse_dec(&astv, iv.p, iv.n);
	int same = ok2 && bigint_cmp(&astv, out) == 0;
	bigint_free(&astv);
	if (!same) {
		bigint_free(out);
		sr_buf b = {0};
		sr_puts(&b, "integer literal ");
		fe_fmt_s(&b, src);
		sr_puts(&b, " is not an Integer Spinel can hold (Spinel reads it as ");
		if (!fe_fmt_q(z, &b, iv))
			return 0;
		sr_puts(&b, ") \xe2\x80\x94 literals must be within [-2^63+1, 2^63-1]");
		fe_add(z, FE_REJECTED, FE_SB014, fe_pos_of(z, a, n), sr_bufstr(&b));
		return 0;
	}
	return 1;
}

/* ---- node fields: a Go map keeps the last assignment, so the last entry with the key wins ---- */
sr_str fe_node_str(const sr_node *n, const char *k, int *ok) {
	for (size_t i = n->n_str; i-- > 0;)
		if (sr_eqc(n->str[i].k, k)) {
			*ok = 1;
			return n->str[i].v;
		}
	*ok = 0;
	return (sr_str){"", 0};
}

int64_t fe_node_int(const sr_node *n, const char *k, int *ok) {
	for (size_t i = n->n_int; i-- > 0;)
		if (sr_eqc(n->ints[i].k, k)) {
			*ok = 1;
			return n->ints[i].v;
		}
	*ok = 0;
	return 0;
}

sr_str fe_node_inttext(const sr_node *n, const char *k, int *ok) {
	for (size_t i = n->n_inttext; i-- > 0;)
		if (sr_eqc(n->inttext[i].k, k)) {
			*ok = 1;
			return n->inttext[i].v;
		}
	*ok = 0;
	return (sr_str){"", 0};
}

int64_t fe_node_ref(const sr_node *n, const char *k, int *ok) {
	for (size_t i = n->n_ref; i-- > 0;)
		if (sr_eqc(n->ref[i].k, k)) {
			*ok = 1;
			return n->ref[i].v;
		}
	*ok = 0;
	return 0;
}

const int64_t *fe_node_arr(const sr_node *n, const char *k, size_t *count, int *ok) {
	for (size_t i = n->n_arr; i-- > 0;)
		if (sr_eqc(n->arr[i].k, k)) {
			*ok = 1;
			*count = n->arr[i].n;
			return n->arr[i].ids;
		}
	*ok = 0;
	*count = 0;
	return NULL;
}

/* ---- fmt verbs ---- */
void fe_fmt_s(sr_buf *b, sr_str s) { sr_putstr(b, s); }

void fe_fmt_d(sr_buf *b, int64_t v) { sr_printf(b, "%lld", (long long)v); }

int fe_fmt_q(fe_z *z, sr_buf *b, sr_str s) {
	if (sr_quote_go_ascii(b, s))
		return 1;
	fe_not_ported(z, "%%q of non-ASCII text");
	return 0;
}

void fe_fmt_big(sr_buf *b, const bigint *x) {
	char *s = bigint_string(x);
	sr_puts(b, s);
	free(s);
}

/* filepath.Join on Unix: the non-empty elements joined by '/', then cleaned; "" when every element is empty. */
sr_str fe_path_join(const sr_str *elems, size_t n) {
	sr_buf b = {0};
	int any = 0;
	for (size_t i = 0; i < n; i++) {
		if (elems[i].n == 0)
			continue;
		if (any)
			sr_putc(&b, '/');
		sr_putstr(&b, elems[i]);
		any = 1;
	}
	if (!any)
		return (sr_str){"", 0};
	return fe_path_clean(sr_bufstr(&b));
}
