/* top_splice.c — alignSplice (internal/frontend/splice.go): the line shift of Spinel's builtins splice (upstream suspect S11). */
#include "top_int.h"

#include <string.h>

#define SPLICE_MAX_SHIFT 4 /* spliceMaxShift */

static int spliced(const sr_ast *a)
{
	int64_t *keys = sr_imap_sorted_keys(&a->files);
	for (size_t i = 0; i < a->files.n; i++) {
		const sr_str *p = sr_imap_get(&a->files, keys[i]);
		if (p && memmem(p->p, p->n, "/builtins/", 10))
			return 1;
	}
	return 0;
}

typedef struct {
	const sr_node *n;
	sr_str want;
} anchor;

static int has_ref(const sr_node *n, const char *k)
{
	int ok;
	fe_node_ref(n, k, &ok);
	return ok;
}

/* anchors: the order is irrelevant (measureShift needs every anchor to fit). */
static size_t anchors(const sr_ast *a, int64_t fid, anchor **out)
{
	anchor *v = NULL;
	size_t n = 0;
	int64_t *keys = sr_imap_sorted_keys(&a->nodes);
	for (size_t i = 0; i < a->nodes.n; i++) {
		const sr_node *x = sr_imap_get(&a->nodes, keys[i]);
		if (!x || x->file_id != fid || x->line <= 0)
			continue;
		sr_str w = {"", 0};
		if (sr_eqc(x->type, "ConstantWriteNode") || sr_eqc(x->type, "ConstantReadNode") ||
		    sr_eqc(x->type, "LocalVariableWriteNode")) {
			w = t_str(x, "name");
		} else if (sr_eqc(x->type, "DefNode")) {
			w = t_s("def");
		} else if (sr_eqc(x->type, "CallNode")) {
			sr_str name = t_str(x, "name");
			int op = 0;
			for (size_t j = 0; j < name.n; j++)
				op |= strchr("=[]+-*/<>!%&|^~", name.p[j]) != NULL && name.p[j] != '\0';
			if (!has_ref(x, "receiver") && name.n > 0 && !op)
				w = name;
		}
		if (w.n > 0)
			T_PUSH(v, n, ((anchor){x, w}));
	}
	*out = v;
	return n;
}

static int measure_shift(const sr_ast *a, int64_t fid, const sr_str *lines, size_t n_lines, int64_t *k_out)
{
	anchor *as;
	size_t na = anchors(a, fid, &as);
	if (na == 0)
		return 0;
	int found = 0;
	int64_t k = -1;
	for (int64_t c = 0; c <= SPLICE_MAX_SHIFT; c++) {
		int all = 1;
		for (size_t i = 0; i < na && all; i++) {
			int64_t l = as[i].n->line - c, col = as[i].n->col;
			if (l < 1 || l > (int64_t)n_lines || col < 0 || col > (int64_t)lines[l - 1].n) {
				all = 0;
				break;
			}
			sr_str rest = {lines[l - 1].p + col, lines[l - 1].n - (size_t)col};
			/* an empty anchor matches (memcmp of 0 bytes is 0); the length guard keeps NULL out of memcmp */
			if (rest.n < as[i].want.n || (as[i].want.n > 0 && memcmp(rest.p, as[i].want.p, as[i].want.n) != 0))
				all = 0;
		}
		if (all) {
			found++;
			k = c;
		}
	}
	*k_out = k;
	return found == 1;
}

static void shift_user(sr_analysis *an, int64_t fid, int64_t k)
{
	if (k == 0)
		return;
	sr_ast *a = an->ast;
	int64_t *keys = sr_imap_sorted_keys(&a->nodes);
	for (size_t i = 0; i < a->nodes.n; i++) {
		sr_node *n = sr_imap_get(&a->nodes, keys[i]);
		if (n && n->file_id == fid) {
			n->line -= k;
			if (n->end_line > 0)
				n->end_line -= k;
		}
	}
	const sr_str *pp = sr_imap_get(&a->files, fid);
	sr_str path = pp ? *pp : (sr_str){"", 0}; /* Go: a.Files[fid] ("" when missing; userFileID found it, so present) */
	sr_types *t = an->types;
	if (!t)
		return; /* Go would panic on a nil Types (an.Types.Types); Spinel's analysis always has both or neither */
	for (size_t i = 0; i < t->n_types; i++)
		if (sr_eq(t->types[i].file, path)) {
			t->types[i].line -= k;
			t->types[i].end_line -= k;
		}
	for (size_t i = 0; i < t->n_codegen; i++)
		if (sr_eq(t->codegen[i].file, path)) {
			t->codegen[i].line -= k;
			t->codegen[i].end_line -= k;
		}
	for (size_t i = 0; i < t->n_diags; i++)
		if (sr_eq(t->diags[i].file, path))
			t->diags[i].line -= k;
	sr_reindex_types(t);
}

int fe_align_splice(sr_analysis *an, sr_str base, sr_str text, int64_t *k)
{
	*k = 0;
	if (!an || !an->ast || !spliced(an->ast))
		return 1;
	int64_t fid = t_user_file_id(an->ast, base);
	if (fid < 0)
		return 0;
	/* strings.Split(text, "\n") */
	sr_str *lines = NULL;
	size_t nl = 0, start = 0;
	for (size_t i = 0; i <= text.n; i++)
		if (i == text.n || text.p[i] == '\n') {
			T_PUSH(lines, nl, ((sr_str){text.p + start, i - start}));
			start = i + 1;
		}
	int64_t kk;
	if (!measure_shift(an->ast, fid, lines, nl, &kk))
		return 0;
	shift_user(an, fid, kk);
	*k = kk;
	return 1;
}
