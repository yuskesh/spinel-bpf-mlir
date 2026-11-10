/* spinelread: the canonical dump, the same format as internal/frontend/e176_dump_test.go. */
#include "sr.h"

#include <stdlib.h>

static void q(sr_buf *b, sr_str s) { sr_quote_ascii(b, s); }

void sr_dump_result(sr_buf *b, sr_result r)
{
	sr_puts(b, r.kind == SR_ERR ? "error " : "not-ported ");
	q(b, r.text);
	sr_putc(b, '\n');
}

/* sort a field array by key (Go's sort.Strings order); the arrays hold distinct keys */
static int cmp_kv_str(const void *x, const void *y) { return sr_cmp(((const sr_kv_str *)x)->k, ((const sr_kv_str *)y)->k); }
static int cmp_kv_int(const void *x, const void *y) { return sr_cmp(((const sr_kv_int *)x)->k, ((const sr_kv_int *)y)->k); }
static int cmp_kv_arr(const void *x, const void *y) { return sr_cmp(((const sr_kv_arr *)x)->k, ((const sr_kv_arr *)y)->k); }

#define SORTED(arr, n, cmp)                                                                                                \
	({                                                                                                                 \
		__typeof__(arr) c_ = sr_alloc(((n) ? (n) : 1) * sizeof *(arr));                                            \
		for (size_t i_ = 0; i_ < (n); i_++)                                                                        \
			c_[i_] = (arr)[i_];                                                                                \
		qsort(c_, (n), sizeof *c_, cmp);                                                                           \
		c_;                                                                                                        \
	})

void sr_dump_ast(sr_buf *b, const sr_ast *a)
{
	sr_printf(b, "ast root %lld source ", (long long)a->root);
	q(b, a->source_file);
	sr_putc(b, '\n');
	int64_t *fids = sr_imap_sorted_keys(&a->files);
	for (size_t i = 0; i < a->files.n; i++) {
		sr_printf(b, "file %lld ", (long long)fids[i]);
		q(b, *(sr_str *)sr_imap_get(&a->files, fids[i]));
		sr_putc(b, '\n');
	}
	int64_t *ids = sr_imap_sorted_keys(&a->nodes);
	for (size_t i = 0; i < a->nodes.n; i++) {
		const sr_node *n = sr_imap_get(&a->nodes, ids[i]);
		sr_printf(b, "node %lld ", (long long)n->id);
		q(b, n->type);
		sr_printf(b, " file %lld at %lld %lld %lld %lld\n", (long long)n->file_id, (long long)n->line, (long long)n->col,
			  (long long)n->end_line, (long long)n->end_col);
		sr_kv_arr *arr = SORTED(n->arr, n->n_arr, cmp_kv_arr);
		for (size_t k = 0; k < n->n_arr; k++) {
			sr_puts(b, " arr ");
			q(b, arr[k].k);
			sr_printf(b, " %zu [", arr[k].n);
			for (size_t m = 0; m < arr[k].n; m++)
				sr_printf(b, m ? ",%lld" : "%lld", (long long)arr[k].ids[m]);
			sr_puts(b, "]\n");
		}
		sr_kv_int *ints = SORTED(n->ints, n->n_int, cmp_kv_int);
		for (size_t k = 0; k < n->n_int; k++) {
			sr_puts(b, " int ");
			q(b, ints[k].k);
			sr_printf(b, " %lld\n", (long long)ints[k].v);
		}
		sr_kv_str *it = SORTED(n->inttext, n->n_inttext, cmp_kv_str);
		for (size_t k = 0; k < n->n_inttext; k++) {
			sr_puts(b, " inttext ");
			q(b, it[k].k);
			sr_putc(b, ' ');
			q(b, it[k].v);
			sr_putc(b, '\n');
		}
		sr_kv_int *ref = SORTED(n->ref, n->n_ref, cmp_kv_int);
		for (size_t k = 0; k < n->n_ref; k++) {
			sr_puts(b, " ref ");
			q(b, ref[k].k);
			sr_printf(b, " %lld\n", (long long)ref[k].v);
		}
		sr_kv_str *str = SORTED(n->str, n->n_str, cmp_kv_str);
		for (size_t k = 0; k < n->n_str; k++) {
			sr_puts(b, " str ");
			q(b, str[k].k);
			sr_putc(b, ' ');
			q(b, str[k].v);
			sr_putc(b, '\n');
		}
	}
	int64_t *cs = sr_imap_sorted_keys(&a->parent);
	for (size_t i = 0; i < a->parent.n; i++)
		sr_printf(b, "parent %lld %lld\n", (long long)cs[i], (long long)*(int64_t *)sr_imap_get(&a->parent, cs[i]));
}

static void slice_len(sr_buf *b, const char *tag, int is_nil, size_t n)
{
	if (is_nil)
		sr_printf(b, "%s nil\n", tag);
	else
		sr_printf(b, "%s %zu\n", tag, n);
}

static void qs(sr_buf *b, sr_str s)
{
	sr_putc(b, ' ');
	q(b, s);
}

static void dump_diag_rec(sr_buf *b, const char *tag, size_t i, const sr_diag_rec *d)
{
	sr_printf(b, "%s %zu", tag, i);
	qs(b, d->file);
	sr_printf(b, " %lld %lld", (long long)d->line, (long long)d->col);
	qs(b, d->severity);
	qs(b, d->method);
	qs(b, d->slot);
	qs(b, d->param);
	qs(b, d->message);
	sr_putc(b, '\n');
}

static void join_ref(sr_buf *b, long idx, size_t count)
{
	if (idx >= 0)
		sr_printf(b, "%ld", idx);
	else if (count == 0)
		sr_puts(b, "none");
	else
		sr_printf(b, "many %zu", count);
}

void sr_dump_types(sr_buf *b, const sr_ast *a, const sr_types *t)
{
	slice_len(b, "types", t->types_nil, t->n_types);
	for (size_t i = 0; i < t->n_types; i++) {
		const sr_type_rec *r = &t->types[i];
		sr_printf(b, "type %zu", i);
		qs(b, r->file);
		sr_printf(b, " %lld %lld %lld %lld", (long long)r->line, (long long)r->col, (long long)r->end_line,
			  (long long)r->end_col);
		qs(b, r->kind);
		qs(b, r->name);
		qs(b, r->type);
		qs(b, r->rbs);
		qs(b, r->owner);
		qs(b, r->signature);
		sr_printf(b, " %s %s\n", r->singleton ? "true" : "false", r->widened ? "true" : "false");
	}
	slice_len(b, "diagnostics", t->diags_nil, t->n_diags);
	for (size_t i = 0; i < t->n_diags; i++)
		dump_diag_rec(b, "diagnostic", i, &t->diags[i]);
	slice_len(b, "codegen", t->codegen_nil, t->n_codegen);
	for (size_t i = 0; i < t->n_codegen; i++) {
		const sr_codegen_rec *r = &t->codegen[i];
		sr_printf(b, "cg %zu", i);
		qs(b, r->file);
		sr_printf(b, " %lld %lld %lld %lld", (long long)r->line, (long long)r->col, (long long)r->end_line,
			  (long long)r->end_col);
		qs(b, r->kind);
		qs(b, r->name);
		qs(b, r->dispatch);
		qs(b, r->callee);
		if (r->candidates_nil)
			sr_puts(b, " candidates nil [");
		else
			sr_printf(b, " candidates %zu [", r->n_candidates);
		for (size_t k = 0; k < r->n_candidates; k++) {
			if (k)
				sr_putc(b, ' ');
			q(b, r->candidates[k]);
		}
		sr_printf(b, "] inlined %s\n", r->inlined < 0 ? "nil" : r->inlined ? "true" : "false");
	}
	if (a) {
		int64_t *ids = sr_imap_sorted_keys(&a->nodes);
		for (size_t i = 0; i < a->nodes.n; i++) {
			const sr_node *n = sr_imap_get(&a->nodes, ids[i]);
			size_t tc, cc;
			long ti = sr_type_of(t, a, n, &tc), ci = sr_codegen_of(t, a, n, &cc);
			sr_printf(b, "join %lld type ", (long long)n->id);
			join_ref(b, ti, tc);
			sr_puts(b, " codegen ");
			join_ref(b, ci, cc);
			sr_putc(b, '\n');
		}
	}
	size_t k = 0;
	for (size_t i = 0; i < t->n_diags; i++)
		if (sr_eqc(t->diags[i].severity, "error"))
			dump_diag_rec(b, "spinel-error", k++, &t->diags[i]);
}

void sr_dump_analysis(sr_buf *b, const sr_analysis *a)
{
	for (size_t i = 0; i < a->n_diags; i++) {
		const sr_diag *d = &a->diags[i];
		sr_puts(b, "diag rejected");
		qs(b, d->code);
		qs(b, d->file);
		sr_printf(b, " %lld %lld 0", (long long)d->line, (long long)d->col);
		qs(b, d->msg);
		sr_putc(b, '\n');
	}
	if (!a->ast) {
		sr_puts(b, "analysis nil\n");
		return;
	}
	sr_puts(b, "analysis\n");
	sr_dump_ast(b, a->ast);
	sr_dump_types(b, a->ast, a->types);
}
