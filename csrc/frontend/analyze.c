/* analyze.c — analyze() (internal/frontend/analyze.go) after the C steps 1-2 (fe_top_run): the typing run, then steps 4-7.
 * The Go code stays the canon; each part names the Go it follows. */
#include "core.h"
#include "dump.h"

#include <string.h>

/* the same text as top.c's splice_msg (analyze.go spliceMsg) */
static const char splice_msg[] =
    "Spinel spliced its builtins (enumerable.rb / enumerator.rb — the code names a method that Enumerable defines, such as count or "
    "map) and shifted this file's line numbers, and the shift could not be measured from the named nodes "
    "(docs/upstream_suspects.md S11) — rename the method or avoid the call";

/* a fresh &Result{Source: base}: every slice and the map nil */
static void result_init(fe_result *res, sr_str base)
{
	memset(res, 0, sizeof *res);
	res->source = base;
	res->programs_nil = res->maps_nil = res->rings_nil = res->globals_nil = res->kernel_types_nil = res->funcs_nil = res->struct_ops_nil = 1;
	res->membership_nil = res->edges_nil = 1;
}

/* a Go slice as an fe_diags: nil stays nil, an empty non-nil slice keeps a non-NULL pointer */
static fe_diags diags_of(fe_diag *v, size_t n, int is_nil)
{
	static fe_diag empty;
	if (is_nil)
		return (fe_diags){NULL, 0, 0};
	return (fe_diags){v ? v : &empty, n, n};
}

const char *fe_stub_hit;

static sr_result np_or(fe_z *z, sr_result r)
{
	if (z->np.kind == SR_OK && t_nil_panic)
		fe_not_ported(z, "a Go nil-node panic path in the bodies (a.ref / a.arr / an index on nil)");
	if (z->np.kind == SR_OK && fe_iv_overflow)
		fe_not_ported(z, "an interval bound beyond 128 bits (Go's *big.Int; the C keeps 128)");
	if (z->np.kind == SR_OK && fe_stub_hit)
		fe_not_ported(z, "%s is not ported yet (a group's stub)", fe_stub_hit);
	return z->np.kind != SR_OK ? z->np : r;
}

sr_result fe_analyze(fe_z *z, const sr_spinel *sp, const char *work, sr_str inject_expr, fe_result *res)
{
	result_init(res, z->base);
	fe_iv_overflow = 0;
	fe_stub_hit = NULL;
	fe_top t;
	sr_result r = fe_top_run(z, sp, work, inject_expr, &t);
	switch (t.outcome) {
	case FE_TOP_ERROR:
		return t.err.kind != SR_OK ? t.err : np_or(z, r);
	case FE_TOP_RETURNED:
		res->diags = diags_of(t.res_diags, t.n_res_diags, t.res_diags_nil);
		return np_or(z, sr_ok);
	}

	/* 3. the typing run (the text is the one fe_top_run built) */
	size_t nw = strlen(work);
	char *dir = sr_alloc(nw + sizeof "/typing");
	memcpy(dir, work, nw);
	memcpy(dir + nw, "/typing", sizeof "/typing");
	char *base = sr_alloc(z->base.n + 1);
	memcpy(base, z->base.p, z->base.n);
	fe_analysis an;
	memset(&an, 0, sizeof an);
	an.z = z;
	an.top = &t;
	r = sr_analyze(sp, dir, base, t.inject, &an.typing);
	if (r.kind != SR_OK)
		return r;
	int64_t k;
	if (!fe_align_splice(&an.typing, z->base, t.inject, &k)) {
		sr_buf b = {0};
		sr_puts(&b, splice_msg);
		fe_add(z, FE_REJECTED, FE_SB000, (fe_pos){z->base, 0, 0}, sr_bufstr(&b));
		res->diags = z->diags;
		return np_or(z, sr_ok);
	}
	if (an.typing.n_diags > 0) {
		fe_flush_thread_refs(z, &t, NULL, NULL);
		/* res.Diags = append(z.diags, ds...) */
		fe_diags ds = z->diags;
		fe_diags out = {0};
		for (size_t i = 0; i < ds.n; i++)
			fe_diags_push(&out, ds.v[i]);
		for (size_t i = 0; i < an.typing.n_diags; i++) {
			const sr_diag *g = &an.typing.diags[i];
			fe_diags_push(&out, (fe_diag){FE_REJECTED, FE_SB000, {g->file, g->line, g->col}, NULL, 0, g->msg});
		}
		res->diags = out;
		return np_or(z, sr_ok);
	}

	/* 4-7: checkLibDefs, the bodies, compareInjection, membership, the used declarations (steps.c) */
	fe_steps_4_to_7(&an, res);
	return np_or(z, sr_ok);
}
