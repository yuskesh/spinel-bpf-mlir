/* sub.c — internal/frontend/subprogram.go: the eBPF-side subprograms (scanSubprograms, userCall, callGraph, the flow records,
 * subCall, function, resolveSubprograms) and their small helpers.
 *
 * Go map orders that reach the output are fixed here: callGraph's SB034 loop runs in declaration order
 * (Go: `range reach`), and resolveSubprograms reports a call site's argument sinks in sorted key order (Go: `range g.W[j]`). */
#include "core.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S(x) sr_cstr(x)
static int one_ = 1;
#define TRUE_ ((void *)&one_)

static int has_prefix(sr_str s, const char *p)
{
	size_t b = strlen(p);
	return s.n >= b && memcmp(s.p, p, b) == 0;
}
static int has_suffix(sr_str s, const char *p)
{
	size_t b = strlen(p);
	return s.n >= b && memcmp(s.p + s.n - b, p, b) == 0;
}
static sr_str sfmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static sr_str sfmt(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char tmp[64];
	int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
	va_end(ap);
	char *p = sr_alloc((size_t)n + 1);
	va_start(ap, fmt);
	vsnprintf(p, (size_t)n + 1, fmt, ap);
	va_end(ap);
	return (sr_str){p, (size_t)n};
}

/* an int set (Go map[int]bool) on sr_imap */
static void iset_add(sr_imap *m, int64_t k)
{
	int created;
	*sr_imap_slot(m, k, &created) = TRUE_;
}
static void sset_add(fe_name_table *t, sr_str k) { fe_name_set(t, k, TRUE_); }
static int sset_has(const fe_name_table *t, sr_str k) { return fe_name_get(t, k) != NULL; }

static fe_flow_src empty_src(void)
{
	fe_flow_src s;
	memset(&s, 0, sizeof s);
	return s;
}

/* ---- scanSubprograms (subprogram.go) ---- */
typedef struct {
	sr_str name;
	const sr_node *def;
} def_ent;

static int def_id_cmp(const void *x, const void *y)
{
	const def_ent *a = x, *b = y;
	return a->def->id < b->def->id ? -1 : a->def->id > b->def->id;
}

void fe_scan_subprograms(fe_analysis *z, const sr_ast *a, const fe_name_table *defs)
{
	memset(&z->funcs, 0, sizeof z->funcs);
	memset(&z->flows_of, 0, sizeof z->flows_of);
	memset(&z->site_by_node, 0, sizeof z->site_by_node);
	fe_name_table is_root = {0};
	for (size_t i = 0; i < z->top->n_roots; i++)
		sset_add(&is_root, z->top->roots[i].name);
	def_ent *names = sr_alloc((defs->n + 1) * sizeof *names);
	size_t nn = 0;
	for (size_t i = 0; i < defs->n; i++)
		if (!defs->e[i].removed && !sset_has(&is_root, defs->e[i].key))
			names[nn++] = (def_ent){defs->e[i].key, defs->e[i].val};
	qsort(names, nn, sizeof *names, def_id_cmp);
	for (size_t i = 0; i < nn; i++) {
		sr_str name = names[i].name;
		const sr_node *d = names[i].def;
		fe_func_info *fi = sr_alloc(sizeof *fi);
		memset(fi, 0, sizeof *fi);
		fi->name = name;
		fi->def = d;
		fi->decl = (int64_t)i;
		fi->borrow_idx = fi->win_idx = fi->ctx_idx = -1;
		const sr_node *pn = t_ref(a, d, "parameters");
		if (pn) {
			static const char *const k1[] = {"optionals", "keywords"};
			for (size_t k = 0; k < 2; k++)
				if (t_arr(a, pn, k1[k]).n > 0) {
					sr_buf b = {0};
					sr_puts(&b, "the eBPF-side function `");
					sr_putstr(&b, name);
					sr_puts(&b, "` takes only required positional Integer arguments (no optional or keyword arguments)");
					fi->shape_err = sr_bufstr(&b);
				}
			static const char *const k2[] = {"rest", "keyword_rest", "block"};
			for (size_t k = 0; k < 3; k++)
				if (t_ref(a, pn, k2[k])) {
					sr_buf b = {0};
					sr_puts(&b, "the eBPF-side function `");
					sr_putstr(&b, name);
					sr_puts(&b, "` takes only required positional Integer arguments (no rest, keyword-rest or block argument)");
					fi->shape_err = sr_bufstr(&b);
				}
			t_nodes reqs = t_arr(a, pn, "requireds");
			for (size_t k = 0; k < reqs.n; k++)
				T_PUSH(fi->params, fi->n_params, t_str(reqs.v[k], "name"));
		}
		if (fi->n_params > 5 && fi->shape_err.n == 0) {
			sr_buf b = {0};
			sr_puts(&b, "the eBPF-side function `");
			sr_putstr(&b, name);
			sr_printf(&b, "` takes %zu arguments — a BPF subprogram takes at most 5", fi->n_params);
			fi->shape_err = sr_bufstr(&b);
		}
		fe_name_set(&z->funcs, name, fi);
	}
}

/* userCall (subprogram.go) */
fe_func_info *fe_user_call(fe_analysis *z, const sr_ast *a, const sr_node *n)
{
	if (!n || !t_is(n, "CallNode") || t_ref(a, n, "receiver"))
		return NULL;
	return fe_name_get(&z->funcs, t_str(n, "name"));
}

/* ---- callGraph (subprogram.go) ---- */
typedef struct {
	sr_str *v;
	size_t n;
} names;

typedef struct {
	fe_analysis *z;
	const sr_ast *a;
	const fe_name_table *defs;
	fe_name_table callees; /* name -> names* */
	fe_name_table state;   /* name -> (intptr_t) 1 or 2 */
	sr_str *stack;
	size_t n_stack;
	fe_name_table reported;
} cg_state;

typedef struct {
	fe_analysis *z;
	const sr_ast *a;
	fe_name_table seen;
	names *out;
} edge_walk;

static int edge_walk_fn(void *u, const sr_node *x)
{
	edge_walk *w = u;
	fe_func_info *fi = fe_user_call(w->z, w->a, x);
	if (fi && !sset_has(&w->seen, fi->name)) {
		sset_add(&w->seen, fi->name);
		T_PUSH(w->out->v, w->out->n, fi->name);
	}
	return 1;
}

static names *edge_from(cg_state *g, sr_str name)
{
	if (fe_name_has(&g->callees, name))
		return fe_name_get(&g->callees, name);
	names *out = sr_alloc(sizeof *out);
	memset(out, 0, sizeof *out);
	const sr_node *d = fe_name_get(g->defs, name);
	if (d) {
		edge_walk w = {g->z, g->a, {0}, out};
		t_walk(g->a, d, edge_walk_fn, &w);
	}
	fe_name_set(&g->callees, name, out);
	return out;
}

static int state_of(cg_state *g, sr_str n) { return (int)(intptr_t)fe_name_get(&g->state, n); }
static void set_state(cg_state *g, sr_str n, int s) { fe_name_set(&g->state, n, (void *)(intptr_t)s); }

static sr_str *copy_strs(const sr_str *v, size_t n)
{
	sr_str *o = sr_alloc((n + 1) * sizeof *o);
	if (n)
		memcpy(o, v, n * sizeof *o);
	return o;
}

static void dfs(cg_state *g, sr_str n)
{
	set_state(g, n, 1);
	T_PUSH(g->stack, g->n_stack, n);
	names *es = edge_from(g, n);
	for (size_t k = 0; k < es->n; k++) {
		sr_str m = es->v[k];
		switch (state_of(g, m)) {
		case 0: {
			fe_func_info *fm = fe_name_get(&g->z->funcs, m);
			fm->n_path = g->n_stack + 1;
			fm->path = copy_strs(g->stack, g->n_stack);
			fm->path[g->n_stack] = m;
			dfs(g, m);
			break;
		}
		case 1: {
			size_t i = 0;
			for (size_t q = 0; q < g->n_stack; q++)
				if (sr_eq(g->stack[q], m))
					i = q;
			size_t nc = g->n_stack - i + 1;
			sr_str *cyc = copy_strs(g->stack + i, g->n_stack - i);
			cyc[nc - 1] = m;
			if (!sset_has(&g->reported, m)) {
				sset_add(&g->reported, m);
				const sr_node *d = fe_name_get(g->defs, m);
				sr_buf b = {0};
				sr_puts(&b, "recursion is not accepted on the eBPF side: ");
				sr_putstr(&b, t_join(cyc, nc, " → "));
				sr_puts(&b, " (BPF subprograms are non-recursive)");
				fe_diags_push(&g->z->z->diags, (fe_diag){FE_REJECTED, FE_SB035, fe_pos_of(g->z->z, g->a, d), copy_strs(g->stack, g->n_stack),
									 g->n_stack, sr_bufstr(&b)});
			}
			for (size_t q = 0; q < nc; q++) {
				fe_func_info *fi = fe_name_get(&g->z->funcs, cyc[q]);
				if (fi)
					fi->bad = 1;
			}
			break;
		}
		}
	}
	g->n_stack--;
	set_state(g, n, 2);
}

/* integerSig (subprogram.go) */
static int is_special_param(sr_str p)
{
	return fe_streq(p, "MapRef") || fe_streq(p, "RecordRef") || fe_streq(p, "Window") || fe_streq(p, "XdpMd") || fe_streq(p, "SkBuff");
}

static sr_str *split_comma(sr_str s, size_t *n)
{
	sr_str *out = NULL;
	*n = 0;
	size_t start = 0;
	for (size_t i = 0; i + 1 < s.n + 1; i++) {
		if (i + 1 < s.n && s.p[i] == ',' && s.p[i + 1] == ' ') {
			T_PUSH(out, *n, ((sr_str){s.p + start, i - start}));
			start = i + 2;
			i++;
		}
	}
	T_PUSH(out, *n, ((sr_str){s.p + start, s.n - start}));
	return out;
}

static long index_of(sr_str s, const char *x)
{
	size_t b = strlen(x);
	for (size_t i = 0; i + b <= s.n; i++)
		if (memcmp(s.p + i, x, b) == 0)
			return (long)i;
	return -1;
}

int fe_integer_sig(sr_str sig)
{
	if (sig.n == 0)
		return 1;
	long i = index_of(sig, "("), j = index_of(sig, ") -> ");
	if (i != 0 || j < 0)
		return 0;
	sr_str inner = {sig.p + 1, (size_t)j - 1};
	if (inner.n) {
		size_t np;
		sr_str *ps = split_comma(inner, &np);
		int refs = 0;
		for (size_t k = 0; k < np; k++) {
			if (is_special_param(ps[k])) {
				refs++;
				continue;
			}
			if (!fe_streq(ps[k], "Integer"))
				return 0;
		}
		if (refs > 1)
			return 0;
	}
	return fe_streq((sr_str){sig.p + j + 5, sig.n - (size_t)j - 5}, "Integer");
}

/* sigHint (subprogram.go) */
static sr_str sig_hint(sr_str sig)
{
	long j = index_of(sig, ") -> ");
	if (!has_prefix(sig, "(") || j < 0)
		return (sr_str){0};
	static const char *const tracing_ctx[] = {"FentryCtx",	   "FexitCtx", "KprobeCtx",	  "UprobeCtx",	    "TpBtfCtx",	  "KretprobeCtx",
						  "UretprobeCtx", "RawTpCtx", "SocketFilterCtx", "TracepointCtx", "KsyscallCtx", NULL};
	int special = 0, untyped = 0;
	sr_str tracing = {0};
	size_t np;
	sr_str *ps = split_comma((sr_str){sig.p + 1, (size_t)j - 1}, &np);
	for (size_t k = 0; k < np; k++) {
		if (is_special_param(ps[k]))
			special++;
		else if (t_in(ps[k], tracing_ctx))
			tracing = ps[k];
		else if (fe_streq(ps[k], "untyped"))
			untyped = 1;
	}
	if (tracing.n) {
		sr_buf b = {0};
		sr_puts(&b, "; the ");
		sr_putstr(&b, tracing);
		sr_puts(&b, " context is not passed to an eBPF-side function — its reads depend on the attach point: read the values in the program and pass Integers");
		return sr_bufstr(&b);
	}
	if (special > 1)
		return S("; a function takes at most one argument that is not an Integer (a borrowed map value, a checked packet window or a packet context)");
	if (untyped)
		return S("; an argument has different types at different calls (for example the xdp and the sched_cls context, or a window and an Integer) — pass one type in one place");
	return (sr_str){0};
}

static int decl_cmp(const void *x, const void *y)
{
	const fe_func_info *a = *(fe_func_info *const *)x, *b = *(fe_func_info *const *)y;
	return a->decl < b->decl ? -1 : a->decl > b->decl;
}

fe_func_info **fe_call_graph(fe_analysis *z, const sr_ast *a, const fe_name_table *defs, size_t *n_order)
{
	cg_state g;
	memset(&g, 0, sizeof g);
	g.z = z;
	g.a = a;
	g.defs = defs;
	fe_top *t = z->top;
	for (size_t i = 0; i < t->n_roots; i++)
		if (state_of(&g, t->roots[i].name) == 0)
			dfs(&g, t->roots[i].name);
	/* Kahn: reached callees only, callers first, ties in declaration order */
	fe_name_table indeg = {0}; /* name -> (intptr_t) count */
	fe_name_table reach = {0};
	for (size_t i = 0; i < g.state.n; i++)
		if (!g.state.e[i].removed && fe_name_get(&z->funcs, g.state.e[i].key))
			sset_add(&reach, g.state.e[i].key);
#define DEG(n) ((intptr_t)fe_name_get(&indeg, (n)))
#define SETDEG(n, v) fe_name_set(&indeg, (n), (void *)(intptr_t)(v))
	for (size_t i = 0; i < g.state.n; i++) {
		if (g.state.e[i].removed)
			continue;
		names *es = edge_from(&g, g.state.e[i].key);
		for (size_t k = 0; k < es->n; k++)
			if (sset_has(&reach, es->v[k]))
				SETDEG(es->v[k], DEG(es->v[k]) + 1);
	}
	for (size_t i = 0; i < t->n_roots; i++) {
		names *es = edge_from(&g, t->roots[i].name);
		for (size_t k = 0; k < es->n; k++)
			SETDEG(es->v[k], DEG(es->v[k]) - 1);
	}
	fe_func_info **ready = NULL;
	size_t n_ready = 0;
	for (size_t i = 0; i < reach.n; i++)
		if (!reach.e[i].removed && DEG(reach.e[i].key) == 0)
			T_PUSH(ready, n_ready, (fe_func_info *)fe_name_get(&z->funcs, reach.e[i].key));
	fe_func_info **order = NULL;
	size_t n = 0;
	size_t head = 0;
	while (n_ready > head) {
		qsort(ready + head, n_ready - head, sizeof *ready, decl_cmp);
		fe_func_info *f = ready[head++];
		T_PUSH(order, n, f);
		names *es = edge_from(&g, f->name);
		for (size_t k = 0; k < es->n; k++) {
			SETDEG(es->v[k], DEG(es->v[k]) - 1);
			if (DEG(es->v[k]) == 0)
				T_PUSH(ready, n_ready, (fe_func_info *)fe_name_get(&z->funcs, es->v[k]));
		}
	}
#undef DEG
#undef SETDEG
	/* the shape of the reached defs (SB034) and Spinel's signature — Go ranges over `reach`; C goes in declaration order */
	fe_func_info **rs = NULL;
	size_t n_rs = 0;
	for (size_t i = 0; i < reach.n; i++)
		if (!reach.e[i].removed)
			T_PUSH(rs, n_rs, (fe_func_info *)fe_name_get(&z->funcs, reach.e[i].key));
	if (n_rs)
		qsort(rs, n_rs, sizeof *rs, decl_cmp);
	for (size_t i = 0; i < n_rs; i++) {
		fe_func_info *fi = rs[i];
		size_t cnt;
		long ti = sr_type_of(z->typing.types, a, fi->def, &cnt);
		if (ti >= 0)
			cnt = 1;
		if (!fi->bad && fi->shape_err.n == 0 && cnt == 1 && !fe_integer_sig(z->typing.types->types[ti].signature)) {
			sr_str sig = z->typing.types->types[ti].signature;
			sr_str hint = sig_hint(sig);
			if (has_suffix(sig, "-> untyped"))
				hint = S("; if the last expression is arithmetic on a record member, assign it to a local first (`x = r.load.m & 0xFF` then `x`)");
			sr_buf b = {0};
			sr_puts(&b, "Spinel types the eBPF-side function `");
			sr_putstr(&b, fi->name);
			sr_puts(&b, "` as ");
			sr_putstr(&b, sig);
			sr_puts(&b, " — its arguments and its value must be Integer (no true / false, nil or other types)");
			sr_putstr(&b, hint);
			fi->shape_err = sr_bufstr(&b);
		}
		if (fi->shape_err.n) {
			fe_add(z->z, FE_REJECTED, FE_SB034, fe_pos_of(z->z, a, fi->def), fi->shape_err);
			fi->bad = 1;
		}
	}
	for (size_t i = 0; i < z->funcs.n; i++) {
		fe_func_info *fi = z->funcs.e[i].val;
		if (!z->funcs.e[i].removed && fi && fi->bad)
			z->any_bad_func = 1;
	}
	*n_order = n;
	return order;
}

/* ---- the flow records (subprogram.go progCtx.fn, progCtx.resolveSrc, progCtx.noteFlow, progCtx.noteFlowKey, progCtx.path) ---- */
static fe_fn_flows *fn_of(fe_prog_ctx *c)
{
	fe_fn_flows *f = fe_name_get(&c->z->flows_of, c->name);
	if (!f) {
		f = sr_alloc(sizeof *f);
		memset(f, 0, sizeof *f);
		fe_name_set(&c->z->flows_of, c->name, f);
	}
	return f;
}

static fe_flow_src resolve_src(fe_prog_ctx *c, const sr_node *n)
{
	fe_flow_src s = empty_src();
	fe_name_table refs = fe_derived_refs(c, n);
	for (size_t i = 0; i < refs.n; i++) {
		if (refs.e[i].removed || !refs.e[i].val)
			continue;
		sr_str r = refs.e[i].key;
		if (has_prefix(r, "@p") || has_prefix(r, "@r")) {
			char buf[24];
			size_t k = r.n - 2 < sizeof buf - 1 ? r.n - 2 : sizeof buf - 1;
			memcpy(buf, r.p + 2, k);
			buf[k] = 0;
			char *end;
			long long v = strtoll(buf, &end, 10);
			if (*end || k == 0)
				v = 0; /* strconv.Atoi's error leaves 0 */
			iset_add(r.p[1] == 'p' ? &s.params : &s.rets, v);
		} else if (has_prefix(r, "@g")) {
			sset_add(&s.maps, t_cat(S("g:"), (sr_str){r.p + 2, r.n - 2}));
		} else {
			fe_map_decl *m = fe_name_get(&c->ref_map, r);
			if (m)
				sset_add(&s.maps, t_cat(S("m:"), m->name));
		}
	}
	return s;
}

void fe_note_flow(fe_prog_ctx *c, const sr_node *val, fe_map_decl *m, const sr_node *at)
{
	sr_str k = {0};
	if (m)
		k = t_cat(S("m:"), m->name);
	fe_note_flow_key(c, val, k, at);
}

void fe_note_flow_key(fe_prog_ctx *c, const sr_node *val, sr_str k, const sr_node *at)
{
	if (!val)
		return;
	fe_fn_flows *f = fn_of(c);
	fe_flow fl;
	fl.src = resolve_src(c, val);
	fl.sink = k;
	fl.pos = fe_cpos(c, at);
	fl.path = fe_ctx_path(c, &fl.n_path);
	T_PUSH(f->flows, f->n_flows, fl);
}

sr_str *fe_ctx_path(fe_prog_ctx *c, size_t *n)
{
	if (c->fpath) {
		*n = c->n_fpath;
		return c->fpath;
	}
	sr_str *p = sr_alloc(sizeof *p);
	p[0] = c->name;
	*n = 1;
	return p;
}

/* ---- subCall (subprogram.go) ---- */
static void push_arg(fe_expr *e, fe_expr *x)
{
	T_PUSH(e->args, e->n_args, x);
	e->args_nil = 0;
}

static int borrow_param(fe_prog_ctx *c, sr_str ref)
{
	fe_func_info *fi = fe_name_get(&c->z->funcs, c->name);
	return fi && fi->borrow_idx >= 0 && (size_t)fi->borrow_idx < fi->n_params && sr_eq(fi->params[fi->borrow_idx], ref);
}

static int win_param(fe_prog_ctx *c, sr_str wn)
{
	fe_func_info *fi = fe_name_get(&c->z->funcs, c->name);
	return fi && fi->win_idx >= 0 && (size_t)fi->win_idx < fi->n_params && sr_eq(fi->params[fi->win_idx], wn);
}

fe_expr *fe_sub_call(fe_prog_ctx *c, const sr_node *n, fe_func_info *fi, sr_str ref_var)
{
	const sr_ast *a = c->a;
	if (fi->bad)
		return NULL;
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return NULL;
	if (!sr_eq(callee, fi->name)) {
		fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s` resolves to %q, not the top-level def %s", fi->name, callee, fi->name);
		return NULL;
	}
	if (t_ref(a, n, "block")) {
		fe_cadd(c, FE_REJECTED, FE_SB034, n, "a call of the eBPF-side function `%s` takes no block", fi->name);
		return NULL;
	}
	t_nodes as = t_args(a, n);
	if (as.n != fi->n_params) {
		fe_cadd(c, FE_REJECTED, FE_SB034, n, "`%s` takes %d arguments, called with %d", fi->name, (int64_t)fi->n_params, (int64_t)as.n);
		return NULL;
	}
	fe_expr *e = fe_expr_new("call", fe_cpos(c, n));
	e->var = fi->name;
	e->iv = fe_full_i64;
	fe_flow_src *srcs = NULL;
	size_t n_srcs = 0;
	int borrows = 0, special = 0;
	for (size_t i = 0; i < as.n; i++) {
		const sr_node *x = as.v[i];
		sr_str xn = t_str(x, "name");
		int is_read = t_is(x, "LocalVariableReadNode");
		if (is_read && (fe_name_get(&c->refs, xn) || fe_name_get(&c->wins, xn) || (c->param.n && sr_eq(xn, c->param)))) {
			special++;
			if (special > 1) {
				fe_cadd(c, FE_REJECTED, FE_SB034, x,
					"`%s` takes at most one argument that is not an Integer (a borrowed map value, a checked packet window or the context)",
					fi->name);
				return NULL;
			}
		}
		if (is_read && fe_name_get(&c->wins, xn)) {
			int64_t wl = ((fe_win_info *)fe_name_get(&c->wins, xn))->len;
			if (fe_streq(c->prog->kind, "func") && win_param(c, xn)) {
				fe_cadd(c, FE_REJECTED, FE_SB034, x,
					"the window argument `%s` is not forwarded to another eBPF-side function in this stage — read it here", xn);
				return NULL;
			}
			if (fi->win_idx >= 0 && (fi->win_idx != (int64_t)i || fi->win_len != wl)) {
				fe_cadd(c, FE_REJECTED, FE_SB034, x,
					"`%s` is called with a %d-byte window as argument %d, but another call passes a %d-byte window as argument %d — every call passes the same window length in the same place",
					fi->name, wl, (int64_t)i + 1, fi->win_len, fi->win_idx + 1);
				return NULL;
			}
			fi->win_idx = (int64_t)i;
			fi->win_len = wl;
			fe_expr *w = fe_expr_new("winarg", fe_cpos(c, x));
			w->ref = xn;
			w->len = wl;
			push_arg(e, w);
			T_PUSH(srcs, n_srcs, empty_src());
			continue;
		}
		if (c->param.n && fe_is_var_read(c, x, c->param)) {
			sr_str k = fe_ctx_kind_of(c);
			if (fe_streq(c->prog->kind, "func")) {
				fe_cadd(c, FE_REJECTED, FE_SB034, x,
					"the context argument `%s` is not forwarded to another eBPF-side function in this stage — check the packet here", c->param);
				return NULL;
			}
			if (!fe_has_packet(k) || fe_streq(k, "cgroup_skb")) {
				fe_cadd(c, FE_REJECTED, FE_SB034, x,
					"the %s context is not passed to an eBPF-side function — its reads depend on the attach point; read the values in the program and pass Integers",
					k);
				return NULL;
			}
			if (fi->ctx_idx >= 0 && (fi->ctx_idx != (int64_t)i || !sr_eq(fi->ctx_kind, k))) {
				fe_cadd(c, FE_REJECTED, FE_SB034, x,
					"`%s` is called with the %s context as argument %d, but another call passes the %s context as argument %d — one function takes one kind of context in one place",
					fi->name, k, (int64_t)i + 1, fi->ctx_kind, fi->ctx_idx + 1);
				return NULL;
			}
			fi->ctx_idx = (int64_t)i;
			fi->ctx_kind = k;
			fe_expr *w = fe_expr_new("ctxarg", fe_cpos(c, x));
			w->var = k;
			push_arg(e, w);
			T_PUSH(srcs, n_srcs, empty_src());
			continue;
		}
		if (is_read && fe_name_get(&c->refs, xn)) {
			sr_str ref = xn;
			fe_map_decl *m = fe_name_get(&c->ref_map, ref);
			borrows++;
			if (fe_streq(c->prog->kind, "func") && borrow_param(c, ref)) {
				fe_cadd(c, FE_REJECTED, FE_SB034, x,
					"the borrowed argument `%s` is not forwarded to another eBPF-side function in this stage — do the access here", ref);
				return NULL;
			}
			if (borrows > 1) {
				fe_cadd(c, FE_REJECTED, FE_SB034, x, "`%s` takes at most one borrowed map value", fi->name);
				return NULL;
			}
			if (fi->borrow_idx >= 0 && (fi->borrow_idx != (int64_t)i || fi->borrow_map != m)) {
				if (!m || !fi->borrow_map) {
					t_nil_panic = 1;
					return NULL;
				}
				fe_cadd(c, FE_REJECTED, FE_SB034, x,
					"`%s` is called with a borrowed value of %s as argument %d, but another call passes %s as argument %d — every call passes the same map value in the same place",
					fi->name, m->name, (int64_t)i + 1, fi->borrow_map->name, fi->borrow_idx + 1);
				return NULL;
			}
			fi->borrow_idx = (int64_t)i;
			fi->borrow_map = m;
			fe_expr *w = fe_expr_new("refarg", fe_cpos(c, x));
			w->ref = ref;
			w->map = m;
			push_arg(e, w);
			T_PUSH(srcs, n_srcs, empty_src());
			continue;
		}
		fe_expr *v = fe_ctx_expr(c, x, ref_var);
		if (!v)
			return NULL;
		if (v->bool_) {
			fe_cadd(c, FE_REJECTED, FE_SB034, x, "argument %d of `%s` is true / false — an eBPF-side function takes Integer arguments", (int64_t)i + 1,
				fi->name);
			return NULL;
		}
		if (v->wide) {
			fe_cadd(c, FE_REJECTED, FE_SB014, x,
				"argument %d of `%s` is a u64 value %I that does not fit Ruby's Integer — narrow it first (`x & M` or `x >> K`)", (int64_t)i + 1,
				fi->name, v->iv);
			return NULL;
		}
		push_arg(e, v);
		T_PUSH(srcs, n_srcs, resolve_src(c, x));
	}
	for (size_t i = 0; i < e->n_args; i++) {
		fe_expr *v = e->args[i];
		if (fe_streq(v->kind, "refarg") || fe_streq(v->kind, "winarg") || fe_streq(v->kind, "ctxarg"))
			continue;
		if (fi->n_arg_iv == 0) {
			fi->arg_iv = sr_alloc((fi->n_params + 1) * sizeof *fi->arg_iv);
			memset(fi->arg_iv, 0, (fi->n_params + 1) * sizeof *fi->arg_iv);
			fi->n_arg_iv = fi->n_params;
		}
		if (!fi->arg_iv[i].set)
			fi->arg_iv[i] = v->iv;
		else
			fi->arg_iv[i] = fe_union(fi->arg_iv[i], v->iv);
	}
	fi->called = 1;
	fe_call_site *s = sr_alloc(sizeof *s);
	s->id = n->id;
	s->caller = c->name;
	s->callee = fi;
	s->args = srcs;
	s->n_args = n_srcs;
	s->pos = fe_cpos(c, n);
	s->path = fe_ctx_path(c, &s->n_path);
	fe_fn_flows *f = fn_of(c);
	T_PUSH(f->sites, f->n_sites, s);
	int created;
	*sr_imap_slot(&c->z->site_by_node, n->id, &created) = s;
	return e;
}

/* ---- function (subprogram.go) ---- */
typedef struct {
	fe_prog_ctx *c;
	const fe_func_info *fi;
	int bad;
} fn_walk;

static int fn_walk_fn(void *u, const sr_node *x)
{
	fn_walk *w = u;
	if (w->bad)
		return 0;
	if (t_is(x, "ReturnNode")) {
		fe_cadd(w->c, FE_REJECTED, FE_SB034, x,
			"`return` is not accepted in the eBPF-side function `%s` — its last expression is its value (use if / else)", w->fi->name);
		w->bad = 1;
	} else if (t_is(x, "ConstantPathNode") && fe_verdict_kind_of(t_const_name(w->c->a, x)).n) {
		fe_cadd(w->c, FE_REJECTED, FE_SB034, x,
			"%s is a program verdict — an eBPF-side function returns an Integer; return the verdict from the program", t_const_name(w->c->a, x));
		w->bad = 1;
	}
	return !w->bad;
}

static int is_stmt_only_call(fe_prog_ctx *c, const sr_node *n)
{
	const sr_node *r = t_ref(c->a, n, "receiver");
	if (!r || !t_is(r, "ConstantReadNode"))
		return 0;
	sr_str name = t_str(n, "name");
	if (fe_name_get(&c->z->top->maps, t_str(r, "name")) && (fe_streq(name, "update") || fe_streq(name, "atomic_add")))
		return 1;
	return fe_name_get(&c->z->top->globals, t_str(r, "name")) && fe_streq(name, "add");
}

static int blocking_since(const fe_diags *ds, size_t before)
{
	for (size_t i = before; i < ds->n; i++)
		if (ds->v[i].verdict != FE_CONDITIONAL && ds->v[i].verdict != FE_VERIFIED)
			return 1;
	return 0;
}

fe_program *fe_function(fe_analysis *z, const sr_ast *a, fe_func_info *fi)
{
	const sr_node *d = fi->def;
	fe_prog_ctx *c = fe_new_ctx(z, a, d, fi->name);
	c->fpath = fi->path;
	c->n_fpath = fi->n_path;
	fe_program *p = sr_alloc(sizeof *p);
	memset(p, 0, sizeof *p);
	c->prog = p;
	p->name = fi->name;
	p->kind = S("func");
	p->pos = fe_cpos(c, d);
	p->end_line = d->end_line;
	p->f_params = fi->params;
	p->n_f_params = fi->n_params;
	p->f_params_nil = fi->n_params == 0;
	p->f_borrow = fi->borrow_idx;
	p->f_borrow_map = fi->borrow_map;
	p->f_win = fi->win_idx;
	p->f_win_len = fi->win_len;
	p->f_ctx = fi->ctx_idx;
	p->f_ctx_kind = fi->ctx_kind;
	p->params_nil = p->t_args_nil = p->t_fields_nil = p->globals_nil = p->maps_nil = p->rings_nil = 1;
	p->body.nil = 1;
	size_t before = z->z->diags.n;
	fn_walk fw = {c, fi, 0};
	t_walk(a, d, fn_walk_fn, &fw);
	if (fw.bad)
		return NULL;
	sr_str ref_var = {0};
	for (size_t i = 0; i < fi->n_params; i++) {
		sr_str pn = fi->params[i];
		if ((int64_t)i == fi->win_idx) {
			fe_win_info *w = sr_alloc(sizeof *w);
			w->len = fi->win_len;
			w->active = 1;
			fe_name_set(&c->wins, pn, w);
			continue;
		}
		if ((int64_t)i == fi->ctx_idx) {
			c->param = pn;
			c->ctx_kind = fi->ctx_kind;
			continue;
		}
		if ((int64_t)i == fi->borrow_idx) {
			t_nodes reqs = t_arr(a, t_ref(a, d, "parameters"), "requireds");
			if (i >= reqs.n) {
				t_nil_panic = 1;
				return NULL;
			}
			fe_name_set(&c->refs, pn, (void *)reqs.v[i]);
			fe_name_set(&c->ref_map, pn, fi->borrow_map);
			fe_name_set(&c->ref_key, pn, NULL);
			ref_var = pn;
			continue;
		}
		fe_ival iv = fe_full_i64;
		if (i < fi->n_arg_iv && fi->arg_iv[i].set)
			iv = fi->arg_iv[i];
		fe_var_info *v = sr_alloc(sizeof *v);
		memset(v, 0, sizeof *v);
		v->iv = iv;
		fe_name_set(&v->from, sfmt("@p%zu", i), TRUE_);
		fe_name_set(&c->env, pn, v);
	}
	const sr_node *body = t_ref(a, d, "body");
	t_nodes stmts = {0};
	if (body) {
		if (!t_is(body, "StatementsNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB034, body,
				"the body of the eBPF-side function `%s` must be a plain sequence of statements (no rescue / ensure)", fi->name);
			return NULL;
		}
		stmts = t_arr(a, body, "body");
	}
	if (stmts.n == 0) {
		fe_cadd(c, FE_REJECTED, FE_SB034, d, "the eBPF-side function `%s` must end with an Integer expression (its value)", fi->name);
		return NULL;
	}
	const sr_node *last = stmts.v[stmts.n - 1];
	static const char *const bad_last[] = {"LocalVariableWriteNode", "IfNode", "UnlessNode", "WhileNode", "UntilNode", "CaseNode",
					       "MultiWriteNode", "LocalVariableOperatorWriteNode", NULL};
	if (t_in(last->type, bad_last)) {
		fe_cadd(c, FE_REJECTED, FE_SB034, last,
			"the last statement of the eBPF-side function `%s` must be an Integer expression (its value), not %s", fi->name, last->type);
		return NULL;
	}
	if (t_is(last, "CallNode") && is_stmt_only_call(c, last)) {
		fe_cadd(c, FE_REJECTED, FE_SB034, last,
			"the last statement of the eBPF-side function `%s` must be an Integer expression (its value), not the map / global call `%s`",
			fi->name, t_str(last, "name"));
		return NULL;
	}
	p->body = fe_ctx_stmts(c, stmts.v, stmts.n - 1, ref_var);
	fe_expr *ret = fe_ctx_expr(c, last, ref_var);
	if (!ret)
		return NULL;
	if (ret->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB034, last, "the eBPF-side function `%s` returns true / false — it returns an Integer", fi->name);
		return NULL;
	}
	if (ret->wide) {
		fe_cadd(c, FE_REJECTED, FE_SB014, last,
			"the eBPF-side function `%s` returns a u64 value that does not fit Ruby's Integer — narrow it first (`x & M` or `x >> K`)", fi->name);
		return NULL;
	}
	p->f_ret = ret;
	p->verdict_pos = fe_cpos(c, last);
	fe_note_flow(c, last, NULL, last);
	fe_top *t = z->top;
	for (size_t i = 0; i < t->n_map_order; i++)
		if (fe_ptr_set_has(&c->used, t->map_order[i])) {
			T_PUSH(p->maps, p->n_maps, t->map_order[i]);
			p->maps_nil = 0;
		}
	for (size_t i = 0; i < t->n_ring_order; i++)
		if (fe_ptr_set_has(&c->used_rings, t->ring_order[i])) {
			T_PUSH(p->rings, p->n_rings, t->ring_order[i]);
			p->rings_nil = 0;
		}
	for (size_t i = 0; i < t->n_global_order; i++)
		if (fe_ptr_set_has(&c->used_globals, t->global_order[i])) {
			T_PUSH(p->globals, p->n_globals, t->global_order[i]);
			p->globals_nil = 0;
		}
	if (z->z->diags.n > before && blocking_since(&z->z->diags, before))
		return NULL;
	return p;
}

/* ---- resolveSubprograms (subprogram.go) ---- */
typedef struct {
	fe_name_table maps;
	sr_imap params;
	fe_name_table via_ret;
} expanded;

typedef struct {
	fe_analysis *z;
	sr_imap sites_by_id;
	fe_name_table by_name;
	fe_diags reported; /* (pos, msg) pairs already reported */
} rs_state;

static void sset_union(fe_name_table *dst, const fe_name_table *src)
{
	for (size_t i = 0; i < src->n; i++)
		if (!src->e[i].removed && src->e[i].val)
			sset_add(dst, src->e[i].key);
}

static void iset_union(sr_imap *dst, const sr_imap *src)
{
	int64_t *ks = sr_imap_sorted_keys(src);
	for (size_t i = 0; i < src->n; i++)
		if (sr_imap_get(src, ks[i]))
			iset_add(dst, ks[i]);
}

static expanded expand(rs_state *s, const fe_flow_src *src, int depth)
{
	expanded e;
	memset(&e, 0, sizeof e);
	sset_union(&e.maps, &src->maps);
	iset_union(&e.params, &src->params);
	if (depth > 16)
		return e;
	int64_t *ids = sr_imap_sorted_keys(&src->rets);
	for (size_t q = 0; q < src->rets.n; q++) {
		fe_call_site *site = sr_imap_get(&s->sites_by_id, ids[q]);
		if (!site)
			continue;
		fe_func_info *g = site->callee;
		for (size_t i = 0; i < g->r_maps.n; i++)
			if (!g->r_maps.e[i].removed && g->r_maps.e[i].val) {
				sset_add(&e.maps, g->r_maps.e[i].key);
				sset_add(&e.via_ret, g->r_maps.e[i].key);
			}
		int64_t *js = sr_imap_sorted_keys(&g->r_param);
		for (size_t k = 0; k < g->r_param.n; k++) {
			int64_t j = js[k];
			if (j < 0 || (size_t)j >= site->n_args)
				continue;
			expanded x = expand(s, &site->args[j], depth + 1);
			for (size_t i = 0; i < x.maps.n; i++)
				if (!x.maps.e[i].removed && x.maps.e[i].val) {
					sset_add(&e.maps, x.maps.e[i].key);
					sset_add(&e.via_ret, x.maps.e[i].key);
				}
			iset_union(&e.params, &x.params);
			sset_union(&e.via_ret, &x.via_ret);
		}
	}
	return e;
}

static int exempt_key(rs_state *s, sr_str k)
{
	if (!has_prefix(k, "m:"))
		return 0;
	fe_map_decl *m = fe_name_get(&s->by_name, (sr_str){k.p + 2, k.n - 2});
	return fe_per_cpu_exempt(m, s->z->top->root_kinds, s->z->top->n_root_kinds);
}

static sr_str obj_name(sr_str k)
{
	sr_str rest = {k.p + 2, k.n - 2};
	if (has_prefix(k, "g:"))
		return t_cat(S("Counter "), rest);
	return rest;
}

static void report(rs_state *s, fe_pos p, sr_str *path, size_t n_path, sr_str msg)
{
	for (size_t i = 0; i < s->reported.n; i++) {
		const fe_diag *d = &s->reported.v[i];
		if (sr_eq(d->pos.file, p.file) && d->pos.line == p.line && d->pos.col == p.col && sr_eq(d->msg, msg))
			return;
	}
	fe_diag d = {FE_REJECTED, FE_SB019, p, path, n_path, msg};
	fe_diags_push(&s->reported, d);
	fe_diags_push(&s->z->z->diags, d);
}

static fe_name_table *w_of(fe_func_info *fi, int64_t p)
{
	fe_name_table *t = sr_imap_get(&fi->w, p);
	if (!t) {
		t = sr_alloc(sizeof *t);
		memset(t, 0, sizeof *t);
		int created;
		*sr_imap_slot(&fi->w, p, &created) = t;
	}
	return t;
}

static void process(rs_state *s, sr_str name, fe_func_info *fi)
{
	fe_fn_flows *f = fe_name_get(&s->z->flows_of, name);
	if (!f)
		return;
	for (size_t q = 0; q < f->n_sites; q++) {
		fe_call_site *site = f->sites[q];
		fe_func_info *g = site->callee;
		for (size_t j = 0; j < site->n_args; j++) {
			expanded x = expand(s, &site->args[j], 0);
			fe_name_table *gw = sr_imap_get(&g->w, (int64_t)j);
			if (!gw)
				continue;
			size_t nk;
			sr_str *keys = fe_sorted_set(gw, &nk); /* Go ranges over the map: C reports in sorted order */
			for (size_t k = 0; k < nk; k++) {
				sr_str m = keys[k];
				if (sset_has(&x.maps, m) && !exempt_key(s, m)) {
					sr_buf b = {0};
					sr_puts(&b, "`");
					sr_putstr(&b, g->name);
					sr_printf(&b, "(…)` argument %zu carries a value read from ", j + 1);
					sr_putstr(&b, obj_name(m));
					sr_puts(&b, ", and `");
					sr_putstr(&b, g->name);
					sr_puts(&b, "` writes ");
					sr_putstr(&b, obj_name(m));
					sr_puts(&b, " — concurrent CPUs lose updates across the call; use atomic_add on the entry with a delta that does not read it");
					report(s, site->pos, site->path, site->n_path, sr_bufstr(&b));
				}
				if (fi) {
					int64_t *ps = sr_imap_sorted_keys(&x.params);
					for (size_t i = 0; i < x.params.n; i++)
						if (sr_imap_get(&x.params, ps[i]))
							sset_add(w_of(fi, ps[i]), m);
				}
			}
		}
	}
	for (size_t q = 0; q < f->n_flows; q++) {
		fe_flow *fl = &f->flows[q];
		expanded x = expand(s, &fl->src, 0);
		if (fl->sink.n == 0) {
			if (fi) {
				sset_union(&fi->r_maps, &x.maps);
				iset_union(&fi->r_param, &x.params);
			}
			continue;
		}
		if (sset_has(&x.via_ret, fl->sink) && !exempt_key(s, fl->sink)) {
			sr_buf b = {0};
			sr_puts(&b, "the value written to ");
			sr_putstr(&b, obj_name(fl->sink));
			sr_puts(&b, " comes from an eBPF-side function that reads ");
			sr_putstr(&b, obj_name(fl->sink));
			sr_puts(&b, " — concurrent CPUs lose updates across the call; use atomic_add on the entry with a delta that does not read it");
			report(s, fl->pos, fl->path, fl->n_path, sr_bufstr(&b));
		}
		if (fi) {
			int64_t *ps = sr_imap_sorted_keys(&x.params);
			for (size_t i = 0; i < x.params.n; i++)
				if (sr_imap_get(&x.params, ps[i]))
					sset_add(w_of(fi, ps[i]), fl->sink);
		}
	}
}

void fe_resolve_subprograms(fe_analysis *z, fe_func_info **order, size_t n_order, fe_program **programs, size_t n_programs)
{
	rs_state s;
	memset(&s, 0, sizeof s);
	s.z = z;
	for (size_t i = 0; i < z->flows_of.n; i++) {
		fe_fn_flows *f = z->flows_of.e[i].val;
		if (z->flows_of.e[i].removed || !f)
			continue;
		for (size_t q = 0; q < f->n_sites; q++) {
			int created;
			*sr_imap_slot(&s.sites_by_id, f->sites[q]->id, &created) = f->sites[q];
		}
	}
	for (size_t i = 0; i < z->top->n_map_order; i++)
		fe_name_set(&s.by_name, z->top->map_order[i]->name, z->top->map_order[i]);
	for (size_t i = n_order; i-- > 0;)
		process(&s, order[i]->name, order[i]);
	for (size_t i = 0; i < n_programs; i++)
		process(&s, programs[i]->name, NULL);
}

/* callsBadFunc (subprogram.go) */
typedef struct {
	fe_prog_ctx *c;
	int bad;
} badf_walk;

static int badf_walk_fn(void *u, const sr_node *x)
{
	badf_walk *w = u;
	fe_func_info *fi = fe_user_call(w->c->z, w->c->a, x);
	if (fi && fi->bad)
		w->bad = 1;
	return !w->bad;
}

int fe_calls_bad_func(fe_prog_ctx *c, const sr_node *n)
{
	if (!c->z->any_bad_func)
		return 0;
	badf_walk w = {c, 0};
	t_walk(c->a, n, badf_walk_fn, &w);
	return w.bad;
}

/* ringPath (subprogram.go) */
typedef struct {
	fe_prog_ctx *c;
	fe_func_info *f;
	fe_name_table *seen;
	sr_str *out;
	size_t n_out;
} ring_walk;

static sr_str *ring_path(fe_prog_ctx *c, fe_func_info *f, fe_name_table *seen, size_t *n);

static int ring_walk_fn(void *u, const sr_node *x)
{
	ring_walk *w = u;
	fe_prog_ctx *c = w->c;
	if (w->out)
		return 0;
	if (fe_is_output(c, x) || fe_is_output_str(c, x)) {
		const sr_node *r = t_ref(c->a, x, "receiver");
		if (!r) {
			t_nil_panic = 1;
			return 0;
		}
		w->out = sr_alloc(2 * sizeof *w->out);
		w->out[0] = w->f->name;
		w->out[1] = t_cat(t_cat(t_str(r, "name"), S(".")), t_str(x, "name"));
		w->n_out = 2;
		return 0;
	}
	fe_func_info *g = fe_user_call(c->z, c->a, x);
	if (g) {
		size_t np;
		sr_str *p = ring_path(c, g, w->seen, &np);
		if (p) {
			w->out = sr_alloc((np + 1) * sizeof *w->out);
			w->out[0] = w->f->name;
			memcpy(w->out + 1, p, np * sizeof *p);
			w->n_out = np + 1;
			return 0;
		}
	}
	return 1;
}

static sr_str *ring_path(fe_prog_ctx *c, fe_func_info *f, fe_name_table *seen, size_t *n)
{
	*n = 0;
	if (sset_has(seen, f->name))
		return NULL;
	sset_add(seen, f->name);
	ring_walk w = {c, f, seen, NULL, 0};
	t_walk(c->a, f->def, ring_walk_fn, &w);
	*n = w.n_out;
	return w.out;
}

sr_str *fe_ring_path(fe_prog_ctx *c, fe_func_info *f, size_t *n)
{
	fe_name_table seen = {0};
	return ring_path(c, f, &seen, n);
}

/* borrowArgUse (subprogram.go) */
int fe_borrow_arg_use(fe_prog_ctx *c, const sr_node *x)
{
	const sr_ast *a = c->a;
	const int64_t *pid = sr_imap_get(&a->parent, x->id);
	const sr_node *p = t_node(a, pid ? *pid : 0);
	if (!p || !t_is(p, "ArgumentsNode"))
		return 0;
	const int64_t *gid = sr_imap_get(&a->parent, p->id);
	return fe_user_call(c->z, a, t_node(a, gid ? *gid : 0)) != NULL;
}

/* ctxKindOf (subprogram.go) */
sr_str fe_ctx_kind_of(fe_prog_ctx *c)
{
	if (c->prog && fe_streq(c->prog->kind, "func")) {
		if (c->ctx_kind.n)
			return c->ctx_kind;
		return S("func");
	}
	if (!c->prog)
		return (sr_str){0};
	return c->prog->kind;
}
