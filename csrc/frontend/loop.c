/* loop.c — internal/frontend/loop.go (bounded loops) and guard.go (early-return guards).
 *
 * A Go map order fixed here: loopStmt's "bool carried" SB030 names the first such local in the body's walk
 * order (Go: `range writesIn(...)`). */
#include "core.h"

#include <string.h>

#define S(x) sr_cstr(x)
static int one_ = 1;
#define TRUE_ ((void *)&one_)

const char *const fe_loop_forms = "`N.times do |i| … end`, `k.times`, `(0...k).each` or `(0..m).each`";

static const char *const iter_names[] = {"times", "each",	   "upto", "downto",	 "step",      "each_with_index", "each_with_object",
					 "map",	  "select", "reject", "each_slice", "each_cons", "reverse_each",   "loop",
					 NULL};

/* isIterCall (loop.go) */
int fe_is_iter_call(fe_prog_ctx *c, const sr_node *n)
{
	if (!n || !t_is(n, "CallNode") || !t_in(t_str(n, "name"), iter_names))
		return 0;
	const sr_node *b = t_ref(c->a, n, "block");
	return b && t_is(b, "BlockNode");
}

/* rangeRecv (loop.go) */
static int range_recv(fe_prog_ctx *c, const sr_node *recv, const sr_node **lo, const sr_node **hi, int *incl)
{
	if (!recv || !t_is(recv, "ParenthesesNode"))
		return 0;
	const sr_node *st = t_ref(c->a, recv, "body");
	if (!st || !t_is(st, "StatementsNode") || t_arr(c->a, st, "body").n != 1)
		return 0;
	const sr_node *r = t_arr(c->a, st, "body").v[0];
	if (!t_is(r, "RangeNode"))
		return 0;
	int ok;
	int64_t flags = fe_node_int(r, "flags", &ok);
	*lo = t_ref(c->a, r, "left");
	*hi = t_ref(c->a, r, "right");
	*incl = (flags & 4) == 0;
	return 1;
}

/* blockParam (loop.go) */
static int block_param(fe_prog_ctx *c, const sr_node *blk, sr_str *out)
{
	const sr_ast *a = c->a;
	*out = (sr_str){0};
	const sr_node *bp = t_ref(a, blk, "parameters");
	if (!bp)
		return 1;
	const sr_node *ps = t_ref(a, bp, "parameters");
	if (!t_is(bp, "BlockParametersNode") || t_arr(a, bp, "locals").n != 0 || !ps) {
		fe_cadd(c, FE_REJECTED, FE_SB030, bp, "the loop block takes one parameter `|i|` (or none) — no block-local `;` names");
		return 0;
	}
	t_nodes req = t_arr(a, ps, "requireds");
	size_t extra = t_arr(a, ps, "optionals").n + t_arr(a, ps, "keywords").n + t_arr(a, ps, "posts").n;
	static const char *const fs[] = {"rest", "keyword_rest", "block"};
	for (size_t i = 0; i < 3; i++)
		if (t_ref(a, ps, fs[i]))
			extra++;
	if (req.n != 1 || extra != 0 || !t_is(req.v[0], "RequiredParameterNode")) {
		fe_cadd(c, FE_REJECTED, FE_SB030, bp, "the loop block takes one parameter `|i|` (the index 0, 1, …) or none");
		return 0;
	}
	*out = t_str(req.v[0], "name");
	return 1;
}

/* writesIn (loop.go): name -> the first write node, in walk order */
typedef struct {
	fe_name_table out;
} writes_walk;

static int writes_walk_fn(void *u, const sr_node *x)
{
	writes_walk *w = u;
	if (t_is(x, "LocalVariableWriteNode") || t_is(x, "LocalVariableOperatorWriteNode") || t_is(x, "LocalVariableOrWriteNode") ||
	    t_is(x, "LocalVariableAndWriteNode")) {
		sr_str nm = t_str(x, "name");
		if (!fe_name_has(&w->out, nm))
			fe_name_set(&w->out, nm, (void *)x);
	}
	return 1;
}

static fe_name_table writes_in(const sr_ast *a, const sr_node *n)
{
	writes_walk w = {{0}};
	if (n)
		t_walk(a, n, writes_walk_fn, &w);
	return w.out;
}

/* ---- the snapshot (loop.go ctxSnapshot, cp, progCtx.save, progCtx.restore) ---- */
static fe_name_table name_copy(const fe_name_table *t)
{
	fe_name_table o = {0};
	for (size_t i = 0; i < t->n; i++)
		if (!t->e[i].removed)
			fe_name_set(&o, t->e[i].key, t->e[i].val);
	return o;
}

static fe_ptr_set ptr_copy(const fe_ptr_set *s)
{
	fe_ptr_set o = {0};
	for (size_t i = 0; i < s->n; i++)
		fe_ptr_set_add(&o, s->v[i]);
	return o;
}

static sr_imap imap_copy(const sr_imap *m)
{
	sr_imap o;
	memset(&o, 0, sizeof o);
	int64_t *ks = sr_imap_sorted_keys(m);
	for (size_t i = 0; i < m->n; i++) {
		int created;
		*sr_imap_slot(&o, ks[i], &created) = sr_imap_get(m, ks[i]);
	}
	return o;
}

static fe_ctx_snapshot save(fe_prog_ctx *c)
{
	fe_ctx_snapshot s;
	s.diags = (int64_t)c->z->z->diags.n;
	s.refs = name_copy(&c->refs);
	s.ref_map = name_copy(&c->ref_map);
	s.ref_key = name_copy(&c->ref_key);
	s.wins = name_copy(&c->wins);
	s.used = ptr_copy(&c->used);
	s.used_globals = ptr_copy(&c->used_globals);
	s.used_rings = ptr_copy(&c->used_rings);
	s.bad_bind = name_copy(&c->bad_bind);
	s.poisoned = name_copy(&c->poisoned);
	s.status_reported = name_copy(&c->status_reported);
	s.locals = name_copy(&c->block_locals);
	s.skip_ifs = imap_copy(&c->skip_ifs);
	return s;
}

static void restore(fe_prog_ctx *c, const fe_ctx_snapshot *s)
{
	c->z->z->diags.n = (size_t)s->diags;
	c->refs = name_copy(&s->refs);
	c->ref_map = name_copy(&s->ref_map);
	c->ref_key = name_copy(&s->ref_key);
	c->wins = name_copy(&s->wins);
	c->used = ptr_copy(&s->used);
	c->used_globals = ptr_copy(&s->used_globals);
	c->used_rings = ptr_copy(&s->used_rings);
	c->bad_bind = name_copy(&s->bad_bind);
	c->poisoned = name_copy(&s->poisoned);
	c->status_reported = name_copy(&s->status_reported);
	c->block_locals = name_copy(&s->locals);
	c->skip_ifs = imap_copy(&s->skip_ifs);
}

/* keepKeys (loop.go) */
static fe_name_table keep_keys(const fe_name_table *e, const fe_name_table *pre)
{
	fe_name_table out = {0};
	for (size_t i = 0; i < e->n; i++) {
		if (e->e[i].removed || !fe_name_has(pre, e->e[i].key))
			continue;
		fe_var_info *v = sr_alloc(sizeof *v);
		*v = *(const fe_var_info *)e->e[i].val;
		fe_name_set(&out, e->e[i].key, v);
	}
	for (size_t i = 0; i < pre->n; i++) {
		if (pre->e[i].removed || fe_name_has(&out, pre->e[i].key))
			continue;
		fe_var_info *v = sr_alloc(sizeof *v);
		*v = *(const fe_var_info *)pre->e[i].val;
		fe_name_set(&out, pre->e[i].key, v);
	}
	return out;
}

/* loopBody (loop.go) */
static fe_stmts loop_body(fe_prog_ctx *c, const sr_node *const *body, size_t nb, const fe_name_table *entry, sr_str iv_name, fe_ival iv,
			  int64_t n, fe_name_table *end, fe_name_table **breaks, size_t *n_breaks)
{
	c->env = fe_copy_env(entry);
	if (iv_name.n) {
		fe_var_info *v = sr_alloc(sizeof *v);
		memset(v, 0, sizeof *v);
		v->iv = iv;
		v->from_nil = 1;
		fe_name_set(&c->env, iv_name, v);
	}
	fe_loop_frame *f = sr_alloc(sizeof *f);
	memset(f, 0, sizeof *f);
	f->n = n;
	T_PUSH(c->loops, c->n_loops, f);
	sr_str saved_arm = c->esc_arm;
	c->esc_arm = (sr_str){0};
	fe_stmts ss = fe_ctx_stmts(c, body, nb, (sr_str){0});
	c->esc_arm = saved_arm;
	c->n_loops--;
	fe_name_table e = c->env;
	for (size_t i = 0; i < f->n_nexts; i++)
		e = fe_join_env(&e, &f->nexts[i]);
	*end = e;
	*breaks = f->breaks;
	*n_breaks = f->n_breaks;
	return ss;
}

/* loopBodyAllowed (loop.go) */
typedef struct {
	fe_prog_ctx *c;
	sr_str iv_name;
	int ok;
} allowed_walk;

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

static int allowed_walk_fn(void *u, const sr_node *x)
{
	allowed_walk *w = u;
	fe_prog_ctx *c = w->c;
	if (!w->ok)
		return 0;
	sr_str nm = t_str(x, "name");
	fe_func_info *uc;
	if (t_is(x, "LocalVariableReadNode") && fe_name_get(&c->kptrs, nm)) {
		fe_cadd(c, FE_REJECTED, FE_SB030, x,
			"the kernel pointer `%s` is not read inside a loop body (bpf-mlir's ebpf.loop body has no CO-RE read) — read the members before the loop", nm);
		w->ok = 0;
	} else if (t_is(x, "LocalVariableReadNode") && (fe_name_get(&c->refs, nm) || fe_name_get(&c->wins, nm))) {
		fe_cadd(c, FE_REJECTED, FE_SB030, x,
			"`%s` is bound outside the loop — a lookup result or a packet window does not cross into a loop body (bpf-mlir's ebpf.loop carries only integers); do the lookup / check inside the body",
			nm);
		w->ok = 0;
	} else if (w->iv_name.n && has_prefix(x->type, "LocalVariable") && has_suffix(x->type, "WriteNode") && sr_eq(nm, w->iv_name)) {
		fe_cadd(c, FE_REJECTED, FE_SB030, x,
			"the loop index `%s` is not assigned inside the body (Ruby rebinds it every iteration; the unrolled copies fix it) — use another local",
			w->iv_name);
		w->ok = 0;
	} else if ((uc = fe_user_call(c->z, c->a, x)) != NULL && ({
			   size_t np;
			   fe_ring_path(c, uc, &np) != NULL;
		   })) {
		size_t np;
		sr_str *p = fe_ring_path(c, uc, &np);
		fe_cadd(c, FE_REJECTED, FE_SB030, x,
			"`%s` is called inside a loop and reaches a ring buffer output (%s) — bpf-mlir's ebpf.loop body cannot reach a ring buffer op through a call; output after the loop",
			nm, t_join(p, np, " → "));
		w->ok = 0;
	} else if (fe_is_output(c, x) || fe_is_output_str(c, x)) {
		fe_cadd(c, FE_REJECTED, FE_SB030, x,
			"a ring buffer `%s` is not accepted inside a loop (bpf-mlir's ebpf.loop body has no ring buffer op) — count in the loop and output after it",
			nm);
		w->ok = 0;
	}
	return w->ok;
}

static int loop_body_allowed(fe_prog_ctx *c, const sr_node *blk, sr_str iv_name)
{
	if (iv_name.n && (fe_name_has(&c->env, iv_name) || sr_eq(iv_name, c->param) || fe_name_get(&c->refs, iv_name) ||
			  fe_name_get(&c->wins, iv_name))) {
		fe_cadd(c, FE_REJECTED, FE_SB030, blk, "the block parameter `%s` shadows a local of the same name — rename it", iv_name);
		return 0;
	}
	allowed_walk w = {c, iv_name, 1};
	const sr_node *body = t_ref(c->a, blk, "body");
	if (body)
		t_walk(c->a, body, allowed_walk_fn, &w);
	return w.ok;
}

/* loopStmt (loop.go) */
int fe_loop_stmt(fe_prog_ctx *c, const sr_node *n, fe_stmt *out)
{
	const sr_ast *a = c->a;
	sr_str name = t_str(n, "name");
	const sr_node *recv = t_ref(a, n, "receiver"), *blk = t_ref(a, n, "block");
	if (fe_streq(name, "loop") && !recv) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "`loop do` has no bound — write %S with a bound ≤ %d", fe_loop_forms, (int64_t)FE_MAX_LOOP_COUNT);
		return 0;
	}
	const sr_node *count = NULL;
	int incl = 0;
	if (fe_streq(name, "times") && recv && t_args(a, n).n == 0) {
		count = recv;
	} else if (fe_streq(name, "each") && t_args(a, n).n == 0) {
		const sr_node *lo = NULL, *hi = NULL;
		int in = 0;
		if (!range_recv(c, recv, &lo, &hi, &in) || !hi) {
			fe_cadd(c, FE_REJECTED, FE_SB030, n, "`each` is accepted only on a range `(0...k)` / `(0..m)` — the bounded loops are %S", fe_loop_forms);
			return 0;
		}
		int ok;
		if (!lo || !t_is(lo, "IntegerNode") || fe_node_int(lo, "value", &ok) != 0) {
			fe_cadd(c, FE_REJECTED, FE_SB030, n, "the range must start at literal 0 — write `(0...k).each` and add the start inside the body");
			return 0;
		}
		count = hi;
		incl = in;
	} else {
		fe_cadd(c, FE_REJECTED, FE_SB030, n, "`%s` with a block is not accepted on the eBPF side — the bounded loops are %S", name, fe_loop_forms);
		return 0;
	}
	if (c->n_loops >= 2) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n, "loops nest at most 2 deep on the eBPF side (bpf-mlir's ebpf.loop) — move the innermost loop out");
		return 0;
	}
	sr_str iv_name;
	if (!block_param(c, blk, &iv_name))
		return 0;
	const sr_node *body = t_ref(a, blk, "body");
	t_nodes body_n = {0};
	if (body) {
		if (!t_is(body, "StatementsNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB030, body, "the loop body must be a plain sequence of statements, got %s", body->type);
			return 0;
		}
		body_n = t_arr(a, body, "body");
	}
	if (!loop_body_allowed(c, blk, iv_name))
		return 0;

	fe_expr *bound = NULL;
	int64_t n_count = 0;
	int clamp = 0;
	intv max = intv_from_i64(FE_MAX_LOOP_COUNT);
	if (t_is(count, "IntegerNode")) {
		bigint v;
		if (!fe_literal(c->z->z, a, count, &v))
			return 0;
		int ok;
		intv x = fe_intv_of_big(&v, &ok);
		if (!ok) {
			fe_not_ported(c->z->z, "a loop count beyond 128 bits");
			return 0;
		}
		if (incl)
			x = fe_iv_add1(x, intv_from_i64(1));
		if (intv_cmp(x, max) > 0) {
			char xb[48];
			fe_cadd(c, FE_REJECTED, FE_SB030, n, "the loop runs %S times — bpf-mlir's ebpf.loop runs at most %d; split the work or narrow it",
				intv_string(x, xb), (int64_t)FE_MAX_LOOP_COUNT);
			return 0;
		}
		if (intv_sign(x) > 0)
			n_count = intv_int64(x);
	} else {
		fe_expr *e = fe_ctx_expr(c, count, (sr_str){0});
		if (!e)
			return 0;
		if (e->bool_ || e->wide) {
			fe_cadd(c, FE_REJECTED, FE_SB030, count, "the loop count must be an Integer");
			return 0;
		}
		fe_ival r = e->iv;
		if (incl)
			r = fe_iv_add(r, fe_point(intv_from_i64(1)));
		if (intv_cmp(r.hi, max) > 0) {
			fe_cadd(c, FE_REJECTED, FE_SB030, count,
				"the loop %S has range %I — its upper end must be ≤ %d for bpf-mlir's ebpf.loop: show it in the range, e.g. `k & 63`, `k %% 64` or inside `if k <= 64`",
				incl ? "count (m + 1)" : "count", r, (int64_t)FE_MAX_LOOP_COUNT);
			return 0;
		}
		if (intv_sign(r.hi) > 0)
			n_count = intv_int64(r.hi);
		clamp = intv_sign(r.lo) < 0;
		bound = e;
	}
	int64_t prod = n_count;
	for (size_t i = 0; i < c->n_loops; i++)
		prod *= c->loops[i]->n;
	if (prod > FE_MAX_LOOP_COUNT) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n,
			"the nested loops run %d times in all — bpf-mlir's ebpf.loop allows a product ≤ %d; shrink one of the counts", prod,
			(int64_t)FE_MAX_LOOP_COUNT);
		return 0;
	}

	/* the outer locals the body assigns (iter_args) */
	fe_name_table pre = c->env;
	fe_name_table writes = writes_in(a, body);
	sr_str *carried = NULL;
	size_t n_carried = 0;
	for (size_t i = 0; i < writes.n; i++) {
		sr_str w = writes.e[i].key;
		if (!fe_name_has(&pre, w))
			continue;
		const fe_var_info *pv = fe_name_get(&pre, w);
		if (pv && pv->bool_) {
			fe_cadd(c, FE_REJECTED, FE_SB030, writes.e[i].val,
				"`%s` is a bool assigned inside the loop — a value carried across iterations must be an Integer (use 0 / 1)", w);
			return 0;
		}
		T_PUSH(carried, n_carried, w);
	}
	if (n_carried) {
		fe_name_table srt = {0};
		for (size_t i = 0; i < n_carried; i++)
			fe_name_set(&srt, carried[i], TRUE_);
		carried = fe_sorted_set(&srt, &n_carried);
	}

	/* the (U) runs in order (their diagnostics and bindings are dropped) */
	fe_name_table entry = fe_copy_env(&pre);
	fe_name_table *entries = NULL, *exits = NULL;
	size_t n_entries = 0, n_exits = 0;
	fe_ctx_snapshot snap = save(c);
	for (int64_t j = 0; j < n_count; j++) {
		T_PUSH(entries, n_entries, entry);
		if (bound)
			T_PUSH(exits, n_exits, entry);
		fe_name_table end, *brks;
		size_t nb;
		loop_body(c, body_n.v, body_n.n, &entry, iv_name, fe_point(intv_from_i64(j)), n_count, &end, &brks, &nb);
		restore(c, &snap);
		for (size_t k = 0; k < nb; k++)
			T_PUSH(exits, n_exits, brks[k]);
		entry = keep_keys(&end, &pre);
	}
	T_PUSH(exits, n_exits, entry);
	fe_name_table all = fe_copy_env(&pre);
	if (n_entries > 0) {
		all = entries[0];
		for (size_t k = 1; k < n_entries; k++)
			all = fe_join_env(&all, &entries[k]);
	}
	fe_ival ivr = n_count == 0 ? fe_point(intv_from_i64(0)) : fe_iv(intv_from_i64(0), intv_from_i64(n_count - 1));
	fe_name_table end2, *brks2;
	size_t nb2;
	fe_stmts ss = loop_body(c, body_n.v, body_n.n, &all, iv_name, ivr, n_count, &end2, &brks2, &nb2);
	fe_name_table post = exits[0];
	for (size_t k = 1; k < n_exits; k++)
		post = fe_join_env(&post, &exits[k]);
	c->env = keep_keys(&post, &pre);
	for (size_t i = 0; i < writes.n; i++) {
		sr_str w = writes.e[i].key;
		if (!fe_name_has(&pre, w) && !sr_eq(w, iv_name))
			fe_name_set(&c->block_locals, w, TRUE_);
	}
	fe_stmt s = fe_stmt_new("loop");
	s.count = n_count;
	s.bound = bound;
	s.clamp = clamp;
	s.incl = incl && bound;
	s.var = iv_name;
	s.carried = carried;
	s.n_carried = n_carried;
	s.carried_nil = n_carried == 0;
	s.then = ss;
	s.pos = fe_cpos(c, n);
	*out = s;
	return 1;
}

/* escape (loop.go) */
int fe_escape(fe_prog_ctx *c, const sr_node *n, int last, fe_stmt *out)
{
	const char *kw = t_is(n, "BreakNode") ? "break" : t_is(n, "NextNode") ? "next" : "";
	if (c->n_loops == 0) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n, "`%S` outside a loop is not accepted on the eBPF side", kw);
		return 0;
	}
	if (t_ref(c->a, n, "arguments")) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n,
			"`%S` with a value is not accepted — the value of a loop is not used on the eBPF side; write a bare `%S` and keep the value in a local", kw,
			kw);
		return 0;
	}
	if (fe_streq(c->esc_arm, "window")) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n,
			"`%S` inside a packet window's `if w` arm is not accepted (bpf-mlir leaves a loop only from an if / present arm) — set a local in the arm and `%S if` after it",
			kw, kw);
		return 0;
	}
	if (c->esc_arm.n == 0) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n,
			"an unconditional `%S` directly in the loop body makes the rest of the body dead code — write `%S if cond`", kw, kw);
		return 0;
	}
	if (!last) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n, "`%S` must be the last statement of its arm — the statements after it are dead code", kw);
		return 0;
	}
	fe_loop_frame *f = c->loops[c->n_loops - 1];
	fe_name_table e = fe_copy_env(&c->env);
	if (kw[0] == 'b')
		T_PUSH(f->breaks, f->n_breaks, e);
	else
		T_PUSH(f->nexts, f->n_nexts, e);
	fe_stmt s = fe_stmt_new(kw);
	s.pos = fe_cpos(c, n);
	*out = s;
	return 1;
}

/* escapes (loop.go) */
int fe_escapes(const fe_stmts *ss)
{
	return ss->n > 0 && (fe_streq(ss->v[ss->n - 1].kind, "break") || fe_streq(ss->v[ss->n - 1].kind, "next"));
}

/* ---- guard.go ---- */

/* guardOf (guard.go) */
static const sr_node *guard_of(fe_prog_ctx *c, const sr_node *n)
{
	const sr_ast *a = c->a;
	if (!t_is(n, "IfNode") && !t_is(n, "UnlessNode"))
		return NULL;
	if ((t_is(n, "IfNode") && t_ref(a, n, "subsequent")) || (t_is(n, "UnlessNode") && t_ref(a, n, "else_clause")))
		return NULL;
	const sr_node *st = t_ref(a, n, "statements");
	if (!st || t_arr(a, st, "body").n != 1)
		return NULL;
	const sr_node *r = t_arr(a, st, "body").v[0];
	if (!t_is(r, "ReturnNode"))
		return NULL;
	return r;
}

static void stmts_append(fe_stmts *out, fe_stmt s) { fe_stmts_push(out, s); }

/* guardStmts (guard.go) */
fe_stmts fe_guard_stmts(fe_prog_ctx *c, const sr_node *const *ns, size_t nn)
{
	const sr_ast *a = c->a;
	for (size_t i = 0; i < nn; i++) {
		const sr_node *n = ns[i];
		const sr_node *r = guard_of(c, n);
		if (!r)
			continue;
		fe_stmts out = fe_ctx_stmts(c, ns, i, (sr_str){0});
		int created;
		*sr_imap_slot(&c->guard_returns, r->id, &created) = TRUE_;
		t_nodes as = {0};
		const sr_node *args = t_ref(a, r, "arguments");
		if (args)
			as = t_arr(a, args, "arguments");
		sr_str kind = c->prog->kind;
		fe_name_table table = fe_verdicts_of(kind);
		if (as.n != 1) {
			fe_cadd(c, FE_REJECTED, FE_SB008, r, "a guard `return` must return one %s (%s)", fe_verdict_want(kind, S("BPF::XDP_* constant")),
				fe_verdict_want(kind, S("`return BPF::XDP_DROP if cond`")));
			return out;
		}
		sr_str cn = t_const_name(a, as.v[0]);
		sr_str v = {0};
		if (fe_streq(kind, "fmod_ret") && fe_is_fmod_return(c, as.v[0])) {
			int ok;
			bigint *lit = fe_fmod_guard_value(c, r, as.v[0], &ok);
			if (!ok)
				return out;
			if (c->prog->fmod_guard && bigint_cmp(c->prog->fmod_guard, lit) != 0) {
				fe_cadd(c, FE_REJECTED, FE_SB008, r,
					"the early returns return BPF.fmod_return(%B) and BPF.fmod_return(%B) — the terminal arith.select chooses between only two values (the early one and the last one), so every guard returns the same value",
					(const bigint *)c->prog->fmod_guard, (const bigint *)lit);
				return out;
			}
			c->prog->fmod_guard = lit;
			v = S("value");
		} else {
			const sr_str *tv = NULL;
			if (cn.n >= 5 && memcmp(cn.p, "BPF::", 5) == 0)
				tv = fe_name_get(&table, (sr_str){cn.p + 5, cn.n - 5});
			if (!t_is(as.v[0], "ConstantPathNode") || !tv || tv->n == 0) {
				fe_cadd(c, FE_REJECTED, FE_SB008, r, "a guard `return` must return one %s, got %s",
					fe_verdict_want(kind, S("BPF::XDP_* constant")), as.v[0]->type);
				return out;
			}
			v = *tv;
		}
		if (c->prog->guard_verdict.n && !sr_eq(c->prog->guard_verdict, v)) {
			fe_cadd(c, FE_REJECTED, FE_SB008, r,
				"the early returns return %s and %s — bpf-mlir's ebpf.verdict.if chooses between only two verdicts (the early one and the last one), so every guard returns the same verdict",
				c->prog->guard_verdict, v);
			return out;
		}
		c->prog->guard_verdict = v;
		fe_expr *cond = fe_cond(c, t_ref(a, n, "predicate"), (sr_str){0});
		if (!cond)
			return out;
		if (t_is(n, "UnlessNode")) {
			fe_expr *nc = fe_expr_new("not", cond->pos);
			fe_expr_args(nc, &cond, 1);
			nc->bool_ = 1;
			cond = nc;
		}
		fe_name_table pre = c->env;
		c->env = fe_narrow_env(&pre, cond, 0);
		fe_stmts rest = fe_guard_stmts(c, ns + i + 1, nn - i - 1);
		fe_stmt s = fe_stmt_new("guard");
		s.cond = cond;
		s.else_ = rest;
		s.op = v;
		s.pos = fe_cpos(c, n);
		stmts_append(&out, s);
		return out;
	}
	return fe_ctx_stmts(c, ns, nn, (sr_str){0});
}
