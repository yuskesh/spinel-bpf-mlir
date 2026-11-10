/* prog2.c — internal/frontend/program.go, part B: mapCall, lookupCheck, inIf, verdict,
 * rejectMidReturns, condAssign, literalArg, windowCheck, windowRead, readsBad, inSkippedIf, inRebindIf, verdictWant, ctxUse,
 * tracingRead, verdictKindText, verdictReturns, ctxStore, isAdjustPkt and adjustPkt; and analyze.go's verdict tables. */
#include "core.h"

#include <stdlib.h>
#include <string.h>

#define S(x) sr_cstr(x)

/* ---- analyze.go xdpVerdicts, tcVerdicts, sfVerdicts, cgVerdicts, nfVerdicts, flowVerdicts, skVerdicts, fmodVerdicts,
 * verdictsOf, verdictKindOf verdict tables ---- */
static const char *const xdp_v[][2] = {{"XDP_ABORTED", "aborted"}, {"XDP_DROP", "drop"}, {"XDP_PASS", "pass"}, {"XDP_TX", "tx"}, {NULL, NULL}};
static const char *const tc_v[][2] = {{"TC_PASS", "pass"}, {"TC_DROP", "drop"}, {NULL, NULL}};
static const char *const sf_v[][2] = {{"SF_KEEP", "keep"}, {"SF_DROP", "drop"}, {NULL, NULL}};
static const char *const cg_v[][2] = {{"CG_ALLOW", "allow"}, {"CG_DENY", "deny"}, {NULL, NULL}};
static const char *const nf_v[][2] = {{"NF_ACCEPT", "accept"}, {"NF_DROP", "drop"}, {NULL, NULL}};
static const char *const flow_v[][2] = {{"FLOW_OK", "ok"}, {"FLOW_DROP", "drop"}, {"FLOW_CONTINUE", "flow_dissector_continue"}, {NULL, NULL}};
static const char *const sk_v[][2] = {{"SK_PASS", "pass"}, {"SK_DROP", "drop"}, {NULL, NULL}};
static const char *const fmod_v[][2] = {{"FMOD_CALL", "done"}, {NULL, NULL}};

static const struct {
	const char *kind;
	const char *const (*t)[2];
} verdict_tables[] = {{"xdp", xdp_v},	      {"sched_cls", tc_v},	{"socket_filter", sf_v}, {"cgroup_skb", cg_v},
		      {"netfilter", nf_v},    {"flow_dissector", flow_v}, {"sk_lookup", sk_v},	 {"fmod_ret", fmod_v}};

static const char *const (*table_of(sr_str kind))[2]
{
	for (size_t i = 0; i < sizeof verdict_tables / sizeof verdict_tables[0]; i++)
		if (fe_streq(kind, verdict_tables[i].kind))
			return verdict_tables[i].t;
	return NULL;
}

static const char *table_get(const char *const (*t)[2], sr_str name)
{
	if (!t)
		return NULL;
	for (size_t i = 0; t[i][0]; i++)
		if (fe_streq(name, t[i][0]))
			return t[i][1];
	return NULL;
}

fe_name_table fe_verdicts_of(sr_str kind)
{
	fe_name_table out = {0};
	const char *const (*t)[2] = table_of(kind);
	if (!t)
		return out;
	for (size_t i = 0; t[i][0]; i++) {
		sr_str *v = sr_alloc(sizeof *v);
		*v = S(t[i][1]);
		fe_name_set(&out, S(t[i][0]), v);
	}
	return out;
}

/* verdictKindOf (analyze.go) */
sr_str fe_verdict_kind_of(sr_str cn)
{
	if (cn.n <= 5 || memcmp(cn.p, "BPF::", 5) != 0)
		return (sr_str){0};
	sr_str rest = {cn.p + 5, cn.n - 5};
	for (size_t i = 0; i < sizeof verdict_tables / sizeof verdict_tables[0]; i++)
		if (table_get(verdict_tables[i].t, rest))
			return S(verdict_tables[i].kind);
	return (sr_str){0};
}

/* ---- AST parents ---- */
static int parent_of(const sr_ast *a, int64_t id, int64_t *p)
{
	const int64_t *v = sr_imap_get(&a->parent, id);
	if (!v)
		return 0;
	*p = *v;
	return 1;
}

static const sr_node *parent_node(const sr_ast *a, const sr_node *x)
{
	int64_t p = 0;
	parent_of(a, x->id, &p); /* Go reads the zero id when there is no parent */
	return t_node(a, p);
}

/* inIf (program.go) */
int fe_in_if_of(const sr_ast *a, const sr_node *x, const sr_node *ifn)
{
	const sr_node *st = t_ref(a, ifn, "statements");
	for (int64_t p = x->id;;) {
		int64_t pid;
		if (!parent_of(a, p, &pid))
			return 0;
		if (st && pid == st->id)
			return 1;
		if (pid == ifn->id)
			return 0;
		p = pid;
	}
}

/* inSkippedIf (program.go) */
static int in_skipped_if(fe_prog_ctx *c, const sr_node *x)
{
	int64_t p;
	for (int ok = parent_of(c->a, x->id, &p); ok; ok = parent_of(c->a, p, &p))
		if (sr_imap_get(&c->skip_ifs, p))
			return 1;
	return 0;
}

/* inRebindIf (program.go) */
static int in_rebind_if(fe_prog_ctx *c, const sr_node *x, sr_str name, const sr_node *w)
{
	const sr_ast *a = c->a;
	int64_t p;
	for (int ok = parent_of(a, x->id, &p); ok; ok = parent_of(a, p, &p)) {
		const sr_node *ifn = t_node(a, p);
		if (!ifn || !t_is(ifn, "IfNode") || !fe_is_var_read(c, t_ref(a, ifn, "predicate"), name))
			continue;
		const sr_node *st = parent_node(a, ifn);
		if (!st || !t_is(st, "StatementsNode"))
			continue;
		t_nodes body = t_arr(a, st, "body");
		for (size_t i = 1; i < body.n; i++)
			if (body.v[i] == ifn && t_is(body.v[i - 1], "LocalVariableWriteNode") && sr_eq(t_str(body.v[i - 1], "name"), name) &&
			    body.v[i - 1] != w)
				return 1;
	}
	return 0;
}

/* ---- mapCall (program.go) ---- */
typedef struct {
	fe_map_decl *m;
	int update;
} rmw_msg;

static sr_str rmw_text(void *u, sr_str ref)
{
	rmw_msg *r = u;
	sr_buf b = {0};
	if (!r->update) {
		sr_puts(&b, "`");
		sr_putstr(&b, r->m->name);
		sr_puts(&b, ".atomic_add` adds a value read from the same entry (`");
		sr_putstr(&b, ref);
		sr_puts(&b, ".load`) — concurrent CPUs interleave the read and the add; use a delta that does not read the map (keys must be different literals to accept this form)");
	} else {
		sr_puts(&b, "`");
		sr_putstr(&b, r->m->name);
		sr_puts(&b, ".update` stores a value read from the same map (`");
		sr_putstr(&b, ref);
		sr_puts(&b, ".load`) — concurrent CPUs lose updates; use `");
		sr_putstr(&b, r->m->name);
		sr_puts(&b, ".atomic_add` (keys must be different literals to accept this form)");
	}
	return sr_bufstr(&b);
}

static int is_lpm(const fe_map_decl *m) { return fe_streq(m->kind, "lpm_trie"); }

static int ctx_store(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out);

int fe_map_call(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out)
{
	const sr_ast *a = c->a;
	sr_str name = t_str(n, "name");
	const sr_node *recv = t_ref(a, n, "receiver");
	if (recv && t_is(recv, "ConstantReadNode")) {
		fe_global_decl *g = fe_name_get(&c->z->top->globals, t_str(recv, "name"));
		if (g) {
			int handled;
			t_nodes gas = t_args(a, n);
			int gok = fe_global_stmt(c, n, g, gas.v, gas.n, ref_var, out, &handled); /* a Global's set / an ExitInfo */
			if (handled)
				return gok;
			if (fe_streq(name, "add")) {
				t_nodes as = t_args(a, n);
				return fe_global_add(c, n, g, as.v, as.n, ref_var, out);
			}
			fe_cadd(c, FE_REJECTED, FE_SB029, n,
				"a bare `%s.%s` statement — a global is read as `%s.value` in an expression, and a Counter adds with `%s.add(d)`",
				g->const_name, name, g->const_name, g->const_name);
			return 0;
		}
		if (fe_name_get(&c->z->top->bad_globals, t_str(recv, "name")))
			return 0;
	}
	if (!fe_has_packet(c->prog->kind) && fe_is_var_read(c, recv, c->param)) {
		fe_cadd(c, FE_REJECTED, FE_SB028, n, "a bare `%s.%s` statement — the %s context is read only as a value (%S)", c->param, name,
			c->prog->kind, fe_ctx_reads(c->prog->kind));
		return 0;
	}
	if (fe_streq(c->prog->kind, "flow_dissector") && fe_streq(name, "set_key") && fe_is_var_read(c, recv, c->param))
		return fe_flow_key_store(c, n, ref_var, out);
	if (fe_streq(c->prog->kind, "sched_cls") && fe_streq(name, "mark=") && fe_is_var_read(c, recv, c->param))
		return ctx_store(c, n, ref_var, out);
	if (fe_reads_bad(c, n))
		return 0;
	sr_str cn = t_const_name(a, recv);
	fe_map_decl *dm = fe_name_get(&c->z->top->maps, cn);
	if (dm && is_lpm(dm) && !fe_streq(name, "lookup") && !fe_streq(name, "check") && !fe_in_operators(name)) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n,
			"`%s.%s` is not accepted — an lpm_trie is read-only on the eBPF side (look it up with `p = %s.lookup(a0, a1, a2, a3)` then `if p`; user space writes it with `obj.lpm_put`)",
			dm->const_name, name, dm->const_name);
		return 0;
	}
	if (!fe_streq(name, "atomic_add") && !fe_streq(name, "update")) {
		if (fe_streq(name, "lookup"))
			fe_cadd(c, FE_REJECTED, FE_SB005, n, "`lookup` must be assigned to a local and checked with `if` (`p = M.lookup(k)` then `if p`)");
		else if (fe_streq(name, "check"))
			fe_cadd(c, FE_REJECTED, FE_SB005, n,
				"`check` must be assigned to a local and checked with `if` (`w = %s.check(off, len)` then `if w` — no block form)", c->param);
		else if (fe_in_operators(name))
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "a bare `%s` expression statement is not accepted", name);
		else
			fe_cadd(c, FE_REJECTED, FE_SB002, n, "call `%s` is not accepted on the eBPF side", name);
		return 0;
	}
	if (dm && fe_map_is_hash(dm) && fe_streq(name, "atomic_add")) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n,
			"`%s.atomic_add(k, d)` is not accepted on a hash map — a missing key makes it do nothing silently; use `st = %s.add_or_init(k, d)` (adds, or creates the entry), or `p.atomic_add(d)` inside `if p` after `p = %s.lookup(k)`",
			dm->const_name, dm->const_name, dm->const_name);
		return 0;
	}
	if (fe_name_get(&c->z->top->bad_hash, cn) && fe_streq(name, "atomic_add"))
		return 0;
	if (dm && dm->record && fe_streq(name, "atomic_add")) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n,
			"`%s.atomic_add` is not accepted on a record map — add to a member with `p = %s.lookup(k)`, `if p`, `p.atomic_add(:member, d)`",
			dm->const_name, dm->const_name);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return 0;
	sr_str want_c = S("ArrayMap");
	if (dm)
		want_c = fe_map_class_name(dm);
	sr_str want = t_cat(t_cat(want_c, S("#")), name);
	if (!sr_eq(callee, want) && !(fe_streq(want_c, "ArrayMap") && sr_eq(callee, t_cat(S("RecordMap#"), name)))) {
		fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s` resolves to %s, not BPF::%s#%s", name, callee, want_c, name);
		return 0;
	}
	fe_map_decl *m = fe_map_of(c, recv, n);
	t_nodes as = t_args(a, n);
	if (!m)
		return 0;
	if (m->record)
		return fe_record_update(c, n, name, m, as.v, as.n, ref_var, out);
	const char *role = fe_streq(name, "atomic_add") ? "delta" : "value";
	if (as.n != 2 || t_ref(a, n, "block")) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "`%s` takes exactly two arguments (key, %S)", name, role);
		return 0;
	}
	fe_expr *k = fe_ctx_key(c, as.v[0], m, ref_var);
	rmw_msg rm = {m, fe_streq(name, "update")};
	if (fe_streq(name, "atomic_add") && fe_rmw_first(c, n, as.v[1], m, k, rmw_text, &rm))
		return 0;
	if (fe_streq(name, "update") && fe_rmw_first(c, n, as.v[1], m, k, rmw_text, &rm))
		return 0;
	fe_expr *v = fe_ctx_value(c, as.v[1], m, ref_var, S(role));
	if (!k || !v)
		return 0;
	{
		int rok;
		sr_str ref = fe_reads_map(v, m, &rok);
		if (rok && fe_streq(name, "update") && !fe_exempt(c, m)) {
			fe_expr *lk = fe_name_get(&c->ref_key, ref);
			if (!lk || !fe_streq(lk->kind, "lit") || !fe_streq(k->kind, "lit") || bigint_cmp(lk->lit, k->lit) == 0) {
				fe_cadd(c, FE_REJECTED, FE_SB019, n,
					"`%s.update` stores a value read from the same map (`%s.load`) — concurrent CPUs lose updates; use `%s.atomic_add` (keys must be different literals to accept this form)",
					m->name, ref, m->name);
				return 0;
			}
		}
	}
	fe_stmt s = fe_stmt_new("");
	s.kind = name;
	s.map = m;
	s.key = k;
	s.value = v;
	s.pos = fe_cpos(c, n);
	*out = s;
	return 1;
}

/* ---- lookupCheck (program.go) ---- */
typedef struct {
	fe_prog_ctx *c;
	sr_str name;
	const sr_node *w, *ifn;
	fe_map_decl *m;
} lookup_walk;

static int has_prefix(sr_str s, const char *p)
{
	size_t b = strlen(p);
	return s.n >= b && memcmp(s.p, p, b) == 0;
}
static int has_suffix(sr_str s, const char *x)
{
	size_t b = strlen(x);
	return s.n >= b && memcmp(s.p + s.n - b, x, b) == 0;
}

static sr_str trim_eq(sr_str s)
{
	if (s.n && s.p[s.n - 1] == '=')
		s.n--;
	return s;
}

static int lookup_walk_fn(void *u, const sr_node *x)
{
	lookup_walk *lw = u;
	fe_prog_ctx *c = lw->c;
	const sr_ast *a = c->a;
	sr_str name = lw->name;
	if (!t_is(x, "LocalVariableReadNode") || !sr_eq(t_str(x, "name"), name))
		return 1;
	if (x == t_ref(a, lw->ifn, "predicate") || in_skipped_if(c, x) || in_rebind_if(c, x, name, lw->w))
		return 1;
	const sr_node *parent = parent_node(a, x);
	if (fe_borrow_arg_use(c, x) && fe_in_if_of(a, x, lw->ifn))
		return 1;
	if (lw->m->record) {
		if (parent && t_is(parent, "CallNode") && t_ref(a, parent, "receiver") == x && fe_in_if_of(a, parent, lw->ifn)) {
			sr_str pn = t_str(parent, "name");
			if (fe_streq(pn, "atomic_add"))
				return 1;
			const sr_node *gp = parent_node(a, parent);
			if (fe_streq(pn, "load") && gp && t_is(gp, "CallNode") && t_ref(a, gp, "receiver") == parent &&
			    fe_record_decl_field(lw->m->record, trim_eq(t_str(gp, "name"))))
				return 1;
			if (fe_streq(pn, "load") && gp && has_prefix(gp->type, "Call") && has_suffix(gp->type, "WriteNode") &&
			    t_ref(a, gp, "receiver") == parent)
				return 1;
			if (fe_streq(pn, "load") && gp && t_is(gp, "CallNode") && t_ref(a, gp, "receiver") == parent && fe_member_like(t_str(gp, "name")))
				return 1;
		}
		fe_cadd(c, FE_REJECTED, FE_SB005, x,
			"`%s` may be read only as `if %s`, `%s.load.<member>` / `%s.load.<member> = e` and `%s.atomic_add(:member, d)` inside it — `%s.load` is not a value (no local, dup, comparison or argument: the kernel side writes the map entry directly)",
			name, name, name, name, name, name);
		return 1;
	}
	if (parent && t_is(parent, "CallNode") && (fe_streq(t_str(parent, "name"), "load") || fe_streq(t_str(parent, "name"), "atomic_add")) &&
	    t_ref(a, parent, "receiver") == x && fe_in_if_of(a, parent, lw->ifn))
		return 1;
	fe_cadd(c, FE_REJECTED, FE_SB005, x, "`%s` may be read only as `if %s` and as `%s.load` / `%s.atomic_add(d)` inside it", name, name, name,
		name);
	return 1;
}

static t_nodes arm_body(const sr_ast *a, const sr_node *n)
{
	t_nodes out = {0};
	const sr_node *st = t_ref(a, n, "statements");
	if (st)
		out = t_arr(a, st, "body");
	return out;
}

int fe_lookup_check(fe_prog_ctx *c, const sr_node *w, const sr_node *ifn, sr_str outer_ref, fe_stmt *out)
{
	const sr_ast *a = c->a;
	sr_str name = t_str(w, "name");
	const sr_node *call = t_ref(a, w, "value");
	if (fe_name_has(&c->refs, name)) {
		fe_cadd(c, FE_REJECTED, FE_SB005, w, "`%s` is assigned twice — a lookup result is bound once", name);
		return 0;
	}
	if (fe_name_has(&c->env, name) || sr_eq(name, c->param) || fe_name_get(&c->wins, name)) {
		fe_cadd(c, FE_REJECTED, FE_SB005, w, "`%s` is already a local — a lookup result needs a fresh name", name);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, call, &ok);
	if (!ok)
		return 0;
	sr_str map_t = S("ArrayMap");
	const char *ref_t = "MapRef";
	sr_str cn = t_const_name(a, t_ref(a, call, "receiver"));
	fe_map_decl *dm = fe_name_get(&c->z->top->maps, cn);
	if (dm) {
		map_t = fe_map_class_name(dm);
		if (dm->record)
			ref_t = "RecordRef";
	}
	if (!dm && fe_name_get(&c->z->top->bad_maps, cn))
		return 0;
	if (fe_streq(callee, "RecordMap#lookup") && !fe_streq(map_t, "RecordMap"))
		return 0;
	if (!sr_eq(callee, t_cat(map_t, S("#lookup")))) {
		fe_cadd(c, FE_REJECTED, FE_SB011, call, "`lookup` resolves to %s, not BPF::%s#lookup", callee, map_t);
		return 0;
	}
	fe_map_decl *m = fe_map_of(c, t_ref(a, call, "receiver"), call);
	t_nodes as = t_args(a, call);
	if (!m)
		return 0;
	if (is_lpm(m) && as.n != 4) {
		fe_lpm_key(c, call, m, as.v, as.n, outer_ref);
		return 0;
	}
	if (!is_lpm(m) && as.n != 1) {
		fe_cadd(c, FE_REJECTED, FE_SB002, call, "`lookup` takes exactly one argument (key)");
		return 0;
	}
	if (!fe_typed(c, w) || !fe_typed(c, t_ref(a, ifn, "predicate")))
		return 0;
	if (!fe_streq(fe_rbs(c, w), ref_t)) {
		fe_cadd(c, FE_REJECTED, FE_SB005, w, "`%s` is typed %q, not BPF::%S", name, fe_rbs(c, w), ref_t);
		return 0;
	}
	fe_expr *k = is_lpm(m) ? fe_lpm_key(c, call, m, as.v, as.n, outer_ref) : fe_ctx_key(c, as.v[0], m, outer_ref);
	if (!k)
		return 0;
	fe_name_set(&c->refs, name, (void *)w);
	fe_name_set(&c->ref_map, name, m);
	fe_name_set(&c->ref_key, name, k);
	fe_stmt s = fe_stmt_new("lookup_check");
	s.map = m;
	s.key = k;
	s.var = name;
	s.pos = fe_cpos(c, w);
	s.if_pos = fe_cpos(c, ifn);
	t_nodes then = arm_body(a, ifn);
	fe_name_table pre = c->env;
	c->env = fe_copy_env(&pre);
	sr_str saved_arm = c->esc_arm;
	if (!fe_streq(c->esc_arm, "window"))
		c->esc_arm = S("if");
	s.then = fe_ctx_stmts(c, then.v, then.n, name);
	fe_name_table then_env = c->env;
	c->env = fe_copy_env(&pre);
	const sr_node *sub = t_ref(a, ifn, "subsequent");
	if (sub) {
		if (!t_is(sub, "ElseNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB005, sub, "`elsif` is not accepted after `if %s`", name);
			c->esc_arm = saved_arm;
			return 0;
		}
		t_nodes els = arm_body(a, sub);
		s.else_ = fe_ctx_stmts(c, els.v, els.n, outer_ref);
	}
	c->env = fe_join_arms(&pre, &then_env, &c->env, fe_escapes(&s.then), fe_escapes(&s.else_));
	lookup_walk lw = {c, name, w, ifn, m};
	t_walk(a, c->def, (int (*)(void *, const sr_node *))lookup_walk_fn, &lw);
	c->esc_arm = saved_arm;
	*out = s;
	return 1;
}

/* ---- verdict (program.go) and rejectMidReturns (program.go) ---- */
typedef struct {
	fe_prog_ctx *c;
	const sr_node *n;
} mid_walk;

static int mid_walk_fn(void *u, const sr_node *x)
{
	mid_walk *m = u;
	fe_prog_ctx *c = m->c;
	if (t_is(x, "ReturnNode") && x != m->n && !sr_imap_get(&c->guard_returns, x->id))
		fe_cadd(c, FE_REJECTED, FE_SB008, x, "`return` is accepted only as the last statement or as a top-level guard %s",
			fe_verdict_want(c->prog->kind, S("`return BPF::XDP_X if cond`")));
	return 1;
}

void fe_reject_mid_returns(fe_prog_ctx *c, const sr_node *n)
{
	mid_walk m = {c, n};
	t_walk(c->a, c->def, mid_walk_fn, &m);
}

void fe_verdict_of(fe_prog_ctx *c, const sr_node *n)
{
	const sr_ast *a = c->a;
	const sr_node *v = n;
	if (t_is(n, "ReturnNode")) {
		t_nodes as = {0};
		const sr_node *args = t_ref(a, n, "arguments");
		if (args)
			as = t_arr(a, args, "arguments");
		if (as.n != 1) {
			fe_cadd(c, FE_REJECTED, FE_SB008, n, "`return` must return one %s", fe_verdict_want(c->prog->kind, S("BPF::XDP_* constant")));
			return;
		}
		v = as.v[0];
	}
	if (fe_is_fmod_return(c, v)) {
		fe_fmod_verdict(c, n, v);
		fe_reject_mid_returns(c, n);
		return;
	}
	if (t_is(v, "CallNode") && fe_streq(t_str(v, "name"), "redirect")) {
		fe_redirect_verdict(c, n, v);
		return;
	}
	sr_str cn = t_const_name(a, v);
	const char *const (*table)[2] = table_of(c->prog->kind);
	const char *vv = NULL;
	if (cn.n >= 5 && memcmp(cn.p, "BPF::", 5) == 0)
		vv = table_get(table, (sr_str){cn.p + 5, cn.n - 5});
	if (!t_is(v, "ConstantPathNode") || !vv || !*vv) {
		fe_cadd(c, FE_REJECTED, FE_SB008, n, "the program must end with %s, got %s",
			fe_verdict_want(c->prog->kind, S("an XDP verdict (BPF::XDP_ABORTED / XDP_DROP / XDP_PASS / XDP_TX)")), n->type);
		return;
	}
	if (!fe_typed(c, v))
		return;
	if (!fe_streq(fe_rbs(c, v), "Integer")) {
		fe_cadd(c, FE_REJECTED, FE_SB011, v, "%s is typed %q, not the Integer constant of ruby/lib/bpf.rb", cn, fe_rbs(c, v));
		return;
	}
	c->prog->verdict = S(vv);
	c->prog->verdict_const = (sr_str){cn.p + 5, cn.n - 5};
	c->prog->verdict_pos = fe_cpos(c, n);
	fe_reject_mid_returns(c, n);
}

/* condAssign (program.go) */
const sr_node *fe_cond_assign(const sr_ast *a, const sr_node *n)
{
	while (n && t_is(n, "ParenthesesNode")) {
		const sr_node *b = t_ref(a, n, "body");
		size_t cnt = 0;
		if (b)
			fe_node_arr(b, "body", &cnt, &(int){0});
		if (!b || !t_is(b, "StatementsNode") || cnt != 1)
			return NULL;
		t_nodes bs = t_arr(a, b, "body");
		if (bs.n == 0) {
			t_nil_panic = 1;
			return NULL;
		}
		n = bs.v[0];
	}
	if (n && t_is(n, "LocalVariableWriteNode"))
		return n;
	return NULL;
}

/* literalArg (program.go) */
bigint *fe_literal_arg(fe_prog_ctx *c, const sr_node *n, const char *what)
{
	if (!n || !t_is(n, "IntegerNode")) {
		fe_cadd(c, FE_REJECTED, FE_SB006, n, "the %S must be an integer literal", what);
		return NULL;
	}
	if (!fe_typed(c, n))
		return NULL;
	bigint *v = sr_alloc(sizeof *v);
	if (!fe_literal(c->z->z, c->a, n, v))
		return NULL;
	return v;
}

/* a *big.Int that the Go reads with Int64(): fail closed when it is not an int64 */
static int big_i64(fe_prog_ctx *c, const bigint *b, int64_t *v)
{
	if (!t_big_int64(b, v)) {
		fe_not_ported(c->z->z, "a literal beyond int64 read with Int64()");
		return 0;
	}
	return 1;
}

/* ---- windowCheck (program.go) ---- */
typedef struct {
	sr_str name;
	int64_t writes;
} writes_walk;

static int writes_walk_fn(void *u, const sr_node *x)
{
	writes_walk *w = u;
	if ((t_is(x, "LocalVariableWriteNode") || t_is(x, "LocalVariableOperatorWriteNode")) && sr_eq(t_str(x, "name"), w->name))
		w->writes++;
	return 1;
}

typedef struct {
	fe_prog_ctx *c;
	sr_str name;
	const sr_node *ifn;
} win_walk;

static int win_walk_fn(void *u, const sr_node *x)
{
	win_walk *ww = u;
	fe_prog_ctx *c = ww->c;
	const sr_ast *a = c->a;
	sr_str name = ww->name;
	if (!t_is(x, "LocalVariableReadNode") || !sr_eq(t_str(x, "name"), name))
		return 1;
	if (x == t_ref(a, ww->ifn, "predicate") || in_skipped_if(c, x))
		return 1;
	const sr_node *parent = parent_node(a, x);
	if (fe_borrow_arg_use(c, x) && fe_in_if_of(a, x, ww->ifn))
		return 1;
	if (parent && t_is(parent, "CallNode") && t_ref(a, parent, "receiver") == x && fe_in_if_of(a, parent, ww->ifn))
		return 1; /* a window read, or a method not in the table (the call's own check says SB002) */
	fe_cadd(c, FE_REJECTED, FE_SB005, x,
		"window `%s` may be read only as `if %s` and as `%s.u8(i)` / `be16` / `be32` / `le16` / `le32` inside it", name, name, name);
	return 1;
}

int fe_window_check(fe_prog_ctx *c, const sr_node *w, const sr_node *ifn, sr_str outer_ref, fe_stmt *out)
{
	const sr_ast *a = c->a;
	sr_str name = t_str(w, "name");
	const sr_node *call = t_ref(a, w, "value");
	if (fe_name_has(&c->wins, name) || fe_name_get(&c->refs, name)) {
		fe_cadd(c, FE_REJECTED, FE_SB005, w, "`%s` is assigned twice — a window is bound once", name);
		return 0;
	}
	if (fe_name_has(&c->env, name) || sr_eq(name, c->param)) {
		fe_cadd(c, FE_REJECTED, FE_SB005, w, "`%s` is already a local — a window needs a fresh name", name);
		return 0;
	}
	if (t_ref(a, call, "block")) {
		fe_cadd(c, FE_REJECTED, FE_SB005, call, "`check` takes no block — write `%s = %s.check(off, len)` then `if %s`", name, c->param, name);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, call, &ok);
	if (!ok)
		return 0;
	sr_str want = t_cat(S(t_ctx_class(fe_ctx_kind_of(c))), S("#check"));
	if (!sr_eq(callee, want)) {
		fe_cadd(c, FE_REJECTED, FE_SB011, call, "`check` resolves to %s, not BPF::%s", callee, want);
		return 0;
	}
	t_nodes as = t_args(a, call);
	if (as.n != 2) {
		fe_cadd(c, FE_REJECTED, FE_SB002, call, "`check` takes exactly two arguments (offset, length)");
		return 0;
	}
	if (!fe_typed(c, w) || !fe_typed(c, t_ref(a, ifn, "predicate")))
		return 0;
	if (!fe_streq(fe_rbs(c, w), "Window")) {
		writes_walk ww = {name, 0};
		t_walk(a, c->def, writes_walk_fn, &ww);
		int okf = 1;
		sr_str why = {0};
		if (ww.writes > 1)
			why = fe_cfmt(c->z->z, &okf,
				      " — `%s` is reassigned elsewhere in `%s` (%d assignments), which makes Spinel widen its type; a window is bound once",
				      name, c->name, ww.writes);
		if (!okf)
			return 0;
		fe_cadd(c, FE_REJECTED, FE_SB005, w, "`%s` is typed %q, not BPF::Window%s", name, fe_rbs(c, w), why);
		return 0;
	}
	bigint *nv = fe_literal_arg(c, as.v[1], "window length");
	if (!nv)
		return 0;
	int64_t n;
	if (!t_big_int64(nv, &n) || n < 1 || n > 65535) {
		fe_cadd(c, FE_REJECTED, FE_SB022, as.v[1], "the window length %B is outside [1, 65535]", (const bigint *)nv);
		return 0;
	}
	fe_expr *off = fe_ctx_expr(c, as.v[0], outer_ref);
	if (!off)
		return 0;
	if (off->bool_ || off->wide) {
		fe_cadd(c, FE_REJECTED, FE_SB001, as.v[0], "the window offset must be an Integer (not a bool, not an unnarrowed u64 value)");
		return 0;
	}
	int64_t hi = 65535 - n;
	if (!fe_iv_within(off->iv, intv_from_i64(0), intv_from_i64(hi))) {
		fe_cadd(c, FE_REJECTED, FE_SB023, as.v[0],
			"the window offset's range %I is not within [0, %d] (65535 − %d) — a negative offset does not count from the end of the packet (unlike Ruby's a[-1]) and would silently give nil, Ruby does not wrap, and a packet offset beyond 0xffff has no meaning; narrow it (e.g. `x & 0xFFF`)",
			off->iv, hi, n);
		return 0;
	}
	fe_win_info *info = sr_alloc(sizeof *info);
	info->len = n;
	fe_name_set(&c->wins, name, info);
	fe_stmt s = fe_stmt_new("window_check");
	s.var = name;
	s.off = off;
	s.len = n;
	s.pos = fe_cpos(c, w);
	s.if_pos = fe_cpos(c, ifn);
	t_nodes then = arm_body(a, ifn);
	fe_name_table pre = c->env;
	c->env = fe_copy_env(&pre);
	info->active = 1;
	sr_str saved_arm = c->esc_arm;
	c->esc_arm = S("window");
	s.then = fe_ctx_stmts(c, then.v, then.n, outer_ref);
	info->active = 0;
	fe_name_table then_env = c->env;
	c->env = fe_copy_env(&pre);
	const sr_node *sub = t_ref(a, ifn, "subsequent");
	if (sub) {
		if (!t_is(sub, "ElseNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB005, sub, "`elsif` is not accepted after `if %s`", name);
			c->esc_arm = saved_arm;
			return 0;
		}
		t_nodes els = arm_body(a, sub);
		s.else_ = fe_ctx_stmts(c, els.v, els.n, outer_ref);
	}
	c->env = fe_join_env(&then_env, &c->env);
	win_walk wk = {c, name, ifn};
	t_walk(a, c->def, win_walk_fn, &wk);
	c->esc_arm = saved_arm;
	*out = s;
	return 1;
}

/* windowRead (program.go) */
fe_expr *fe_window_read(fe_prog_ctx *c, const sr_node *n, const sr_node *recv, const sr_node *const *as, size_t n_as)
{
	sr_str name = t_str(n, "name");
	if (!recv || !t_is(recv, "LocalVariableReadNode") || !fe_name_get(&c->wins, t_str(recv, "name"))) {
		if (recv && fe_is_var_read(c, recv, c->param))
			fe_cadd(c, FE_REJECTED, FE_SB002, n,
				"the context has no `%s` — packet reads go through a checked window (`w = %s.check(off, len)`, `if w`, `w.%s(i)`)", name,
				c->param, name);
		else
			fe_cadd(c, FE_REJECTED, FE_SB002, n, "call `%s` is accepted only on a checked window", name);
		return NULL;
	}
	sr_str wn = t_str(recv, "name");
	fe_win_info *info = fe_name_get(&c->wins, wn);
	if (!info->active)
		return NULL;
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return NULL;
	if (!sr_eq(callee, t_cat(S("Window#"), name))) {
		fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s` resolves to %s, not BPF::Window#%s", name, callee, name);
		return NULL;
	}
	if (n_as != 1) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "`%s` takes exactly one argument (the index)", name);
		return NULL;
	}
	bigint *iv0 = fe_literal_arg(c, as[0], "window index");
	if (!iv0)
		return NULL;
	int64_t width = 0;
	fe_window_read_len(name, &width);
	int ok2;
	intv i0 = fe_intv_of_big(iv0, &ok2);
	if (!ok2) {
		fe_not_ported(c->z->z, "a window index beyond 128 bits");
		return NULL;
	}
	intv end = fe_iv_add1(i0, intv_from_i64(width));
	if (intv_sign(i0) < 0 || intv_cmp(end, intv_from_i64(info->len)) > 0) {
		char eb[48];
		fe_cadd(c, FE_REJECTED, FE_SB022, as[0], "`%s.%s(%B)` reads bytes [%B, %S) outside the window [0, %d)", wn, name, (const bigint *)iv0,
			(const bigint *)iv0, intv_string(end, eb), info->len);
		return NULL;
	}
	intv max;
	intv_lsh(intv_from_i64(1), (uint64_t)(8 * width), &max);
	max = fe_iv_sub1(max, intv_from_i64(1));
	fe_expr *e = fe_expr_new("wload", fe_cpos(c, n));
	e->op = name;
	e->ref = wn;
	e->idx = intv_int64(i0);
	e->len = info->len;
	e->iv = fe_iv(intv_from_i64(0), max);
	return e;
}

/* readsBad (program.go) */
typedef struct {
	fe_prog_ctx *c;
	int found;
} bad_walk;

static int bad_walk_fn(void *u, const sr_node *x)
{
	bad_walk *b = u;
	fe_prog_ctx *c = b->c;
	if (t_is(x, "LocalVariableReadNode")) {
		sr_str nm = t_str(x, "name");
		if (fe_name_get(&c->bad_bind, nm) || (fe_name_get(&c->poisoned, nm) && !fe_name_get(&c->env, nm)))
			b->found = 1;
	}
	return !b->found;
}

int fe_reads_bad(fe_prog_ctx *c, const sr_node *n)
{
	if (!n)
		return 0;
	bad_walk b = {c, 0};
	t_walk(c->a, n, bad_walk_fn, &b);
	return b.found;
}

/* verdictWant (program.go) */
sr_str fe_verdict_want(sr_str kind, sr_str xdp)
{
	int guard = fe_streq(xdp, "`return BPF::XDP_X if cond`") || fe_streq(xdp, "`return BPF::XDP_DROP if cond`");
	int cnst = fe_streq(xdp, "BPF::XDP_* constant");
	static const struct {
		const char *kind, *guard, *cnst, *other;
	} t[] = {
	    {"fmod_ret", "`return BPF.fmod_return(-1) if cond`", "BPF::FMOD_CALL or BPF.fmod_return(literal)",
	     "a named return value — BPF::FMOD_CALL (call the original function) or BPF.fmod_return(e) (e provably non-zero) — not an implicit last expression"},
	    {"socket_filter", "`return BPF::SF_DROP if cond`", "BPF::SF_* constant", "a socket_filter verdict (BPF::SF_KEEP / SF_DROP)"},
	    {"cgroup_skb", "`return BPF::CG_DENY if cond`", "BPF::CG_* constant", "a cgroup_skb verdict (BPF::CG_ALLOW / CG_DENY)"},
	    {"netfilter", "`return BPF::NF_DROP if cond`", "BPF::NF_* constant", "a netfilter verdict (BPF::NF_ACCEPT / NF_DROP)"},
	    {"flow_dissector", "`return BPF::FLOW_DROP if cond`", "BPF::FLOW_* constant",
	     "a flow_dissector verdict (BPF::FLOW_OK / FLOW_DROP / FLOW_CONTINUE)"},
	    {"sk_lookup", "`return BPF::SK_DROP if cond`", "BPF::SK_* constant", "an sk_lookup verdict (BPF::SK_PASS / SK_DROP)"},
	    {"sched_cls", "`return BPF::TC_DROP if cond`", "BPF::TC_* constant", "a sched_cls verdict (BPF::TC_PASS / TC_DROP)"},
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (fe_streq(kind, t[i].kind))
			return S(guard ? t[i].guard : cnst ? t[i].cnst : t[i].other);
	return xdp;
}

/* ctxUse (program.go) */
sr_str fe_ctx_use(sr_str kind, sr_str param)
{
	if (fe_has_packet(kind)) {
		sr_buf b = {0};
		sr_puts(&b, "`w = ");
		sr_putstr(&b, param);
		sr_puts(&b, ".check(off, len)` right before `if w`");
		return sr_bufstr(&b);
	}
	return S(fe_ctx_reads(kind));
}

/* tracingRead (program.go) */
static fe_record_field *typ(sr_str t)
{
	fe_record_field *f = sr_alloc(sizeof *f);
	int64_t bits = 0;
	int sg = 0;
	t_record_type(t, &bits, &sg);
	f->name = t;
	f->bits = bits;
	f->is_signed = sg;
	return f;
}

static fe_expr *mk(const char *k, fe_record_field *f, int64_t idx, fe_pos p)
{
	fe_expr *e = fe_expr_new(k, p);
	e->field = f;
	e->idx = idx;
	if (f->bits == 64 && !f->is_signed) {
		e->iv = fe_iv(intv_from_i64(0), fe_u64_max);
		e->wide = 1;
	} else {
		e->iv = fe_width_range(f->bits, f->is_signed);
	}
	return e;
}

static fe_record_field *named_field(const char *name, int64_t bits, int sg)
{
	fe_record_field *f = sr_alloc(sizeof *f);
	f->name = S(name);
	f->bits = bits;
	f->is_signed = sg;
	return f;
}

static fe_expr *ret_read(fe_prog_ctx *c, const sr_node *n, sr_str callee, size_t n_as, const char *want, const char *kind, int64_t idx,
			 fe_pos p)
{
	if (!fe_streq(callee, want) || n_as != 0) {
		sr_buf m = {0};
		sr_puts(&m, "`%s.ret` resolves to %q (with %d arguments), not BPF::");
		sr_puts(&m, want);
		fe_cadd(c, FE_REJECTED, FE_SB011, n, (const char *)sr_bufstr(&m).p, c->param, callee, (int64_t)n_as);
		return NULL;
	}
	return mk(kind, typ(c->prog->ret), idx, p);
}

fe_expr *fe_tracing_read(fe_prog_ctx *c, const sr_node *n, sr_str name, const sr_node *const *as, size_t n_as, fe_pos p)
{
	sr_str kind = c->prog->kind;
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return NULL;
	sr_str prm = c->param;
#define K(x) fe_streq(kind, x)
#define N(x) fe_streq(name, x)
	if ((K("socket_filter") && N("len")) || fe_ctx_field(kind, name)) {
		sr_str want = t_cat(t_cat(S(t_ctx_class(kind)), S("#")), name);
		if (!sr_eq(callee, want) || n_as != 0) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s.%s` resolves to %q (with %d arguments), not BPF::%s", prm, name, callee, (int64_t)n_as,
				want);
			return NULL;
		}
		fe_record_field *f = sr_alloc(sizeof *f);
		f->name = name;
		f->bits = 32;
		return mk("ctxfield", f, 0, p);
	}
	if (K("fexit") && N("ret"))
		return ret_read(c, n, callee, n_as, "FexitCtx#ret", "retval", c->prog->nargs, p);
	if (K("kretprobe") && N("ret"))
		return ret_read(c, n, callee, n_as, "KretprobeCtx#ret", "kretval", 0, p);
	if (K("uretprobe") && N("ret"))
		return ret_read(c, n, callee, n_as, "UretprobeCtx#ret", "kretval", 0, p);
	if ((K("ksyscall") && N("argv_arg")) || (K("tracepoint") && N("argv_field"))) {
		fe_cadd(c, FE_REJECTED, FE_SB028, n,
			"`%s.%s(…)` is accepted only as the third argument of `R.output_argv(S.new(…), :arg, %s.%s(…), :status, :index)` — an argv array is not a value on the eBPF side",
			prm, name, prm, name);
		return NULL;
	}
	if (K("ksyscall") && N("str_arg")) {
		fe_cadd(c, FE_REJECTED, FE_SB028, n,
			"`%s.str_arg(n)` is accepted only as the third argument of `R.output_str(S.new(…), :field, %s.str_arg(n), :status)` — a user string is not a value on the eBPF side",
			prm, prm);
		return NULL;
	}
	if (K("tracepoint") && N("copy")) {
		fe_cadd(c, FE_REJECTED, FE_SB028, n,
			"`%s.copy(:f)` (a byte array field) is not a value — it is accepted only as an array member's argument of `R.output(S.new(…))` or as `r.load.<member> = %s.copy(:f)` inside `if r` of a record map's lookup",
			prm, prm);
		return NULL;
	}
	if (K("tracepoint") && N("str_field")) {
		fe_cadd(c, FE_REJECTED, FE_SB028, n,
			"`%s.str_field(:f)` is accepted only as the third argument of `R.output_str(S.new(…), :field, %s.str_field(:f), :status)` — a user string is not a value on the eBPF side",
			prm, prm);
		return NULL;
	}
	if (K("tracepoint") && N("field")) {
		if (!fe_streq(callee, "TracepointCtx#field")) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s.field` resolves to %q, not BPF::TracepointCtx#field", prm, callee);
			return NULL;
		}
		if (n_as != 1 || !t_is(as[0], "SymbolNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB028, n, "`%s.field(:name)` takes one Symbol literal — a field declared in `BPF.tracepoint … fields:`",
				prm);
			return NULL;
		}
		sr_str fn = t_str(as[0], "value");
		for (size_t i = 0; i < c->prog->n_t_fields; i++) {
			fe_tp_field *f = &c->prog->t_fields[i];
			if (!sr_eq(f->name, fn))
				continue;
			if (fe_streq(f->type, "user_str")) {
				fe_cadd(c, FE_REJECTED, FE_SB028, n,
					"`%s.field(:%s)`: %s is declared :user_str — read the string with `%s.str_field(:%s)` as the third argument of `R.output_str`",
					prm, fn, fn, prm, fn);
				return NULL;
			}
			if (f->n > 0) {
				fe_cadd(c, FE_REJECTED, FE_SB028, n,
					"`%s.field(:%s)`: %s is declared as a byte array [:%s, %d] — copy it with `%s.copy(:%s)` into a `[:u8, %d]` member of the event",
					prm, fn, fn, f->type, f->n, prm, fn, f->n);
				return NULL;
			}
			if (fe_streq(f->type, "user_str_array")) {
				fe_cadd(c, FE_REJECTED, FE_SB028, n,
					"`%s.field(:%s)`: %s is declared :user_str_array — read its strings with `%s.argv_field(:%s)` as the third argument of `R.output_argv`",
					prm, fn, fn, prm, fn);
				return NULL;
			}
			fe_record_field *rf = typ(f->type);
			rf->name = f->name;
			return mk("tpfield", rf, f->offset, p);
		}
		fe_cadd(c, FE_REJECTED, FE_SB028, as[0],
			"`%s.field(:%s)`: %s is not declared in `BPF.tracepoint … fields:` (declare its offset and type from the tracefs format)", prm, fn,
			fn);
		return NULL;
	}
	if (K("raw_tp") && N("arg")) {
		if (!fe_streq(callee, "RawTpCtx#arg")) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s.arg` resolves to %q, not BPF::RawTpCtx#arg", prm, callee);
			return NULL;
		}
		if (n_as != 1 || !t_is(as[0], "IntegerNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB028, n, "`%s.arg(i)` takes one Integer literal i — the tracepoint's args index 0..11", prm);
			return NULL;
		}
		bigint *nb = sr_alloc(sizeof *nb);
		if (!fe_literal(c->z->z, c->a, as[0], nb))
			return NULL;
		int64_t v;
		if (!t_big_int64(nb, &v) || v < 0 || v > 11) {
			fe_cadd(c, FE_REJECTED, FE_SB028, as[0],
				"`%s.arg(%B)`: a raw_tp argument index is 0..11 (args[i] of bpf_raw_tracepoint_args — 0-origin, unlike the 1-origin register numbers of `BPF.kprobe … params:`)",
				prm, (const bigint *)nb);
			return NULL;
		}
		return mk("rawarg", typ(S("u64")), v, p);
	}
	if (K("kprobe") && N("read")) {
		fe_cadd(c, FE_REJECTED, FE_SB028, n,
			"`%s.read(n, offset, :type)` returns a value and a status — use it only as the statement `v, st = %s.read(…)` (the status is read later — a failed read is 0, like a real 0)",
			prm, prm);
		return NULL;
	}
	if ((K("kprobe") || K("ksyscall")) && N("arg")) {
		const char *want = K("kprobe") ? "KprobeCtx#arg" : "KsyscallCtx#arg";
		if (!fe_streq(callee, want)) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s.arg` resolves to %q, not BPF::%S", prm, callee, want);
			return NULL;
		}
		if (n_as != 1 || !t_is(as[0], "IntegerNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB028, n, "`%s.arg(n)` takes one Integer literal n — a declared parameter number", prm);
			return NULL;
		}
		bigint *nb = sr_alloc(sizeof *nb);
		if (!fe_literal(c->z->z, c->a, as[0], nb))
			return NULL;
		int64_t v;
		int is64 = t_big_int64(nb, &v);
		const bigint *B = nb;
		for (size_t i = 0; i < c->prog->n_params; i++) {
			fe_kparam *kp = &c->prog->params[i];
			if (!(is64 && kp->n == v))
				continue;
			if (fe_streq(kp->type, "ptr"))
				return mk("kparg", named_field("ptr", 64, 1), v, p);
			if (fe_streq(kp->type, "user_str")) {
				fe_cadd(c, FE_REJECTED, FE_SB028, n,
					"`%s.arg(%B)`: parameter %B is declared :user_str — read the string with `%s.str_arg(%B)` as the third argument of `R.output_str`",
					prm, B, B, prm, B);
				return NULL;
			}
			if (fe_streq(kp->type, "user_str_array")) {
				fe_cadd(c, FE_REJECTED, FE_SB028, n,
					"`%s.arg(%B)`: parameter %B is declared :user_str_array — read its strings with `%s.argv_arg(%B)` as the third argument of `R.output_argv`",
					prm, B, B, prm, B);
				return NULL;
			}
			return mk("kparg", typ(kp->type), v, p);
		}
		fe_cadd(c, FE_REJECTED, FE_SB028, as[0],
			"`%s.arg(%B)`: %B is not a parameter number declared in `BPF.%s … params:` (numbers are 1..6, 1-origin like the schema's n)", prm, B,
			B, kind);
		return NULL;
	}
	if (K("uprobe") && N("arg")) {
		if (!fe_streq(callee, "UprobeCtx#arg")) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s.arg` resolves to %q, not BPF::UprobeCtx#arg", prm, callee);
			return NULL;
		}
		fe_kparam *kp = fe_uprobe_param(c, n, as, n_as);
		if (!kp)
			return NULL;
		if (fe_streq(kp->type, "user_str")) {
			fe_cadd(c, FE_REJECTED, FE_SB028, n,
				"`%s.arg(%d)`: parameter %d is declared :user_str — read it with `%s.str_arg(%d)` as the third argument of `R.output_str`", prm,
				kp->n, kp->n, prm, kp->n);
			return NULL;
		}
		if (fe_streq(kp->type, "user_buf")) {
			fe_cadd(c, FE_REJECTED, FE_SB028, n,
				"`%s.arg(%d)`: parameter %d is declared :user_buf — read it with `%s.buf_arg(%d)` as the third argument of `R.output_buf`", prm,
				kp->n, kp->n, prm, kp->n);
			return NULL;
		}
		if (fe_streq(kp->type, "ptr"))
			return mk("kparg", named_field("ptr", 64, 1), kp->n, p);
		return mk("kparg", typ(kp->type), kp->n, p);
	}
	if (K("struct_ops") && (N("kptr") || N("kptr_or_null"))) { /* the socket-argument rule: the socket only as `tp = ctx.kptr_or_null(i, T)` + `if tp` */
		fe_struct_ops_kptr_refused(c, n);
		return NULL;
	}
	if (K("struct_ops") && N("arg")) { /* a struct_ops member's integer argument (the member table decides its type) */
		if (!fe_streq(callee, "StructOpsCtx#arg")) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s.arg` resolves to %q, not BPF::StructOpsCtx#arg", prm, callee);
			return NULL;
		}
		if (n_as != 1 || !t_is(as[0], "IntegerNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB033, n, "`%s.arg(i)` takes one Integer literal i — an argument index of the member", prm);
			return NULL;
		}
		bigint *nb = sr_alloc(sizeof *nb);
		if (!fe_literal(c->z->z, c->a, as[0], nb))
			return NULL;
		int64_t v;
		if (!big_i64(c, nb, &v))
			return NULL;
		const fe_so_member *m = fe_so_member_of(c->prog->so_type, c->prog->so_member);
		if (!m)
			return NULL;
		if (v < 0 || v >= m->nargs) {
			fe_cadd(c, FE_REJECTED, FE_SB033, as[0], "%s.%S has %d arguments — `%s.arg(%d)` is outside them", c->prog->so_type, m->name, m->nargs,
				prm, v);
			return NULL;
		}
		const fe_so_arg *ar = &m->args[v];
		if (!strcmp(ar->kind, "sock")) {
			fe_cadd(c, FE_REJECTED, FE_SB033, n,
				"argument %d of %s.%S is the socket pointer (struct sock *, read as tcp_sock) — it is not an integer; bind it with `tp = %s.kptr_or_null(%d, T)`",
				v, c->prog->so_type, m->name, prm, v);
			return NULL;
		}
		if (!strcmp(ar->kind, "task")) {
			fe_cadd(c, FE_REJECTED, FE_SB033, n,
				"argument %d of %s.%S is the task pointer (struct task_struct *) — it is not an integer; bind it with `p = %s.kptr_or_null(%d, T)`",
				v, c->prog->so_type, m->name, prm, v);
			return NULL;
		}
		if (!strcmp(ar->kind, "exitinfo")) {
			fe_cadd(c, FE_REJECTED, FE_SB033, n,
				"argument %d of %s.%S is the exit info (struct scx_exit_info *) — it is read only by `BPF::Scx.exit_info(%s, U)`", v,
				c->prog->so_type, m->name, prm);
			return NULL;
		}
		if (!strcmp(ar->kind, "bool")) {
			fe_cadd(c, FE_REJECTED, FE_SB033, n, "argument %d of %s.%S is a bool, which this version does not read", v, c->prog->so_type,
				m->name);
			return NULL;
		}
		if (!strcmp(ar->kind, "ptr")) {
			fe_cadd(c, FE_REJECTED, FE_SB033, n, "argument %d of %s.%S is a pointer this version does not read", v, c->prog->so_type, m->name);
			return NULL;
		}
		fe_so_add_index(c->prog, v); /* soAddIndex: ascending, once each */
		return mk("kparg", typ(t_s(ar->type)), v, p);
	}
	if ((K("tp_btf") || K("fentry") || K("fmod_ret")) && N("arg")) {
		const char *want = K("tp_btf") ? "TpBtfCtx#arg" : K("fentry") ? "FentryCtx#arg" : "FmodRetCtx#arg";
		if (!fe_streq(callee, want)) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s.arg` resolves to %q, not BPF::%S", prm, callee, want);
			return NULL;
		}
		if (n_as != 1 || !t_is(as[0], "IntegerNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB033, n, "`%s.arg(i)` takes one Integer literal i — an argument index declared in `BPF.%s … args:`", prm,
				kind);
			return NULL;
		}
		bigint *nb = sr_alloc(sizeof *nb);
		if (!fe_literal(c->z->z, c->a, as[0], nb))
			return NULL;
		int64_t v;
		if (!big_i64(c, nb, &v))
			return NULL;
		fe_tp_arg *ta = fe_program_tp_arg(c->prog, v);
		if (!ta) {
			fe_cadd(c, FE_REJECTED, FE_SB033, as[0], "argument %B is not declared in `BPF.%s … args:`", (const bigint *)nb, kind);
			return NULL;
		}
		if (ta->kt) {
			fe_cadd(c, FE_REJECTED, FE_SB033, n, "argument %d is declared as the kernel struct %s — bind it with `t = %s.kptr(%d, %sT)`", ta->idx,
				ta->kt->const_name, prm, ta->idx, ta->kt->const_name);
			return NULL;
		}
		return mk("kparg", typ(ta->type), ta->idx, p);
	}
	if (K("tp_btf") && (N("kptr") || N("kptr_or_null"))) {
		fe_cadd(c, FE_REJECTED, FE_SB033, n, "`%s.%s(…)` is not a value — bind it as a statement in the program's body: `t = %s.kptr(i, T)`", prm,
			name, prm);
		return NULL;
	}
	if (K("uprobe") && N("str_arg")) {
		fe_cadd(c, FE_REJECTED, FE_SB028, n,
			"`%s.str_arg(n)` is accepted only as the third argument of `R.output_str(S.new(…), :field, %s.str_arg(n), :status)` — a user string is not a value on the eBPF side",
			prm, prm);
		return NULL;
	}
	if (K("uprobe") && N("buf_arg")) {
		fe_cadd(c, FE_REJECTED, FE_SB028, n,
			"`%s.buf_arg(n)` is accepted only as the third argument of %s — a user buffer is not a value on the eBPF side", prm,
			fe_output_buf_form(prm));
		return NULL;
	}
#undef K
#undef N
	fe_cadd(c, FE_REJECTED, FE_SB028, n, "the %s context has no `%s` — it reads %S", kind, name, fe_ctx_reads(kind));
	return NULL;
}

/* verdictKindText (program.go) */
sr_str fe_verdict_kind_text(sr_str vk)
{
	static const char *const t[][2] = {{"xdp", "an XDP"},		{"sched_cls", "a sched_cls (tcx)"}, {"cgroup_skb", "a cgroup_skb"},
					   {"netfilter", "a netfilter"},	{"flow_dissector", "a flow_dissector"}, {"fmod_ret", "a fmod_ret"}};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (fe_streq(vk, t[i][0]))
			return S(t[i][1]);
	return S("a socket_filter");
}

/* verdictReturns (program.go) */
sr_str fe_verdict_returns(sr_str kind)
{
	static const char *const t[][2] = {
	    {"xdp", "an XDP program returns BPF::XDP_ABORTED / XDP_DROP / XDP_PASS / XDP_TX"},
	    {"sched_cls", "a sched_cls (`BPF.tcx`) program returns BPF::TC_PASS or BPF::TC_DROP"},
	    {"socket_filter", "a socket_filter program returns BPF::SF_KEEP or BPF::SF_DROP"},
	    {"cgroup_skb", "a cgroup_skb program returns BPF::CG_ALLOW or BPF::CG_DENY"},
	    {"netfilter", "a netfilter program returns BPF::NF_ACCEPT or BPF::NF_DROP"},
	    {"flow_dissector", "a flow_dissector program returns BPF::FLOW_OK / FLOW_DROP / FLOW_CONTINUE"},
	    {"fmod_ret", "a fmod_ret program returns BPF::FMOD_CALL or BPF.fmod_return(e) (e provably non-zero)"},
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (fe_streq(kind, t[i][0]))
			return S(t[i][1]);
	return t_cat(t_cat(S("a "), kind), S(" program returns nothing (its last value is dropped)"));
}

/* ctxStore (program.go) */
static int ctx_store(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out)
{
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return 0;
	if (!fe_streq(callee, "SkBuff#mark=")) {
		fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s.mark =` resolves to %s, not BPF::SkBuff#mark=", c->param, callee);
		return 0;
	}
	t_nodes as = t_args(c->a, n);
	if (as.n != 1) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "`%s.mark = v` takes one value", c->param);
		return 0;
	}
	fe_expr *e = fe_ctx_expr(c, as.v[0], ref_var);
	if (!e)
		return 0;
	if (e->bool_ || e->wide || !fe_iv_within(e->iv, intv_from_i64(0), fe_u32_max)) {
		fe_cadd(c, FE_REJECTED, FE_SB014, as.v[0],
			"the value's range %I does not fit __sk_buff.mark (u32 [0, 4294967295]) — the store would truncate silently; narrow it (e.g. `& 0xFFFF_FFFF`)",
			e->iv);
		return 0;
	}
	fe_stmt s = fe_stmt_new("ctxstore");
	s.path = S("mark");
	s.val = e;
	s.pos = fe_cpos(c, n);
	*out = s;
	return 1;
}

/* isAdjustPkt (program.go) */
int fe_is_adjust_pkt(fe_prog_ctx *c, const sr_node *n)
{
	return n && t_is(n, "CallNode") && (fe_streq(t_str(n, "name"), "adjust_head") || fe_streq(t_str(n, "name"), "adjust_tail")) && c->prog &&
	       fe_streq(c->prog->kind, "xdp") && fe_is_var_read(c, t_ref(c->a, n, "receiver"), c->param);
}

/* adjustPkt (program.go) */
fe_expr *fe_adjust_pkt(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	const sr_ast *a = c->a;
	sr_str nm = t_str(n, "name"), prm = c->param;
	const sr_node *p = parent_node(a, n);
	if (!p || !t_is(p, "LocalVariableWriteNode") || t_ref(a, p, "value") != n) {
		fe_cadd(c, FE_REJECTED, FE_SB026, n,
			"the status of `%s.%s(d)` (0 or −errno) is accepted only as `st = %s.%s(d)` (read later) or `_ = %s.%s(d)` — not as an argument, an operand or another value",
			prm, nm, prm, nm, prm, nm);
		return NULL;
	}
	if (!fe_top_level(c, p)) {
		fe_cadd(c, FE_REJECTED, FE_SB002, p,
			"`%s = %s.%s(d)` is accepted only as a statement directly in the program's body — not inside an arm or a loop (the helper invalidates the packet windows; decide the delta in the arm and move the packet at the top level)",
			t_str(p, "name"), prm, nm);
		return NULL;
	}
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return NULL;
	sr_str want = t_cat(S("XdpMd#"), nm);
	if (!sr_eq(callee, want)) {
		fe_cadd(c, FE_REJECTED, FE_SB011, n, "`%s` resolves to %s, not BPF::%s", nm, callee, want);
		return NULL;
	}
	t_nodes as = t_args(a, n);
	if (as.n != 1) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "`%s.%s(d)` takes one delta", prm, nm);
		return NULL;
	}
	fe_ival res = fe_iv(intv_from_i64(-4095), intv_from_i64(0));
	if (fe_streq(nm, "adjust_tail")) {
		int64_t k = 0;
		int good = t_is(as.v[0], "IntegerNode");
		if (good) {
			bigint b;
			int64_t v;
			good = fe_literal(c->z->z, a, as.v[0], &b) && t_big_int64(&b, &v) && v <= 0 && v >= INT32_MIN;
			if (good)
				k = v;
		}
		if (!good) {
			fe_cadd(c, FE_REJECTED, FE_SB014, as.v[0],
				"`%s.adjust_tail(k)` takes an Integer literal k ≤ 0 (it only shrinks the tail; bpf-mlir accepts only a constant non-positive delta)",
				prm);
			return NULL;
		}
		fe_expr *e = fe_expr_new("adjt", fe_cpos(c, n));
		e->idx = k;
		e->iv = res;
		return e;
	}
	fe_expr *d = fe_ctx_expr(c, as.v[0], ref_var);
	if (!d)
		return NULL;
	if (d->bool_ || d->wide || !fe_iv_within(d->iv, fe_i32_min, fe_i32_max)) {
		fe_cadd(c, FE_REJECTED, FE_SB014, as.v[0],
			"the delta's range %I does not fit the helper's int (i32 [-2147483648, 2147483647]) — narrow it", d->iv);
		return NULL;
	}
	fe_expr *e = fe_expr_new("adjh", fe_cpos(c, n));
	fe_expr_args(e, &d, 1);
	e->iv = res;
	return e;
}
