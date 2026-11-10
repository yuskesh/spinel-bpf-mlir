/* body_kernel — G2's kernel-struct body functions: kernel.go (kptrCall, nfBind, kptrBind, kfieldRead, kptrMisuse, isKptrRead,
 * topLevel, kcheckCall, kcheckStmt, kcheckedRoot, kcopyStmt, kpathRead, kptrPathRecv) and kpath.go (kaddrRead). Each comment
 * names the Go it follows (internal/frontend at main c204310). */
#include "body_g2.h"

#include <stdint.h>

/* KernelTypeDecl.field and Program.tpArg are the core's (body.h contract change 2) */
#define kt_field fe_kernel_type_decl_field
#define tp_arg fe_program_tp_arg

static fe_kernel_type_decl *kptr_of(fe_prog_ctx *c, sr_str name) { return fe_name_get(&c->kptrs, name); }
static fe_kernel_type_decl *handle(fe_prog_ctx *c, sr_str name) { return fe_name_get(&c->z->top->kt_handles, name); }
static const sr_node *recv_of(fe_prog_ctx *c, const sr_node *n) { return fe_ast_ref(c->a, n, "receiver"); }

/* the range of a kfload of an integer member (kernel.go progCtx.kfieldRead and progCtx.kpathRead) */
static void kf_range(fe_expr *e, const fe_kernel_field *f)
{
	if (f->bits == 64 && !f->is_signed) {
		e->iv = fe_iv(intv_from_i64(0), intv_from_u64(UINT64_MAX));
		e->wide = 1;
	} else {
		e->iv = fe_width_range(f->bits, f->is_signed);
	}
}

/* kernel.go kptrCall */
int fe_kptr_call(fe_prog_ctx *c, const sr_node *v)
{
	if (g2_is(v, "CallNode") && (sr_eqc(g2_str(v, "name"), "state") || sr_eqc(g2_str(v, "name"), "skb")) &&
	    fe_is_var_read(c, recv_of(c, v), c->param) && sr_eqc(c->prog->kind, "netfilter"))
		return 1;
	return g2_is(v, "CallNode") && (sr_eqc(g2_str(v, "name"), "kptr") || sr_eqc(g2_str(v, "name"), "kptr_or_null")) &&
	       fe_is_var_read(c, recv_of(c, v), c->param) && sr_eqc(c->prog->kind, "tp_btf");
}

/* kernel.go nfPtrs */
static const char *nf_ptr(sr_str field)
{
	if (sr_eqc(field, "state"))
		return "nf_hook_state";
	if (sr_eqc(field, "skb"))
		return "sk_buff";
	return "";
}

/* kernel.go nfBind */
static int nf_bind(fe_prog_ctx *c, const sr_node *w, const sr_node *v, sr_str name, fe_stmt *out)
{
	sr_str field = g2_str(v, "name");
	int ok;
	sr_str callee = fe_callee(c, v, &ok);
	if (!ok)
		return 0;
	sr_buf wb = {0};
	sr_puts(&wb, "NfCtx#");
	sr_putstr(&wb, field);
	sr_str want = sr_bufstr(&wb);
	if (!sr_eq(callee, want)) {
		g2_reject(c, FE_SB011, v, "`%s` resolves to %s, not BPF::%s", field, callee, want);
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, v, &n_as);
	if (n_as != 1 || !g2_is(as[0], "ConstantReadNode")) {
		g2_reject(c, FE_SB033, v,
			  "`%s.%s(T)` takes one kernel struct's sample handle (`T = BPF::KernelType.new(…)` of a `BPF.kernel_type(…, %q, …)`)",
			  c->param, field, sr_cstr(nf_ptr(field)));
		return 0;
	}
	fe_kernel_type_decl *h = handle(c, g2_str(as[0], "name"));
	if (!h || !sr_eqc(h->name, nf_ptr(field))) {
		sr_str got = sr_cstr("not a kernel struct handle");
		if (h)
			got = h->name;
		g2_reject(c, FE_SB033, as[0], "`%s.%s` points to the kernel struct %c — %s is %s", c->param, field, nf_ptr(field),
			  g2_str(as[0], "name"), got);
		return 0;
	}
	fe_name_set(&c->kptrs, name, h);
	fe_stmt s = fe_stmt_new("kptr");
	s.var = name;
	s.path = field;
	s.kt = h;
	s.pos = g2_pos(c, w);
	*out = s;
	return 1;
}

/* a name already bound (kernel.go progCtx.kptrBind and progCtx.kcheckStmt) */
static int bound(fe_prog_ctx *c, sr_str name)
{
	return fe_name_has(&c->env, name) || sr_eq(name, c->param) || fe_name_get(&c->refs, name) || fe_name_get(&c->wins, name) ||
	       kptr_of(c, name);
}

/* kernel.go kptrBind */
int fe_kptr_bind(fe_prog_ctx *c, const sr_node *w, int top, fe_stmt *out)
{
	sr_str name = g2_str(w, "name");
	const sr_node *v = fe_ast_ref(c->a, w, "value");
	if (!top) {
		g2_reject(c, FE_SB033, w,
			  "`%s = %s.kptr(…)` is accepted only as a statement directly in the program's body (not inside an arm or a loop) — bind the kernel pointer first",
			  name, c->param);
		return 0;
	}
	if (bound(c, name)) {
		g2_reject(c, FE_SB033, w, "`%s` is already bound — a kernel pointer is bound once to a fresh name", name);
		return 0;
	}
	if (sr_eqc(c->prog->kind, "netfilter"))
		return nf_bind(c, w, v, name, out);
	int ok;
	sr_str callee = fe_callee(c, v, &ok);
	if (!ok)
		return 0;
	if (!sr_eqc(callee, "TpBtfCtx#kptr")) {
		g2_reject(c, FE_SB011, v, "`kptr` resolves to %s, not BPF::TpBtfCtx#kptr", callee);
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, v, &n_as);
	if (n_as != 2 || !g2_is(as[0], "IntegerNode") || !g2_is(as[1], "ConstantReadNode")) {
		g2_reject(c, FE_SB033, v, "`%s.kptr(i, T)` takes an Integer literal index and a kernel struct's sample handle", c->param);
		return 0;
	}
	int64_t i;
	if (!g2_lit_int(c, as[0], &i)) /* literal has added SB001 or SB014; stop, never use the value */
		return 0;
	fe_tp_arg *ta = tp_arg(c->prog, i);
	fe_kernel_type_decl *h = handle(c, g2_str(as[1], "name"));
	if (!ta) {
		g2_reject(c, FE_SB033, as[0], "argument %d is not declared in `BPF.tp_btf … args:`", i);
		return 0;
	}
	if (!ta->kt) {
		g2_reject(c, FE_SB033, v, "argument %d is declared as the integer :%s — read it with `%s.arg(%d)`", i, ta->type, c->param, i);
		return 0;
	}
	if (!h || h != ta->kt) {
		g2_reject(c, FE_SB033, as[1], "argument %d is declared as %s (%s), not %s", i, ta->kt->const_name, ta->kt->name,
			  g2_str(as[1], "name"));
		return 0;
	}
	if (ta->null) {
		g2_reject(c, FE_SB033, v,
			  "argument %d is declared nullable (`[:or_null, T]`) — read it with `q = %s.kptr_or_null(%d, T)` and `if q`", i,
			  c->param, i);
		return 0;
	}
	fe_name_set(&c->kptrs, name, ta->kt);
	fe_stmt s = fe_stmt_new("kptr");
	s.var = name;
	s.len = i;
	s.kt = ta->kt;
	s.pos = g2_pos(c, w);
	*out = s;
	return 1;
}

/* kernel.go kfieldRead */
fe_expr *fe_kfield_read(fe_prog_ctx *c, const sr_node *n, const sr_node *recv, fe_pos p)
{
	sr_str t = g2_str(recv_of(c, recv), "name");
	fe_kernel_type_decl *d = kptr_of(c, t);
	sr_str mname = g2_str(n, "name");
	fe_kernel_field *f = kt_field(d, mname);
	if (!f) {
		g2_reject(c, FE_SB033, n, "%s (%s) declares no member `%s` — declare the members it reads in BPF.kernel_type", d->const_name,
			  d->name, mname);
		return NULL;
	}
	int ok;
	sr_str cs = fe_callee(c, recv, &ok);
	if (!ok || !sr_eqc(cs, "KPtr#load")) {
		if (ok)
			g2_reject(c, FE_SB011, recv, "`load` resolves to %s, not BPF::KPtr#load", cs);
		return NULL;
	}
	size_t n_as;
	fe_args(c->a, n, &n_as);
	if (n_as != 0) {
		g2_reject(c, FE_SB002, n, "a member read takes no arguments");
		return NULL;
	}
	if (sr_eqc(f->kind, "kptr")) {
		g2_reject(c, FE_SB033, n, "member %s is a kernel pointer — follow it with `rp = %s.ptr(:%s, T)` and `if rp`", f->name, t, f->name);
		return NULL;
	}
	if (sr_eqc(f->kind, "array")) {
		g2_reject(c, FE_SB033, n,
			  "member %s is a byte array — copy it into a record's byte-array member with `r.load.<member> = %s.copy(:%s)`", f->name,
			  t, f->name);
		return NULL;
	}
	if (sr_eqc(f->kind, "struct")) {
		g2_reject(c, FE_SB033, n, "member %s is an embedded struct — read its integer members as `%s.load.%s.m`", f->name, t, f->name);
		return NULL;
	}
	if (sr_eqc(f->kind, "strptr")) {
		g2_reject(c, FE_SB033, n,
			  "member %s is a :strptr (char *) — read the string it points to with `R.output_str(…, %s.str(:%s), …)`, not its address",
			  f->name, t, f->name);
		return NULL;
	}
	fe_record_field *rf = sr_alloc(sizeof *rf);
	rf->name = f->name;
	rf->bits = f->bits;
	rf->is_signed = f->is_signed;
	fe_expr *e = g2_expr("kfload", p);
	e->var = t;
	e->field = rf;
	e->path = d->name;
	kf_range(e, f);
	return e;
}

/* kernel.go kptrMisuse */
void fe_kptr_misuse(fe_prog_ctx *c, const sr_node *n, sr_str name)
{
	int call = g2_is(n, "CallNode");
	sr_str m = g2_str(n, "name");
	if (call && sr_eqc(m, "ptr"))
		g2_reject(c, FE_SB005, n,
			  "`%s.ptr(:m, T)` (a pointer field — nullable) is accepted only as `rp = %s.ptr(:m, T)` followed immediately by `if rp`",
			  name, name);
	else if (call && sr_eqc(m, "copy"))
		g2_reject(c, FE_SB033, n,
			  "`%s.copy(:m)` (a byte-array field) is not a value — it is accepted only as `r.load.<member> = %s.copy(:m)` inside `if r` of a record map's lookup",
			  name, name);
	else if (call && sr_eqc(m, "load"))
		g2_reject(c, FE_SB033, n, "`%s.load` is not a value — read an integer member `%s.load.m`", name, name);
	else
		g2_reject(c, FE_SB033, n, "the kernel pointer `%s` is not a value — read its members as `%s.load.m`", name, name);
}

/* kernel.go isKptrRead */
int fe_is_kptr_read(fe_prog_ctx *c, const sr_node *n)
{
	return g2_is(n, "LocalVariableReadNode") && kptr_of(c, g2_str(n, "name")) != NULL;
}

/* kernel.go topLevel */
int fe_top_level(fe_prog_ctx *c, const sr_node *n)
{
	const sr_node *p = g2_parent(c->a, n);
	if (!p || !sr_eqc(p->type, "StatementsNode"))
		return 0;
	return g2_parent(c->a, p) == c->def;
}

/* kernel.go kcheckCall */
int fe_kcheck_call(fe_prog_ctx *c, const sr_node *v)
{
	if (!g2_is(v, "CallNode"))
		return 0;
	if (sr_eqc(g2_str(v, "name"), "kptr_or_null") && fe_is_var_read(c, recv_of(c, v), c->param) && fe_uses_kernel_types(c->prog))
		return 1;
	return sr_eqc(g2_str(v, "name"), "ptr") && fe_is_kptr_read(c, recv_of(c, v));
}

/* the statements of an IfNode's or ElseNode's "statements" (nil when absent) */
static fe_stmts arm(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	size_t k = 0;
	const sr_node **ns = NULL;
	const sr_node *st = fe_ast_ref(c->a, n, "statements");
	if (st)
		ns = fe_ast_arr(c->a, st, "body", &k);
	return fe_ctx_stmts(c, ns, k, ref_var);
}

/* kernel.go kcheckStmt */
int fe_kcheck_stmt(fe_prog_ctx *c, const sr_node *w, const sr_node *ifn, sr_str ref_var, fe_stmt *out)
{
	sr_str name = g2_str(w, "name");
	const sr_node *v = fe_ast_ref(c->a, w, "value");
	if (bound(c, name) || fe_name_get(&c->kchecked, name)) {
		g2_reject(c, FE_SB033, w, "`%s` is already bound — a kernel pointer is bound once to a fresh name", name);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, v, &ok);
	if (!ok)
		return 0;
	size_t n_as;
	const sr_node **as = fe_args(c->a, v, &n_as);
	fe_stmt s = fe_stmt_new("kcheck");
	s.var = name;
	s.pos = g2_pos(c, w);
	s.if_pos = g2_pos(c, ifn);
	if (sr_eqc(g2_str(v, "name"), "kptr_or_null")) {
		const char *want = sr_eqc(c->prog->kind, "tp_btf")   ? "TpBtfCtx#kptr_or_null"
				   : sr_eqc(c->prog->kind, "fentry") ? "FentryCtx#kptr_or_null"
								     : "";
		if (!sr_eqc(callee, want)) {
			g2_reject(c, FE_SB011, v, "`kptr_or_null` resolves to %s, not BPF::%c", callee, want);
			return 0;
		}
		if (!fe_top_level(c, w)) {
			g2_reject(c, FE_SB033, w, "`%s = %s.kptr_or_null(…)` is accepted only as a statement directly in the program's body", name,
				  c->param);
			return 0;
		}
		if (n_as != 2 || !g2_is(as[0], "IntegerNode") || !g2_is(as[1], "ConstantReadNode")) {
			g2_reject(c, FE_SB033, v, "`%s.kptr_or_null(i, T)` takes an Integer literal index and a kernel struct's sample handle",
				  c->param);
			return 0;
		}
		int64_t i;
		if (!g2_lit_int(c, as[0], &i)) /* literal has added SB001 or SB014; stop, never use the value */
			return 0;
		fe_tp_arg *ta = tp_arg(c->prog, i);
		fe_kernel_type_decl *h = handle(c, g2_str(as[1], "name"));
		if (!ta) {
			g2_reject(c, FE_SB033, as[0], "argument %d is not declared in `BPF.%s … args:`", i, c->prog->kind);
			return 0;
		}
		if (!ta->kt) {
			g2_reject(c, FE_SB033, v, "argument %d is declared as the integer :%s — read it with `%s.arg(%d)`", i, ta->type, c->param,
				  i);
			return 0;
		}
		if (!ta->null) {
			g2_reject(c, FE_SB033, v,
				  "argument %d is declared non-null — read it with `t = %s.kptr(%d, T)` (declare `%d => [:or_null, T]` if the tracepoint passes NULL)",
				  i, c->param, i, i);
			return 0;
		}
		if (!h || h != ta->kt) {
			g2_reject(c, FE_SB033, as[1], "argument %d is declared as %s (%s), not %s", i, ta->kt->const_name, ta->kt->name,
				  g2_str(as[1], "name"));
			return 0;
		}
		s.kt = ta->kt;
		s.len = i;
		s.path = (sr_str){0};
	} else {
		sr_str t = g2_str(recv_of(c, v), "name");
		fe_kernel_type_decl *d = kptr_of(c, t);
		if (!sr_eqc(callee, "KPtr#ptr")) {
			g2_reject(c, FE_SB011, v, "`ptr` resolves to %s, not BPF::KPtr#ptr", callee);
			return 0;
		}
		if (n_as != 2 || !g2_is(as[0], "SymbolNode") || !g2_is(as[1], "ConstantReadNode")) {
			g2_reject(c, FE_SB033, v, "`%s.ptr(:m, T)` takes a member Symbol and the pointee's sample handle", t);
			return 0;
		}
		fe_kernel_field *f = kt_field(d, g2_str(as[0], "value"));
		fe_kernel_type_decl *h = handle(c, g2_str(as[1], "name"));
		if (!f) {
			g2_reject(c, FE_SB033, as[0], "%s (%s) declares no member `%s`", d->const_name, d->name, g2_str(as[0], "value"));
			return 0;
		}
		if (!sr_eqc(f->kind, "kptr")) {
			g2_reject(c, FE_SB033, as[0], "member %s is not a kernel pointer (`[:kptr, S]`) — read it with `%s.load.%s`", f->name, t,
				  f->name);
			return 0;
		}
		if (!h || !sr_eq(h->const_name, f->ptr)) {
			g2_reject(c, FE_SB033, as[1], "member %s points to %s, not the struct of %s", f->name, f->ptr, g2_str(as[1], "name"));
			return 0;
		}
		s.kt = h;
		s.path = f->name;
		s.ptr_of = t;
		s.ptr_of_kt = d;
	}
	if (!fe_typed(c, fe_ast_ref(c->a, ifn, "predicate")))
		return 0;
	fe_name_set(&c->kchecked, name, g2_true);
	fe_name_table pre = c->env;
	c->env = fe_copy_env(&pre);
	fe_name_set(&c->kptrs, name, s.kt);
	s.then = arm(c, ifn, ref_var);
	fe_name_delete(&c->kptrs, name);
	fe_name_table then_env = c->env;
	c->env = fe_copy_env(&pre);
	const sr_node *sub = fe_ast_ref(c->a, ifn, "subsequent");
	if (sub) {
		if (!sr_eqc(sub->type, "ElseNode")) {
			g2_reject(c, FE_SB005, sub, "`elsif` is not accepted after `if %s`", name);
			return 0;
		}
		s.else_ = arm(c, sub, ref_var);
	}
	c->env = fe_join_arms(&pre, &then_env, &c->env, fe_escapes(&s.then), fe_escapes(&s.else_));
	*out = s;
	return 1;
}

/* kernel.go kcheckedRoot */
sr_str fe_kchecked_root(fe_prog_ctx *c, const sr_node *n)
{
	while (g2_is(n, "CallNode"))
		n = recv_of(c, n);
	if (g2_is(n, "LocalVariableReadNode") && fe_name_get(&c->kchecked, g2_str(n, "name")) && !kptr_of(c, g2_str(n, "name")))
		return g2_str(n, "name");
	return (sr_str){0};
}

/* kernel.go kcopyStmt */
int fe_kcopy_stmt(fe_prog_ctx *c, const sr_node *n, const sr_node *cp, sr_str ref, fe_map_decl *m, fe_record_field *rf, fe_stmt *out)
{
	sr_str t = g2_str(recv_of(c, cp), "name");
	fe_kernel_type_decl *d = kptr_of(c, t);
	int ok;
	sr_str callee = fe_callee(c, cp, &ok);
	if (!ok)
		return 0;
	if (!sr_eqc(callee, "KPtr#copy")) {
		g2_reject(c, FE_SB011, cp, "`copy` resolves to %s, not BPF::KPtr#copy", callee);
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, cp, &n_as);
	if (n_as != 1 || !g2_is(as[0], "SymbolNode")) {
		g2_reject(c, FE_SB033, cp, "`%s.copy(:m)` takes one member Symbol", t);
		return 0;
	}
	fe_kernel_field *kf = kt_field(d, g2_str(as[0], "value"));
	if (!kf) {
		g2_reject(c, FE_SB033, as[0], "%s (%s) declares no member `%s`", d->const_name, d->name, g2_str(as[0], "value"));
		return 0;
	}
	if (!sr_eqc(kf->kind, "array")) {
		g2_reject(c, FE_SB033, as[0], "member %s is not a byte array (`[:u8, N]`) — read it with `%s.load.%s`", kf->name, t, kf->name);
		return 0;
	}
	if (rf->count == 0 || rf->bits != 8) {
		g2_reject(c, FE_SB033, n,
			  "record member %s of %s is not an 8-bit array — `%s.copy(:%s)` copies %d bytes into a `[:u8, %d]` member", rf->name,
			  m->record->const_name, t, kf->name, kf->count, kf->count);
		return 0;
	}
	if (rf->count != kf->count) {
		g2_reject(c, FE_SB033, n, "record member %s has %d elements but %s.%s has %d — the copy is a fixed N bytes, declare the same N",
			  rf->name, rf->count, d->const_name, kf->name, kf->count);
		return 0;
	}
	fe_stmt s = fe_stmt_new("kcopy");
	s.var = ref;
	s.map = m;
	s.field = rf;
	s.path = kf->name;
	s.ptr_of = t;
	s.ptr_of_kt = d;
	s.pos = g2_pos(c, n);
	*out = s;
	return 1;
}

/* kernel.go kpathRead: *ok is Go's second result */
fe_expr *fe_kpath_read(fe_prog_ctx *c, const sr_node *n, fe_pos p, int *ok)
{
	const sr_node *segs[4];
	size_t n_segs = 0;
	const sr_node *cur = n;
	*ok = 0;
	while (g2_is(cur, "CallNode") && !sr_eqc(g2_str(cur, "name"), "load")) {
		if (!fe_member_like(g2_str(cur, "name")))
			return NULL;
		if (n_segs < 4) /* the 4th stands for any longer path: Go rejects len(segs) > 3 before it reads one */
			n_segs++;
		for (size_t i = n_segs - 1; i > 0; i--)
			segs[i] = segs[i - 1];
		segs[0] = cur;
		cur = recv_of(c, cur);
	}
	/* a path longer than 4 drops its last segments above; only its length (> 3) is read below */
	if (!g2_is(cur, "CallNode") || !sr_eqc(g2_str(cur, "name"), "load") || !fe_is_kptr_read(c, recv_of(c, cur)) || n_segs < 2)
		return NULL;
	*ok = 1;
	sr_str t = g2_str(recv_of(c, cur), "name");
	int cok;
	sr_str cs = fe_callee(c, cur, &cok);
	if (!cok || !sr_eqc(cs, "KPtr#load")) {
		if (cok)
			g2_reject(c, FE_SB011, cur, "`load` resolves to %s, not BPF::KPtr#load", cs);
		return NULL;
	}
	fe_kernel_type_decl *root = kptr_of(c, t);
	if (n_segs > 3) {
		/* Go prints len(segs); count the whole path again */
		int64_t total = 0;
		for (const sr_node *x = n; g2_is(x, "CallNode") && !sr_eqc(g2_str(x, "name"), "load"); x = recv_of(c, x))
			total++;
		g2_reject(c, FE_SB033, n, "`%s.load` reads at most 3 members deep (a.b.c — bpf-mlir's kfield paths), got %d", t, total);
		return NULL;
	}
	fe_kernel_type_decl *d = root;
	sr_buf names = {0};
	for (size_t i = 0; i < n_segs; i++) {
		const sr_node *s = segs[i];
		sr_str name = g2_str(s, "name");
		size_t n_as;
		fe_args(c->a, s, &n_as);
		if (n_as != 0) {
			g2_reject(c, FE_SB002, s, "a member read takes no arguments");
			return NULL;
		}
		if (!d) { /* Go calls field on a nil *KernelTypeDecl and panics */
			fe_not_ported(c->z->z, "kpathRead: an embedded struct with no kernel_type");
			return NULL;
		}
		fe_kernel_field *f = kt_field(d, name);
		if (!f) {
			g2_reject(c, FE_SB033, s, "%s (%s) declares no member `%s` — declare the members it reads in BPF.kernel_type", d->const_name,
				  d->name, name);
			return NULL;
		}
		if (i > 0)
			sr_puts(&names, ".");
		sr_putstr(&names, name);
		if (i < n_segs - 1) {
			if (!sr_eqc(f->kind, "struct")) {
				g2_reject(c, FE_SB033, s,
					  "member %s of %s is not an embedded struct ([:struct, S]) — a member path goes only through embedded structs",
					  name, d->const_name);
				return NULL;
			}
			d = fe_name_get(&c->z->top->kts, f->ptr);
			continue;
		}
		sr_str joined = sr_bufstr(&names);
		if (!sr_eqc(f->kind, "int")) {
			g2_reject(c, FE_SB033, s,
				  "`%s.load.%s` reads an integer member only — %s is a %s member (pointers, byte arrays and strings through a member path are not accepted yet)",
				  t, joined, name, f->kind);
			return NULL;
		}
		fe_record_field *rf = sr_alloc(sizeof *rf);
		rf->name = joined;
		rf->bits = f->bits;
		rf->is_signed = f->is_signed;
		fe_expr *e = g2_expr("kfload", p);
		e->var = t;
		e->field = rf;
		e->path = root->name;
		kf_range(e, f);
		return e;
	}
	return NULL;
}

/* kernel.go kptrPathRecv */
int fe_kptr_path_recv(fe_prog_ctx *c, const sr_node *recv)
{
	int64_t segs = 0;
	const sr_node *cur = recv;
	while (g2_is(cur, "CallNode") && !sr_eqc(g2_str(cur, "name"), "load")) {
		if (!fe_member_like(g2_str(cur, "name")))
			return 0;
		segs++;
		cur = recv_of(c, cur);
	}
	return segs >= 1 && g2_is(cur, "CallNode") && sr_eqc(g2_str(cur, "name"), "load") && fe_is_kptr_read(c, recv_of(c, cur));
}

/* kpath.go kaddrRead */
fe_expr *fe_kaddr_read(fe_prog_ctx *c, const sr_node *n, const sr_node *recv, fe_pos p)
{
	sr_str t = g2_str(recv, "name");
	int ok;
	sr_str cs = fe_callee(c, n, &ok);
	if (!ok || !sr_eqc(cs, "KPtr#addr")) {
		if (ok)
			g2_reject(c, FE_SB011, n, "`addr` resolves to %s, not BPF::KPtr#addr", cs);
		return NULL;
	}
	size_t n_as;
	fe_args(c->a, n, &n_as);
	if (n_as != 0) {
		g2_reject(c, FE_SB033, n, "`%s.addr` takes no arguments — it is the address of the checked kernel pointer", t);
		return NULL;
	}
	fe_expr *e = g2_expr("kaddr", p);
	e->var = t;
	e->path = kptr_of(c, t)->name;
	e->iv = fe_width_range(64, 1);
	return e;
}
