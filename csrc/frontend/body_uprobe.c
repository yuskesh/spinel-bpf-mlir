/* body_uprobe — G2's user-string body functions: uprobe.go (uprobeParam, outputStr, outputStrMake, outputStrCheck,
 * ostrStatus, outputKStr), argv.go (outputArgv) and tpstr.go (outputTpStr). Each comment names the Go it follows. Strings come
 * from the arena. */
#include "body_g2.h"

#include <string.h>


/* strings.Contains(s, sub) */
static int contains(sr_str s, const char *sub)
{
	size_t k = strlen(sub);
	for (size_t i = 0; i + k <= s.n; i++)
		if (memcmp(s.p + i, sub, k) == 0)
			return 1;
	return 0;
}

static sr_str cat(sr_str a, const char *b, sr_str c)
{
	sr_buf x = {0};
	sr_putstr(&x, a);
	sr_puts(&x, b);
	sr_putstr(&x, c);
	return sr_bufstr(&x);
}

static sr_str ctx_class(sr_str kind)
{
	const char *s = t_ctx_class(kind);
	return sr_cstr(s ? s : "");
}

static fe_var_info *var_new(int is_bool, fe_ival iv)
{
	fe_var_info *v = sr_alloc(sizeof *v);
	v->bool_ = is_bool;
	v->iv = iv;
	v->from_nil = 1;
	return v;
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

/* the record member a Symbol names (uprobe.go progCtx.outputStr and argv.go progCtx.outputArgv member) */
static fe_record_field *member(fe_ring_decl *r, const sr_node *x)
{
	if (!g2_is(x, "SymbolNode"))
		return NULL;
	for (size_t i = 0; i < r->record->n_fields; i++)
		if (sr_eq(r->record->fields[i].name, g2_str(x, "value")))
			return &r->record->fields[i];
	return NULL;
}

/* uprobe.go uprobeParam */
fe_kparam *fe_uprobe_param(fe_prog_ctx *c, const sr_node *n, const sr_node *const *as, size_t n_as)
{
	if (n_as != 1 || !g2_is(as[0], "IntegerNode")) {
		g2_reject(c, FE_SB028, n, "`%s.%s(n)` takes one Integer literal n — a declared parameter number", c->param, g2_str(n, "name"));
		return NULL;
	}
	bigint nb = {0};
	if (!fe_literal(c->z->z, c->a, as[0], &nb))
		return NULL;
	int64_t v;
	int is64 = g2_big_i64(&nb, &v);
	for (size_t i = 0; i < c->prog->n_params; i++)
		if (is64 && c->prog->params[i].n == v) {
			bigint_free(&nb);
			return &c->prog->params[i];
		}
	g2_reject(c, FE_SB028, as[0],
		  "`%s.%s(%B)`: %B is not a parameter number declared in `BPF.uprobe … params:` (1..6, 1-origin like the schema's n)", c->param,
		  g2_str(n, "name"), (const bigint *)&nb, (const bigint *)&nb);
	bigint_free(&nb);
	return NULL;
}

/* uprobe.go isOutputStr */
int fe_is_output_str(fe_prog_ctx *c, const sr_node *n)
{
	if (!g2_is(n, "CallNode"))
		return 0;
	sr_str m = g2_str(n, "name");
	return (sr_eqc(m, "output_str") || sr_eqc(m, "output_str_or_discard") || sr_eqc(m, "output_comm") || sr_eqc(m, "output_argv") ||
		sr_eqc(m, "output_buf")) &&
	       fe_ring_of(c, fe_ast_ref(c->a, n, "receiver")) != NULL;
}

/* tpstr.go outputTpStr (G2-private by contract change 2; ported in full, not left as the stub first planned for it) */
static int output_tp_str(fe_prog_ctx *c, const sr_node *call, const sr_node *const *as, size_t n_as, fe_ring_decl *r, sr_str meth,
			 fe_record_field *f, fe_record_field *st, sr_str name, sr_str ref_var, fe_stmt *out)
{
	const sr_node *sa = as[2];
	if (!g2_is(sa, "CallNode") || !sr_eqc(g2_str(sa, "name"), "str_field") ||
	    !fe_is_var_read(c, fe_ast_ref(c->a, sa, "receiver"), c->param)) {
		g2_reject(c, FE_SB028, sa,
			  "the third argument of %s in a tracepoint program is `%s.str_field(:f)` itself (a user string is not a value on the eBPF side — not through a local)",
			  meth, c->param);
		return 0;
	}
	int ok;
	sr_str cs = fe_callee(c, sa, &ok);
	if (!ok || !sr_eqc(cs, "TracepointCtx#str_field")) {
		if (ok)
			g2_reject(c, FE_SB011, sa, "`str_field` resolves to %s, not BPF::TracepointCtx#str_field", cs);
		return 0;
	}
	size_t n_sas;
	const sr_node **sas = fe_args(c->a, sa, &n_sas);
	if (n_sas != 1 || !g2_is(sas[0], "SymbolNode")) {
		g2_reject(c, FE_SB028, sa, "`%s.str_field(:f)` takes one Symbol literal — a :user_str field declared in `BPF.tracepoint … fields:`",
			  c->param);
		return 0;
	}
	sr_str fn = g2_str(sas[0], "value");
	fe_tp_field *tf = NULL;
	for (size_t i = 0; i < c->prog->n_t_fields; i++)
		if (sr_eq(c->prog->t_fields[i].name, fn))
			tf = &c->prog->t_fields[i];
	if (!tf) {
		g2_reject(c, FE_SB028, sas[0],
			  "`%s.str_field(:%s)`: %s is not declared in `BPF.tracepoint … fields:` (declare `%s: [offset, :user_str]` from the tracefs format)",
			  c->param, fn, fn, fn);
		return 0;
	}
	if (!sr_eqc(tf->type, "user_str")) {
		g2_reject(c, FE_SB028, sas[0], "`%s.str_field(:%s)`: %s is declared :%s — read it with `%s.field(:%s)`", c->param, fn, fn, tf->type,
			  c->param, fn);
		return 0;
	}
	fe_stmt os = fe_stmt_new("");
	ok = fe_output_str_make(c, call, as, n_as, r, meth, f, st, name, ref_var, &os);
	os.tp_str = tf;
	*out = os;
	return ok;
}

/* uprobe.go outputKStr */
static int output_kstr(fe_prog_ctx *c, const sr_node *call, const sr_node *const *as, size_t n_as, fe_ring_decl *r, sr_str meth,
		       fe_record_field *f, fe_record_field *st, sr_str name, sr_str ref_var, fe_stmt *out)
{
	const sr_node *sa = as[2];
	sr_str k = c->prog->kind;
	if (!sr_eqc(k, "fentry") && !sr_eqc(k, "tp_btf") && !sr_eqc(k, "netfilter")) {
		g2_reject(c, FE_SB028, sa,
			  "`….str(:m)` reads a kernel string through a kernel pointer — a %s program has none (fentry / tp_btf arguments and netfilter's state / skb do)",
			  k);
		return 0;
	}
	const sr_node *recv = fe_ast_ref(c->a, sa, "receiver");
	if (!g2_is(recv, "LocalVariableReadNode") || !fe_name_get(&c->kptrs, g2_str(recv, "name"))) {
		g2_reject(c, FE_SB033, sa,
			  "`….str(:m)` reads a kernel string through a present kernel pointer — `q = %s.kptr_or_null(i, T)` and `if q`, then `q.str(:m)`",
			  c->param);
		return 0;
	}
	int ok;
	sr_str cs = fe_callee(c, sa, &ok);
	if (!ok || !sr_eqc(cs, "KPtr#str")) {
		if (ok)
			g2_reject(c, FE_SB011, sa, "`str` resolves to %s, not BPF::KPtr#str", cs);
		return 0;
	}
	sr_str q = g2_str(recv, "name");
	fe_kernel_type_decl *kt = fe_name_get(&c->kptrs, q);
	size_t n_sas;
	const sr_node **sas = fe_args(c->a, sa, &n_sas);
	if (n_sas != 1 || !g2_is(sas[0], "SymbolNode")) {
		g2_reject(c, FE_SB033, sa, "`%s.str(:m)` takes one Symbol literal — a :strptr member of %s", q, kt->const_name);
		return 0;
	}
	sr_str mv = g2_str(sas[0], "value");
	fe_kernel_field *kf = fe_kernel_type_decl_field(kt, mv);
	if (!kf || !sr_eqc(kf->kind, "strptr")) {
		g2_reject(c, FE_SB033, sas[0],
			  "`%s.str(:%s)`: %s is not a :strptr member of %s (declare `%s: :strptr` in BPF.kernel_type — a char * member)", q, mv, mv,
			  kt->const_name, mv);
		return 0;
	}
	fe_stmt os = fe_stmt_new("");
	ok = fe_output_str_make(c, call, as, n_as, r, meth, f, st, name, ref_var, &os);
	os.ptr_of = q;
	os.ptr_of_kt = kt;
	os.k_str = kf->name;
	*out = os;
	return ok;
}

/* argv.go outputArgv */
static int output_argv(fe_prog_ctx *c, const sr_node *call, sr_str name, sr_str ref_var, fe_stmt *out)
{
	fe_ring_decl *r = fe_ring_of(c, fe_ast_ref(c->a, call, "receiver"));
	const char *src = sr_eqc(c->prog->kind, "ksyscall")	? "ctx.argv_arg(n)"
			  : sr_eqc(c->prog->kind, "tracepoint") ? "ctx.argv_field(:f)"
								: "";
	if (!*src) {
		g2_reject(c, FE_SB028, call,
			  "`%s.output_argv` reads an argv array (`ctx.argv_arg(n)` in a ksyscall program, `ctx.argv_field(:f)` in a tracepoint program) — a %s program has none",
			  r->const_name, c->prog->kind);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, call, &ok);
	if (!ok)
		return 0;
	if (!sr_eqc(callee, "RingBuf#output_argv")) {
		g2_reject(c, FE_SB011, call, "`output_argv` resolves to %s, not BPF::RingBuf#output_argv", callee);
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, call, &n_as);
	if (n_as != 5) {
		g2_reject(c, FE_SB024, call, "output_argv takes five arguments — %s", fe_g2_output_argv_shape(r, sr_cstr(src)));
		return 0;
	}
	fe_record_field *f = member(r, as[1]), *st = member(r, as[3]), *ix = member(r, as[4]);
	if (!f || f->count == 0 || f->bits != 8 || f->is_signed) {
		g2_reject(c, FE_SB024, as[1], "the string member of output_argv must be a :u8 array member of %s (`arg: [:u8, 64]`)",
			  r->record->const_name);
		return 0;
	}
	if (!st || st->count != 0 || st->bits != 64 || !st->is_signed) {
		g2_reject(c, FE_SB024, as[3], "the status member of output_argv must be an :i64 member of %s (the raw status of probe_read_user_str)",
			  r->record->const_name);
		return 0;
	}
	if (!ix || ix->count != 0 || ix->bits != 32 || ix->is_signed) {
		g2_reject(c, FE_SB024, as[4], "the index member of output_argv must be a :u32 member of %s (the argv slot 0..19)",
			  r->record->const_name);
		return 0;
	}
	fe_stmt os = fe_stmt_new("");
	if (!fe_output_str_make(c, call, as, 4, r, sr_cstr("output_argv"), f, st, name, ref_var, &os))
		return 0;
	os.argv = 1;
	os.index = ix;
	const sr_node *sa = as[2];
	sr_str sn = g2_str(sa, "name");
	if (!g2_is(sa, "CallNode") || !fe_is_var_read(c, fe_ast_ref(c->a, sa, "receiver"), c->param) ||
	    (sr_eqc(c->prog->kind, "ksyscall") && !sr_eqc(sn, "argv_arg")) || (sr_eqc(c->prog->kind, "tracepoint") && !sr_eqc(sn, "argv_field"))) {
		/* strings.Replace(src, "ctx", c.param, 1): src starts with "ctx" */
		g2_reject(c, FE_SB028, sa,
			  "the third argument of output_argv is `%s%c` itself (an argv array is not a value on the eBPF side — not through a local)",
			  c->param, src + 3);
		return 0;
	}
	sr_str want = cat(ctx_class(c->prog->kind), "#", sn);
	sr_str cs = fe_callee(c, sa, &ok);
	if (!ok || !sr_eq(cs, want)) {
		if (ok)
			g2_reject(c, FE_SB011, sa, "`%s` resolves to %s, not BPF::%s", sn, cs, want);
		return 0;
	}
	size_t n_sas;
	const sr_node **sas = fe_args(c->a, sa, &n_sas);
	if (sr_eqc(c->prog->kind, "ksyscall")) {
		fe_kparam *kp = fe_uprobe_param(c, sa, sas, n_sas);
		if (!kp)
			return 0;
		if (!sr_eqc(kp->type, "user_str_array")) {
			g2_reject(c, FE_SB028, sa, "`%s.argv_arg(%d)`: parameter %d is declared :%s, not :user_str_array", c->param, kp->n, kp->n,
				  kp->type);
			return 0;
		}
		os.len = kp->n;
		*out = os;
		return 1;
	}
	if (n_sas != 1 || !g2_is(sas[0], "SymbolNode")) {
		g2_reject(c, FE_SB028, sa,
			  "`%s.argv_field(:f)` takes one Symbol literal — a :user_str_array field declared in `BPF.tracepoint … fields:`", c->param);
		return 0;
	}
	sr_str fn = g2_str(sas[0], "value");
	for (size_t i = 0; i < c->prog->n_t_fields; i++)
		if (sr_eq(c->prog->t_fields[i].name, fn)) {
			if (!sr_eqc(c->prog->t_fields[i].type, "user_str_array")) {
				g2_reject(c, FE_SB028, sas[0], "`%s.argv_field(:%s)`: %s is declared :%s, not :user_str_array", c->param, fn, fn,
					  c->prog->t_fields[i].type);
				return 0;
			}
			os.tp_str = &c->prog->t_fields[i];
			*out = os;
			return 1;
		}
	g2_reject(c, FE_SB028, sas[0], "`%s.argv_field(:%s)`: %s is not declared in `BPF.tracepoint … fields:`", c->param, fn, fn);
	return 0;
}

/* uprobe.go outputStr */
int fe_output_str(fe_prog_ctx *c, const sr_node *call, sr_str name, sr_str ref_var, fe_stmt *out)
{
	sr_str cn = g2_str(call, "name");
	if (sr_eqc(cn, "output_comm"))
		return fe_output_comm(c, call, name, ref_var, out);
	if (sr_eqc(cn, "output_argv"))
		return output_argv(c, call, name, ref_var, out);
	if (sr_eqc(cn, "output_buf"))
		return fe_output_buf(c, call, name, ref_var, out);
	fe_ring_decl *r = fe_ring_of(c, fe_ast_ref(c->a, call, "receiver"));
	int tp_str = sr_eqc(c->prog->kind, "tracepoint");
	size_t n_as;
	const sr_node **as = fe_args(c->a, call, &n_as);
	if (!sr_eqc(c->prog->kind, "uprobe") && !sr_eqc(c->prog->kind, "ksyscall") && !tp_str &&
	    !(n_as >= 3 && g2_is(as[2], "CallNode") && sr_eqc(g2_str(as[2], "name"), "str"))) {
		g2_reject(c, FE_SB028, call,
			  "`%s.%s` reads a user string (`ctx.str_arg(n)` in a uprobe or ksyscall program, `ctx.str_field(:f)` in a tracepoint program), or a kernel string (`q.str(:m)` — a :strptr member of a present kernel pointer)",
			  r->const_name, cn);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, call, &ok);
	if (!ok)
		return 0;
	sr_str meth = cn;
	if (!sr_eq(callee, cat(sr_cstr("RingBuf#"), "", meth))) {
		g2_reject(c, FE_SB011, call, "`%s` resolves to %s, not BPF::RingBuf#%s", meth, callee, meth);
		return 0;
	}
	if (n_as == 3 || (n_as == 4 && !member(r, as[3]))) {
		g2_reject(c, FE_SB024, call,
			  "%s needs a status member: add `status: :i64` to BPF.record(%s, …) and pass it as the fourth argument — a failed read leaves the string member zeroed, the same bytes as an empty string, so only the status tells them apart — %s",
			  cn, r->record->const_name, fe_output_str_shape(r));
		return 0;
	}
	if (n_as != 4) {
		g2_reject(c, FE_SB002, call, "output_str takes four arguments — %s", fe_output_str_shape(r));
		return 0;
	}
	fe_record_field *f = member(r, as[1]), *st = member(r, as[3]);
	if (!f || f->count == 0 || f->bits != 8 || f->is_signed) {
		g2_reject(c, FE_SB024, as[1],
			  "the string member of output_str must be a :u8 array member of %s (`name: [:u8, 32]` — bpf-mlir's user.read_str fills a 1-dimensional 8-bit array)",
			  r->record->const_name);
		return 0;
	}
	if (st->count != 0 || st->bits != 64 || !st->is_signed) {
		g2_reject(c, FE_SB024, as[3],
			  "the status member %s of output_str must be :i64 (the raw status of probe_read_user_str — length with NUL, or a negative errno)",
			  st->name);
		return 0;
	}
	const sr_node *sa = as[2];
	if (g2_is(sa, "CallNode") && sr_eqc(g2_str(sa, "name"), "str"))
		return output_kstr(c, call, as, n_as, r, meth, f, st, name, ref_var, out);
	if (tp_str)
		return output_tp_str(c, call, as, n_as, r, meth, f, st, name, ref_var, out);
	if (!g2_is(sa, "CallNode") || !sr_eqc(g2_str(sa, "name"), "str_arg") || !fe_is_var_read(c, fe_ast_ref(c->a, sa, "receiver"), c->param)) {
		g2_reject(c, FE_SB028, sa,
			  "the third argument of output_str is `%s.str_arg(n)` itself (a user string is not a value on the eBPF side — not through a local)",
			  c->param);
		return 0;
	}
	sr_str want = cat(ctx_class(c->prog->kind), "#str_arg", (sr_str){0});
	sr_str cs = fe_callee(c, sa, &ok);
	if (!ok || !sr_eq(cs, want)) {
		if (ok)
			g2_reject(c, FE_SB011, sa, "`str_arg` resolves to %s, not BPF::%s", cs, want);
		return 0;
	}
	size_t n_sas;
	const sr_node **sas = fe_args(c->a, sa, &n_sas);
	fe_kparam *kp = fe_uprobe_param(c, sa, sas, n_sas);
	if (!kp)
		return 0;
	if (!sr_eqc(kp->type, "user_str")) {
		g2_reject(c, FE_SB028, sa, "`%s.str_arg(%d)`: parameter %d is declared :%s — read it with `%s.arg(%d)`", c->param, kp->n, kp->n,
			  kp->type, c->param, kp->n);
		return 0;
	}
	fe_stmt os = fe_stmt_new("");
	ok = fe_output_str_make(c, call, as, n_as, r, meth, f, st, name, ref_var, &os);
	os.len = kp->n;
	*out = os;
	return ok;
}

/* uprobe.go outputStrMake */
int fe_output_str_make(fe_prog_ctx *c, const sr_node *call, const sr_node *const *as, size_t n_as, fe_ring_decl *r, sr_str meth,
		       fe_record_field *f, fe_record_field *st, sr_str name, sr_str ref_var, fe_stmt *out)
{
	(void)n_as;
	const sr_node *mkn = as[0];
	if (g2_is(mkn, "CallNode") && sr_eqc(g2_str(mkn, "name"), "new") &&
	    sr_eq(fe_const_name(c->a, fe_ast_ref(c->a, mkn, "receiver")), r->record->const_name)) {
		size_t n_vs;
		const sr_node **vs = fe_args(c->a, mkn, &n_vs);
		for (size_t i = 0; i < r->record->n_fields; i++) {
			if (&r->record->fields[i] != st || i >= n_vs)
				continue;
			bigint lit = {0};
			int ok = fe_literal(c->z->z, c->a, vs[i], &lit);
			int nz = lit.n != 0;
			bigint_free(&lit);
			if (!g2_is(vs[i], "IntegerNode") || !ok || nz) {
				g2_reject(c, FE_SB024, vs[i], "the status member %s is written by %s — give the literal 0 in %s.new", st->name, meth,
					  r->record->const_name);
				return 0;
			}
		}
	}
	fe_map_decl *m = sr_alloc(sizeof *m);
	m->name = r->name;
	m->record = r->record;
	fe_expr *mk = fe_record_make(c, mkn, r->record, m, ref_var);
	if (!mk)
		return 0;
	fe_ptr_set_add(&c->used_rings, r);
	fe_stmt s = fe_stmt_new("ostr");
	if (sr_eqc(meth, "output_str_or_discard"))
		s.op = sr_cstr("discard"); /* discard when read_str's status < 0 (an empty string is kept) */
	s.ring = r;
	s.value = mk;
	s.var = name;
	s.path = f->name;
	s.field = st;
	s.pos = g2_pos(c, call);
	*out = s;
	return 1;
}

/* uprobe.go outputStrCheck */
fe_stmts fe_output_str_check(fe_prog_ctx *c, const sr_node *w, const sr_node *ifn, sr_str ref_var, int *ok)
{
	fe_stmts none = {0};
	none.nil = 1;
	*ok = 0;
	sr_str name = g2_str(w, "name");
	const sr_node *v = fe_ast_ref(c->a, w, "value");
	if (v && sr_eqc(g2_str(v, "name"), "output_argv")) {
		g2_reject(c, FE_SB025, w,
			  "the result of output_argv is not bound — it emits up to 20 events (one per present argv slot), so write `_ = %s.output_argv(…)`",
			  fe_const_name(c->a, fe_ast_ref(c->a, v, "receiver")));
		return none;
	}
	if (fe_name_has(&c->env, name) || sr_eq(name, c->param) || fe_name_get(&c->refs, name) || fe_name_get(&c->wins, name) ||
	    fe_name_get(&c->ostrs, name)) {
		g2_reject(c, FE_SB005, w, "`%s` is already bound — an output_str result needs a fresh name", name);
		return none;
	}
	if (!fe_typed(c, w) || !fe_typed(c, fe_ast_ref(c->a, ifn, "predicate")))
		return none;
	sr_str t = fe_rbs(c, w);
	if (!contains(t, "OutputStr")) {
		g2_reject(c, FE_SB005, w, "`%s` is typed %q, not BPF::OutputStr (or nil)", name, t);
		return none;
	}
	fe_stmt s = fe_stmt_new("");
	if (!fe_output_str(c, v, name, ref_var, &s))
		return none;
	fe_name_set(&c->ostrs, name, g2_true);
	fe_name_table pre = c->env;
	c->env = fe_copy_env(&pre);
	sr_str k_status = cat(name, "#status", (sr_str){0}), k_sent = cat(name, "#sent", (sr_str){0});
	fe_name_set(&c->env, k_status, var_new(0, fe_full_i64));
	fe_name_set(&c->env, k_sent, var_new(1, (fe_ival){0}));
	fe_name_set(&c->ostr_live, name, g2_true);
	fe_stmts then_s = arm(c, ifn, ref_var);
	fe_name_delete(&c->ostr_live, name);
	fe_name_delete(&c->env, k_status);
	fe_name_delete(&c->env, k_sent);
	fe_name_table then_env = c->env;
	c->env = fe_copy_env(&pre);
	fe_stmts else_s = none;
	const sr_node *sub = fe_ast_ref(c->a, ifn, "subsequent");
	if (sub) {
		if (!sr_eqc(sub->type, "ElseNode")) {
			g2_reject(c, FE_SB005, sub, "`elsif` is not accepted after `if %s`", name);
			return none;
		}
		else_s = arm(c, sub, ref_var);
	}
	c->env = fe_join_arms(&pre, &then_env, &c->env, fe_escapes(&then_s), fe_escapes(&else_s));
	fe_expr *cond = g2_expr("var", g2_pos(c, fe_ast_ref(c->a, ifn, "predicate")));
	cond->var = name;
	cond->bool_ = 1;
	fe_stmt ifs = fe_stmt_new("if");
	ifs.cond = cond;
	ifs.then = then_s;
	ifs.else_ = else_s;
	ifs.pos = g2_pos(c, ifn);
	fe_stmts res = {0};
	fe_stmts_push(&res, s);
	fe_stmts_push(&res, ifs);
	*ok = 1;
	return res;
}

/* uprobe.go ostrStatus */
fe_expr *fe_ostr_status(fe_prog_ctx *c, const sr_node *n, const sr_node *recv, fe_pos p)
{
	sr_str name = g2_str(recv, "name");
	sr_str m = g2_str(n, "name");
	if (!fe_name_get(&c->ostr_live, name)) {
		g2_reject(c, FE_SB005, n, "`%s.%s` is read only inside `if %s` right after `%s = R.output_str(…)`", name, m, name, name);
		return NULL;
	}
	int ok;
	sr_str cs = fe_callee(c, n, &ok);
	if (!ok || !sr_eq(cs, cat(sr_cstr("OutputStr#"), "", m))) {
		if (ok)
			g2_reject(c, FE_SB011, n, "`%s` resolves to %s, not BPF::OutputStr#%s", m, cs, m);
		return NULL;
	}
	size_t n_as;
	fe_args(c->a, n, &n_as);
	if (n_as != 0) {
		g2_reject(c, FE_SB002, n, "`%s.%s` takes no arguments", name, m);
		return NULL;
	}
	fe_expr *e = g2_expr("var", p);
	if (sr_eqc(m, "sent")) {
		e->var = cat(name, "#sent", (sr_str){0});
		e->bool_ = 1;
		return e;
	}
	e->var = cat(name, "#status", (sr_str){0});
	e->iv = fe_full_i64;
	return e;
}
