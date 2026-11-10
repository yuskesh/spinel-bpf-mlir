/* body_kread — G2's kprobe pointer reads: kread.go (kreadStmt, kreadBind, kreadStatusOK) and tpcopy.go (isTpCopy,
 * ctxCopyOtherKind, tpCopyField, tpcopyStmt). Each comment names the Go it follows (internal/frontend at main c204310). */
#include "body_g2.h"

#include <stdint.h>

#define KREAD_MAX_OFFSET 4095 /* kread.go kreadMaxOffset */

static fe_var_info *var_new(fe_ival iv)
{
	fe_var_info *v = sr_alloc(sizeof *v);
	v->iv = iv;
	v->from_nil = 1;
	return v;
}

/* kread.go kreadBind (the literals are freed by the caller) */
static int kread_bind(fe_prog_ctx *c, const sr_node *n, fe_stmt *out, bigint *nb, bigint *ob)
{
	size_t n_ts, n_rights;
	const sr_node **ts = fe_ast_arr(c->a, n, "lefts", &n_ts);
	const sr_node *v = fe_ast_ref(c->a, n, "value");
	fe_ast_arr(c->a, n, "rights", &n_rights);
	if (!sr_eqc(c->prog->kind, "kprobe") || !g2_is(v, "CallNode") || !sr_eqc(g2_str(v, "name"), "read") || n_ts != 2 ||
	    fe_ast_ref(c->a, n, "rest") || n_rights != 0) {
		g2_reject(c, FE_SB028, n,
			  "a multiple assignment is accepted only as `v, st = %s.read(n, offset, :type)` in a kprobe program (two locals — the value and the status)",
			  c->param);
		return 0;
	}
	for (size_t i = 0; i < n_ts; i++)
		if (!g2_is(ts[i], "LocalVariableTargetNode")) {
			g2_reject(c, FE_SB028, ts[i], "`… = %s.read(…)` assigns two plain locals (the value and the status)", c->param);
			return 0;
		}
	int ok;
	sr_str callee = fe_callee(c, v, &ok);
	if (!ok)
		return 0;
	if (!sr_eqc(callee, "KprobeCtx#read")) {
		g2_reject(c, FE_SB011, v, "`read` resolves to %q, not BPF::KprobeCtx#read", callee);
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, v, &n_as);
	if (n_as != 3 || !g2_is(as[0], "IntegerNode") || !g2_is(as[1], "IntegerNode") || !g2_is(as[2], "SymbolNode")) {
		g2_reject(c, FE_SB028, v,
			  "`%s.read(n, offset, :type)` takes a parameter number, an offset (Integer literals) and a type Symbol :i8 … :u64",
			  c->param);
		return 0;
	}
	int ok1 = fe_literal(c->z->z, c->a, as[0], nb);
	int ok2 = fe_literal(c->z->z, c->a, as[1], ob);
	if (!ok1 || !ok2)
		return 0;
	int64_t ni = 0, oi = 0;
	int n64 = g2_big_i64(nb, &ni), o64 = g2_big_i64(ob, &oi);
	fe_kparam *kp = NULL;
	for (size_t k = 0; k < c->prog->n_params; k++)
		if (n64 && c->prog->params[k].n == ni)
			kp = &c->prog->params[k];
	if (!kp || !sr_eqc(kp->type, "ptr")) {
		g2_reject(c, FE_SB028, as[0], "`%s.read(%B, …)`: parameter %B is not declared :ptr in `BPF.kprobe … params:`", c->param,
			  (const bigint *)nb, (const bigint *)nb);
		return 0;
	}
	if (!o64 || oi < 0 || oi > KREAD_MAX_OFFSET) {
		g2_reject(c, FE_SB028, as[1], "`%s.read(%B, %B, …)`: the offset is 0..%d", c->param, (const bigint *)nb, (const bigint *)ob,
			  (int64_t)KREAD_MAX_OFFSET);
		return 0;
	}
	sr_str t = g2_str(as[2], "value");
	int64_t bits;
	int is_signed;
	if (!g2_record_type(t, &bits, &is_signed)) {
		g2_reject(c, FE_SB028, as[2], "`%s.read(…, :%s)`: the type is one of :i8 … :i64 / :u8 … :u64", c->param, t);
		return 0;
	}
	sr_str vn = g2_str(ts[0], "name"), sn = g2_str(ts[1], "name");
	if (sr_eqc(sn, "_")) {
		g2_reject(c, FE_SB026, ts[1],
			  "the status of `%s.read` is dropped — a failed read returns 0 like a real 0; receive it as `v, st = %s.read(…)` and read `st` (e.g. `if st == 0`)",
			  c->param, c->param);
		return 0;
	}
	sr_str names[2] = {vn, sn};
	for (int i = 0; i < 2; i++) {
		sr_str name = names[i];
		if (sr_eqc(name, "_"))
			continue;
		if (fe_name_has(&c->env, name) || sr_eq(name, c->param) || fe_name_get(&c->refs, name) || fe_name_get(&c->wins, name) ||
		    fe_name_get(&c->kptrs, name)) {
			g2_reject(c, FE_SB028, n, "`%s` is already bound — `v, st = %s.read(…)` binds two fresh names", name, c->param);
			return 0;
		}
	}
	sr_buf what = {0};
	sr_putstr(&what, c->param);
	sr_puts(&what, ".read");
	if (!fe_kread_status_ok(c, ts[1], sn, sr_bufstr(&what), sr_cstr("a failed read returns 0 like a real 0")))
		return 0;
	fe_record_field *f = sr_alloc(sizeof *f);
	f->name = t;
	f->bits = bits;
	f->is_signed = is_signed;
	if (!sr_eqc(vn, "_")) {
		fe_var_info *vi = var_new(fe_width_range(f->bits, f->is_signed));
		if (f->bits == 64 && !f->is_signed) {
			vi->iv = fe_iv(intv_from_i64(0), intv_from_u64(UINT64_MAX));
			vi->wide = 1; /* a u64 read: the 64 bits are held as i64, so the value is Wide like a u64 map value */
		}
		fe_name_set(&c->env, vn, vi);
	}
	fe_name_set(&c->env, sn, var_new(fe_iv(intv_from_i64(INT64_MIN), intv_from_i64(0)))); /* the raw status: 0 or negative */
	fe_stmt s = fe_stmt_new("kread");
	s.var = vn;
	s.path = sn;
	s.field = f;
	s.count = ni;
	s.len = oi;
	s.pos = g2_pos(c, n);
	*out = s;
	return 1;
}

/* kread.go kreadStmt */
int fe_kread_stmt(fe_prog_ctx *c, const sr_node *n, fe_stmt *out)
{
	bigint nb = {0}, ob = {0};
	int ok = kread_bind(c, n, out, &nb, &ob);
	bigint_free(&nb);
	bigint_free(&ob);
	if (!ok) { /* the locals of a stopped read are not reported again by later reads (as assign's poisoned) */
		size_t k;
		const sr_node **ts = fe_ast_arr(c->a, n, "lefts", &k);
		for (size_t i = 0; i < k; i++)
			if (g2_is(ts[i], "LocalVariableTargetNode"))
				fe_name_set(&c->poisoned, g2_str(ts[i], "name"), g2_true);
	}
	return ok;
}

typedef struct {
	sr_str name;
	int64_t writes, reads;
} status_count;

static int count_status(void *u, const sr_node *x)
{
	status_count *s = u;
	if (!sr_eq(g2_str(x, "name"), s->name))
		return 1;
	if (sr_eqc(x->type, "LocalVariableWriteNode") || sr_eqc(x->type, "LocalVariableOperatorWriteNode") ||
	    sr_eqc(x->type, "LocalVariableOrWriteNode") || sr_eqc(x->type, "LocalVariableAndWriteNode") ||
	    sr_eqc(x->type, "LocalVariableTargetNode"))
		s->writes++;
	else if (sr_eqc(x->type, "LocalVariableReadNode"))
		s->reads++;
	return 1;
}

/* kread.go kreadStatusOK */
int fe_kread_status_ok(fe_prog_ctx *c, const sr_node *t, sr_str name, sr_str what, sr_str failed)
{
	status_count s = {name, 0, 0};
	fe_walk(c->a, c->def, count_status, &s);
	if (s.writes != 1) {
		g2_reject(c, FE_SB026, t, "`%s` holds the status of `%s` but is assigned %d times — a status local is assigned once", name, what,
			  s.writes);
		return 0;
	}
	if (s.reads == 0) {
		g2_reject(c, FE_SB026, t, "`%s` holds the status of `%s` but is never read — check it (e.g. `if %s == 0`): %s", name, what, name,
			  failed);
		return 0;
	}
	return 1;
}

/* tpcopy.go isTpCopy */
int fe_is_tp_copy(fe_prog_ctx *c, const sr_node *x)
{
	return g2_is(x, "CallNode") && sr_eqc(g2_str(x, "name"), "copy") && c->prog && sr_eqc(c->prog->kind, "tracepoint") &&
	       fe_is_var_read(c, fe_ast_ref(c->a, x, "receiver"), c->param);
}

/* tpcopy.go ctxCopyOtherKind */
int fe_ctx_copy_other_kind(fe_prog_ctx *c, const sr_node *x)
{
	if (!g2_is(x, "CallNode") || !sr_eqc(g2_str(x, "name"), "copy") || !c->prog || sr_eqc(c->prog->kind, "tracepoint") ||
	    c->param.n == 0 || !fe_is_var_read(c, fe_ast_ref(c->a, x, "receiver"), c->param))
		return 0;
	sr_str k = fe_ctx_kind_of(c);
	g2_reject(c, FE_SB028, x, "the %s context has no `copy` — it reads %c", k, fe_ctx_reads(k));
	return 1;
}

/* tpcopy.go tpCopyField */
fe_tp_field *fe_tp_copy_field(fe_prog_ctx *c, const sr_node *x, const sr_node *at, fe_record_field *rf, sr_str rec_const, int *ok)
{
	*ok = 0;
	int cok;
	sr_str cs = fe_callee(c, x, &cok);
	if (!cok || !sr_eqc(cs, "TracepointCtx#copy")) {
		if (cok)
			g2_reject(c, FE_SB011, x, "`copy` resolves to %s, not BPF::TracepointCtx#copy", cs);
		return NULL;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, x, &n_as);
	if (n_as != 1 || !g2_is(as[0], "SymbolNode")) {
		g2_reject(c, FE_SB028, x, "`%s.copy(:f)` takes one Symbol literal — a byte array field declared in `BPF.tracepoint … fields:`",
			  c->param);
		return NULL;
	}
	sr_str fn = g2_str(as[0], "value");
	fe_tp_field *tf = NULL;
	for (size_t i = 0; i < c->prog->n_t_fields; i++)
		if (sr_eq(c->prog->t_fields[i].name, fn))
			tf = &c->prog->t_fields[i];
	if (!tf) {
		g2_reject(c, FE_SB028, as[0],
			  "`%s.copy(:%s)`: %s is not declared in `BPF.tracepoint … fields:` (declare `%s: [offset, [:u8, N]]` from the tracefs format)",
			  c->param, fn, fn, fn);
		return NULL;
	}
	if (tf->n == 0) {
		g2_reject(c, FE_SB028, as[0], "`%s.copy(:%s)`: %s is declared :%s, not a byte array — read it with `%s.field(:%s)`", c->param, fn,
			  fn, tf->type, c->param, fn);
		return NULL;
	}
	if (rf->count == 0 || rf->bits != 8) {
		g2_reject(c, FE_SB028, at, "member %s of %s is not an 8-bit array — `%s.copy(:%s)` copies %d bytes into a `[:u8, %d]` member",
			  rf->name, rec_const, c->param, fn, tf->n, tf->n);
		return NULL;
	}
	if (rf->count != tf->n) {
		g2_reject(c, FE_SB028, at,
			  "member %s of %s has %d elements but %s is a %d-byte array — the copy is a fixed N bytes, declare the same N", rf->name,
			  rec_const, rf->count, fn, tf->n);
		return NULL;
	}
	*ok = 1;
	return tf;
}

/* tpcopy.go tpcopyStmt */
int fe_tpcopy_stmt(fe_prog_ctx *c, const sr_node *n, const sr_node *cp, sr_str ref, fe_map_decl *m, fe_record_field *rf, fe_stmt *out)
{
	int ok;
	fe_tp_field *tf = fe_tp_copy_field(c, cp, n, rf, m->record->const_name, &ok);
	if (!ok)
		return 0;
	fe_stmt s = fe_stmt_new("tpcopy");
	s.var = ref;
	s.map = m;
	s.field = rf;
	s.tp_copy = tf;
	s.pos = g2_pos(c, n);
	*out = s;
	return 1;
}
