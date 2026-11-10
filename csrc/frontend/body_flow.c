/* body_flow — G2's flow-dissector keys and fmod_ret return values: flow.go (flowFieldArgs, flowKeyRead, flowKeyStore)
 * and fmodret.go (isFmodReturn, fmodReturnArg, fmodNonZeroI32, fmodVerdict, fmodGuardValue). Each comment names the Go it follows
 * (internal/frontend at main c204310). */
#include "body_g2.h"

/* flow.go flowField and flowFields */
typedef struct {
	const char *name;
	int64_t bits, count;
} flow_field;

static const flow_field flow_fields[] = {
	{"nhoff", 16, 1},    {"thoff", 16, 1},    {"addr_proto", 16, 1}, {"is_frag", 8, 1},  {"is_first_frag", 8, 1}, {"is_encap", 8, 1},
	{"ip_proto", 8, 1},  {"n_proto", 16, 1},  {"sport", 16, 1},      {"dport", 16, 1},   {"ipv4_src", 32, 1},     {"ipv4_dst", 32, 1},
	{"ipv6_src", 32, 4}, {"ipv6_dst", 32, 4}, {"flags", 32, 1},      {"flow_label", 32, 1},
};

/* flow.go flowFieldArgs: the field's name, its row and the index (−1: none) */
static int flow_field_args(fe_prog_ctx *c, const sr_node *n, const sr_node *const *as, size_t n_as, const char *what, sr_str *name_out,
			   const flow_field **f_out, int64_t *idx_out)
{
	if (n_as < 1 || !g2_is(as[0], "SymbolNode")) {
		g2_reject(c, FE_SB002, n,
			  "`%s.%c` takes the flow key's name as a Symbol literal (`:nhoff`, `:ipv4_src`, `:ipv6_src` with an index …)", c->param,
			  what);
		return 0;
	}
	sr_str name = g2_str(as[0], "value");
	const flow_field *f = NULL;
	for (size_t i = 0; i < sizeof flow_fields / sizeof flow_fields[0]; i++)
		if (sr_eqc(name, flow_fields[i].name))
			f = &flow_fields[i];
	if (!f) {
		g2_reject(c, FE_SB002, as[0],
			  "`:%s` is not a field of struct bpf_flow_keys (nhoff thoff addr_proto is_frag is_first_frag is_encap ip_proto n_proto sport dport ipv4_src ipv4_dst ipv6_src[i] ipv6_dst[i] flags flow_label)",
			  name);
		return 0;
	}
	int64_t idx = -1;
	if (f->count == 4 && n_as == 2) {
		bigint b = {0};
		int lok = fe_literal(c->z->z, c->a, as[1], &b);
		int64_t v = 0;
		int is64 = lok && g2_big_i64(&b, &v);
		bigint_free(&b);
		if (!g2_is(as[1], "IntegerNode") || !lok || !is64 || v < 0 || v > 3) {
			g2_reject(c, FE_SB014, as[1], "the index of `:%s` is an Integer literal 0..3", name);
			return 0;
		}
		idx = v;
	} else if (f->count == 4) {
		g2_reject(c, FE_SB002, n, "`:%s` has 4 elements — give an Integer literal index 0..3 (`%s.%c(:%s, i…)`)", name, c->param, what,
			  name);
		return 0;
	} else if (n_as != 1) {
		g2_reject(c, FE_SB002, n, "`:%s` has no index", name);
		return 0;
	}
	*name_out = name;
	*f_out = f;
	*idx_out = idx;
	return 1;
}

/* flow.go flowKeyRead */
fe_expr *fe_flow_key_read(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	(void)ref_var;
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return NULL;
	if (!sr_eqc(callee, "FlowCtx#key")) {
		g2_reject(c, FE_SB011, n, "`key` resolves to %s, not BPF::FlowCtx#key", callee);
		return NULL;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, n, &n_as);
	sr_str name;
	const flow_field *f;
	int64_t idx;
	if (!flow_field_args(c, n, as, n_as, "key", &name, &f, &idx))
		return NULL;
	fe_record_field *rf = sr_alloc(sizeof *rf);
	rf->name = name;
	rf->bits = f->bits;
	fe_expr *e = g2_expr("fkload", g2_pos(c, n));
	e->field = rf;
	e->idx = idx;
	e->iv = fe_width_range(f->bits, 0);
	return e;
}

/* flow.go flowKeyStore */
int fe_flow_key_store(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out)
{
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return 0;
	if (!sr_eqc(callee, "FlowCtx#set_key")) {
		g2_reject(c, FE_SB011, n, "`set_key` resolves to %s, not BPF::FlowCtx#set_key", callee);
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, n, &n_as);
	if (n_as < 2) {
		g2_reject(c, FE_SB002, n, "`%s.set_key(:f, [i,] v)` takes the key's name, an index for ipv6_src / ipv6_dst, and the value",
			  c->param);
		return 0;
	}
	sr_str name;
	const flow_field *f;
	int64_t idx;
	if (!flow_field_args(c, n, as, n_as - 1, "set_key", &name, &f, &idx))
		return 0;
	const sr_node *vn = as[n_as - 1];
	fe_expr *e = fe_ctx_expr(c, vn, ref_var);
	if (!e)
		return 0;
	fe_ival r = fe_width_range(f->bits, 0);
	if (e->bool_ || e->wide || !fe_iv_within(e->iv, r.lo, r.hi)) {
		g2_reject(c, FE_SB014, vn, "the value's range %I does not fit bpf_flow_keys.%s (u%d %I) — the store would truncate silently; narrow it",
			  e->iv, name, f->bits, r);
		return 0;
	}
	fe_stmt s = fe_stmt_new("fkstore");
	s.path = name;
	s.count = idx;
	s.val = e;
	s.pos = g2_pos(c, n);
	*out = s;
	return 1;
}

/* fmodret.go isFmodReturn */
int fe_is_fmod_return(fe_prog_ctx *c, const sr_node *n)
{
	return g2_is(n, "CallNode") && sr_eqc(g2_str(n, "name"), "fmod_return") &&
	       sr_eqc(fe_const_name(c->a, fe_ast_ref(c->a, n, "receiver")), "BPF");
}

/* fmodret.go fmodReturnArg */
static const sr_node *fmod_return_arg(fe_prog_ctx *c, const sr_node *v)
{
	int ok;
	sr_str callee = fe_callee(c, v, &ok);
	if (!ok)
		return NULL;
	size_t n_as;
	const sr_node **as = fe_args(c->a, v, &n_as);
	if (!sr_eqc(callee, "BPF.fmod_return") || n_as != 1) {
		g2_reject(c, FE_SB011, v, "`BPF.fmod_return` resolves to %q (with %d arguments), not the library's BPF.fmod_return(e)", callee,
			  (int64_t)n_as);
		return NULL;
	}
	return as[0];
}

/* fmodret.go fmodNonZeroI32 */
static int fmod_non_zero_i32(fe_prog_ctx *c, fe_ival iv, const sr_node *n)
{
	if (intv_sign(iv.lo) <= 0 && intv_sign(iv.hi) >= 0) {
		g2_reject(c, FE_SB014, n,
			  "the value of `BPF.fmod_return(e)` may be 0 (its range is %I) — 0 means \"call the original function\", so a replaced return value must be provably non-zero; return BPF::FMOD_CALL for that path instead",
			  iv);
		return 0;
	}
	if (intv_cmp(iv.lo, intv_from_i64(INT32_MIN)) < 0 || intv_cmp(iv.hi, intv_from_i64(INT32_MAX)) > 0) {
		g2_reject(c, FE_SB014, n, "the value of `BPF.fmod_return(e)` may not fit the i32 return value (its range is %I) — narrow it first",
			  iv);
		return 0;
	}
	return 1;
}

/* fmodret.go fmodVerdict */
void fe_fmod_verdict(fe_prog_ctx *c, const sr_node *n, const sr_node *v)
{
	if (!sr_eqc(c->prog->kind, "fmod_ret")) {
		g2_reject(c, FE_SB028, v, "`BPF.fmod_return` ends only a fmod_ret program — %s", fe_verdict_returns(c->prog->kind));
		return;
	}
	const sr_node *en = fmod_return_arg(c, v);
	if (!en)
		return;
	if (c->prog->guard_verdict.n != 0 && !sr_eqc(en->type, "IntegerNode")) {
		g2_reject(c, FE_SB006, en,
			  "with a guard `return … if cond`, the last `BPF.fmod_return(e)` takes an integer literal — the terminal arith.select of bpf-mlir's ebpf.return chooses between program-level values");
		return;
	}
	fe_expr *e = fe_ctx_expr(c, en, (sr_str){0});
	if (!e)
		return;
	if (e->bool_) {
		g2_reject(c, FE_SB001, en, "`BPF.fmod_return(e)` takes an Integer, not a bool");
		return;
	}
	if (!fe_value_ok(c, e, en) || !fmod_non_zero_i32(c, e->iv, en))
		return;
	c->prog->verdict = sr_cstr("done");
	c->prog->fmod_val = e;
	c->prog->verdict_pos = g2_pos(c, n);
}

/* fmodret.go fmodGuardValue */
bigint *fe_fmod_guard_value(fe_prog_ctx *c, const sr_node *r, const sr_node *v, int *ok)
{
	(void)r;
	*ok = 0;
	const sr_node *en = fmod_return_arg(c, v);
	if (!en)
		return NULL;
	if (!sr_eqc(en->type, "IntegerNode") || !fe_typed(c, en)) {
		g2_reject(c, FE_SB006, en,
			  "a guard `return BPF.fmod_return(e) if cond` takes an integer literal e — the terminal arith.select of bpf-mlir's ebpf.return chooses between program-level values");
		return NULL;
	}
	bigint *lit = sr_alloc(sizeof *lit);
	if (!fe_literal(c->z->z, c->a, en, lit))
		return NULL;
	int fits;
	intv x = fe_intv_of_big(lit, &fits);
	if (!fits) {
		fe_not_ported(c->z->z, "fmodGuardValue: a literal beyond 128 bits");
		return NULL;
	}
	if (!fmod_non_zero_i32(c, fe_iv(x, x), en))
		return NULL;
	*ok = 1;
	return lit;
}
