/* body_u64 — the u64 intrinsics: the C twin of internal/frontend/u64ops.go's analysis (u64Op, u64Operand,
 * u64Divisor). The messages are Go's, byte for byte. */
#include "body.h"
#include "body_priv.h"
#include "core.h"
#include "top_int.h"

#include <string.h>

static const char *const u64_ops[] = {"u64_add", "u64_sub", "u64_mul", "u64_div", "time_before", NULL};

/* u64Ops */
int fe_is_u64_op(sr_str name)
{
	return t_in(name, u64_ops);
}

/* u64Operand: a Wide value, or an Integer in [0, 2^63 − 1] */
static fe_expr *u64_operand(fe_prog_ctx *c, sr_str op, int64_t i, const sr_node *x, sr_str ref_var)
{
	fe_expr *e = fe_ctx_expr(c, x, ref_var);
	if (!e)
		return NULL;
	if (e->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB014, x, "operand %d of `BPF.%s` is a bool, not a u64 value", i, op);
		return NULL;
	}
	if (e->wide)
		return e;
	fe_ival r = fe_width_range(64, 0);
	if (!fe_ival_within(e->iv, r.lo, r.hi)) {
		fe_cadd(c, FE_REJECTED, FE_SB014, x,
			"operand %d of `BPF.%s` is an Integer that may be negative (its interval %I is not within %I) — a u64 operand is a u64 value or a non-negative Integer",
			i, op, e->iv, r);
		return NULL;
	}
	return e;
}

/* u64Divisor: an Integer whose interval is within [1, 2^63 − 1] */
static fe_expr *u64_divisor(fe_prog_ctx *c, const sr_node *x, sr_str ref_var)
{
	fe_expr *e = fe_ctx_expr(c, x, ref_var);
	if (!e)
		return NULL;
	if (e->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB014, x, "the divisor of `BPF.u64_div` is a bool, not an Integer");
		return NULL;
	}
	if (e->wide) {
		fe_cadd(c, FE_REJECTED, FE_SB014, x,
			"the divisor of `BPF.u64_div` is a u64 value, which may be 0 — narrow it into an Integer within [1, 2^63 − 1] with an `if`");
		return NULL;
	}
	if (!fe_ival_within(e->iv, intv_from_i64(1), fe_i64_max)) {
		fe_cadd(c, FE_REJECTED, FE_SB014, x,
			"the divisor of `BPF.u64_div` may be 0 (its interval %I is not within [1, 9223372036854775807]) — narrow it with an `if`, e.g. `d = 1` / `if w > 0` / `d = w`",
			e->iv);
		return NULL;
	}
	return e;
}

/* u64Op: `BPF.<op>(a, b)` */
fe_expr *fe_u64_op(fe_prog_ctx *c, const sr_node *n, sr_str name, t_nodes as, sr_str ref_var, fe_pos p)
{
	if (as.n != 2) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "`BPF.%s` takes two operands, got %d", name, (int64_t)as.n);
		return NULL;
	}
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return NULL;
	if (!(callee.n == 4 + name.n && memcmp(callee.p, "BPF.", 4) == 0 && memcmp(callee.p + 4, name.p, name.n) == 0)) {
		fe_cadd(c, FE_REJECTED, FE_SB011, n, "`BPF.%s` resolves to %q, not the library's BPF.%s", name, callee, name);
		return NULL;
	}
	fe_expr *a = u64_operand(c, name, 1, as.v[0], ref_var);
	fe_expr *b = fe_streq(name, "u64_div") ? u64_divisor(c, as.v[1], ref_var) : u64_operand(c, name, 2, as.v[1], ref_var);
	if (!a || !b)
		return NULL;
	fe_expr *e = fe_expr_new("u64op", p);
	e->op = name;
	fe_expr *ab[2] = {a, b};
	fe_expr_args(e, ab, 2);
	if (fe_streq(name, "time_before")) {
		e->bool_ = 1;
		return e;
	}
	e->iv = fe_iv(intv_from_i64(0), fe_u64_max);
	e->wide = 1;
	return e;
}
