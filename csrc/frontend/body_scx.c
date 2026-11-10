/* body_scx — the sched_ext ops: the C twin of internal/frontend/scx.go's analysis (isScxCall, scxPlaceOK, scxTask,
 * scxOperand, scxArgs, scxStmt, scxExpr, scxConst, scxSelect, scxMultiRefused, poisonTargets). The messages are Go's, byte for byte. */
#include "body.h"
#include "body_priv.h"
#include "core.h"
#include "top_int.h"

#include <string.h>

static int one_ = 1;
#define TRUE_ ((void *)&one_)

/* scxOp: whether the first argument is the checked task, the widths of the Integer operands, and the result */
typedef struct {
	const char *name;
	int task;
	int nargs;
	int bits[4];
	const char *res; /* "" a statement, "bool", "status", "pair" */
} scx_op;

static const scx_op scx_ops[] = {
    {"select_cpu_dfl", 1, 2, {32, 64}, "pair"},
    {"dsq_insert", 1, 3, {64, 64, 64}, ""},
    {"dsq_insert_vtime", 1, 4, {64, 64, 64, 64}, ""},
    {"dsq_move_to_local", 0, 1, {64}, "bool"},
    {"create_dsq", 0, 2, {64, 32}, "status"},
    {"task_set_dsq_vtime", 1, 1, {64}, ""},
    {"error", 0, 0, {0}, ""},
    {"exit_info", 0, 0, {0}, ""},
};

enum { SCX_MAX_ERROR_ARGS = 12 }; /* MAX_BPRINTF_VARARGS (bpf-mlir ebpf.scx.error) */

static const scx_op *op_of(sr_str name)
{
	for (size_t i = 0; i < sizeof scx_ops / sizeof scx_ops[0]; i++)
		if (sr_eqc(name, scx_ops[i].name))
			return &scx_ops[i];
	return NULL;
}

int fe_scx_op_bits(sr_str op, int i) { return op_of(op)->bits[i]; }

/* scxStatusDecl: names create_dsq in the status rule's messages (SB026 — hash.go's wording) */
static fe_map_decl scx_status_decl = {.const_name = {"BPF::Scx", 8}};

static fe_ival i32_range(void) { return fe_iv(intv_from_i64(INT32_MIN), intv_from_i64(INT32_MAX)); }

static sr_str nm(const sr_node *n) { return t_str(n, "name"); }

/* isScxCall */
int fe_is_scx_call(fe_prog_ctx *c, const sr_node *n)
{
	if (!n || !t_is(n, "CallNode") || !sr_eqc(fe_const_name(c->a, t_ref(c->a, n, "receiver")), "BPF::Scx"))
		return 0;
	return op_of(nm(n)) != NULL;
}

/* progWhat */
static sr_str prog_what(fe_prog_ctx *c) { return sr_eqc(c->prog->kind, "struct_ops") ? c->prog->so_type : c->prog->kind; }

static int is_sched_ext(fe_prog_ctx *c) { return sr_eqc(c->prog->kind, "struct_ops") && sr_eqc(c->prog->so_type, "sched_ext_ops"); }

/* scxPlaceOK */
static int place_ok(fe_prog_ctx *c, const sr_node *n)
{
	sr_str name = nm(n);
	if (!is_sched_ext(c)) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "`BPF::Scx.%s` is a sched_ext op — only a callback of a sched_ext_ops table calls it, not a %s program",
			name, prog_what(c));
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok)
		return 0;
	if (!sr_eq(callee, t_cat(t_s("Scx."), name))) { /* Spinel's callee of a module function of BPF::Scx */
		fe_cadd(c, FE_REJECTED, FE_SB011, n, "`BPF::Scx.%s` resolves to %q, not the library's BPF::Scx.%s", name, callee, name);
		return 0;
	}
	c->prog->scx = 1;
	return 1;
}

/* scxTask */
static int scx_task(fe_prog_ctx *c, const sr_node *n, const sr_node *x, sr_str *t, fe_kernel_type_decl **kt)
{
	sr_str name = nm(n);
	if (x && t_is(x, "LocalVariableReadNode")) {
		sr_str v = nm(x);
		fe_kernel_type_decl *d = fe_name_get(&c->kptrs, v);
		if (d && sr_eqc(d->name, "task_struct")) {
			*t = v;
			*kt = d;
			return 1;
		}
		if (fe_name_get(&c->kchecked, v)) {
			fe_cadd(c, FE_REJECTED, FE_SB005, x, "`%s` (a nullable kernel pointer) may be passed to `BPF::Scx.%s` only inside its `if %s`", v,
				name, v);
			return 0;
		}
	}
	fe_cadd(c, FE_REJECTED, FE_SB033, n,
		"the first argument of `BPF::Scx.%s` is the checked task pointer (`p = %s.kptr_or_null(i, TaskT)`, inside `if p`)", name, c->param);
	return 0;
}

/* scxOperand */
static fe_expr *scx_operand(fe_prog_ctx *c, sr_str op, const sr_node *x, int bits, sr_str ref_var)
{
	fe_expr *e = fe_ctx_expr(c, x, ref_var);
	if (!e)
		return NULL;
	if (e->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB014, x, "`BPF::Scx.%s` takes an Integer here, not a Bool", op);
		return NULL;
	}
	if (bits == 64) {
		if (e->wide)
			return e;
		fe_ival r = fe_width_range(64, 0);
		if (!fe_ival_within(e->iv, r.lo, r.hi)) {
			fe_cadd(c, FE_REJECTED, FE_SB014, x,
				"the value's range %I does not fit this u64 operand of `BPF::Scx.%s` (%I for an Integer) — the op would see another number",
				e->iv, op, r);
			return NULL;
		}
		return e;
	}
	fe_ival r = i32_range();
	if (e->wide || !fe_ival_within(e->iv, r.lo, r.hi)) {
		if (e->wide)
			fe_cadd(c, FE_REJECTED, FE_SB014, x, "a u64 value does not fit this i32 operand of `BPF::Scx.%s` (%I)", op, r);
		else
			fe_cadd(c, FE_REJECTED, FE_SB014, x, "the value's range %I does not fit this i32 operand of `BPF::Scx.%s` (%I)", e->iv, op, r);
		return NULL;
	}
	return e;
}

/* scxArgs: the task local, its type and the operands */
static int scx_args(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, sr_str *t, fe_kernel_type_decl **kt, fe_expr ***es, size_t *n_es)
{
	sr_str name = nm(n);
	const scx_op *op = op_of(name);
	t_nodes as = t_args(c->a, n);
	int64_t want = op->nargs + (op->task ? 1 : 0);
	if ((int64_t)as.n != want) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "`BPF::Scx.%s` takes %d arguments, got %d", name, want, (int64_t)as.n);
		return 0;
	}
	*t = (sr_str){"", 0};
	*kt = NULL;
	size_t k = 0;
	if (op->task) {
		if (!scx_task(c, n, as.v[0], t, kt))
			return 0;
		k = 1;
	}
	fe_expr **v = NULL;
	size_t nv = 0;
	for (size_t i = k; i < as.n; i++) {
		fe_expr *e = scx_operand(c, name, as.v[i], op->bits[i - k], ref_var);
		if (!e)
			return 0;
		T_PUSH(v, nv, e);
	}
	*es = v;
	*n_es = nv;
	return 1;
}

static void set_args(fe_stmt *s, fe_expr **es, size_t n)
{
	s->scx_args = es;
	s->n_scx_args = n;
	s->scx_args_nil = es == NULL;
}

static const char *pair_msg = "`BPF::Scx.select_cpu_dfl` gives two values — write `cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)`";

/* scxStmt: 1 when n is a `BPF::Scx.<op>(…)` statement (handled), with *ok and *out */
int fe_scx_stmt(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok)
{
	*ok = 0;
	if (!fe_is_scx_call(c, n))
		return 0;
	sr_str name = nm(n);
	if (!place_ok(c, n))
		return 1;
	fe_pos pos = fe_cpos(c, n);
	if (sr_eqc(name, "create_dsq")) {
		fe_cadd(c, FE_REJECTED, FE_SB026, n, "%s", fe_status_ignored(&scx_status_decl, name));
		return 1;
	}
	if (sr_eqc(name, "select_cpu_dfl")) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "%S", pair_msg);
		return 1;
	}
	if (sr_eqc(name, "error")) {
		t_nodes as = t_args(c->a, n);
		sr_str f = as.n >= 1 ? t_str(as.v[0], "content") : (sr_str){"", 0};
		if (as.n < 1 || !t_is(as.v[0], "StringNode") || f.n == 0 || memchr(f.p, 0, f.n)) {
			fe_cadd(c, FE_REJECTED, FE_SB002, n, "`BPF::Scx.error(\"fmt\", a, …)` takes a non-empty format String literal first");
			return 1;
		}
		if (as.n - 1 > SCX_MAX_ERROR_ARGS) {
			fe_cadd(c, FE_REJECTED, FE_SB002, n, "`BPF::Scx.error` takes at most %d Integers after the format", (int64_t)SCX_MAX_ERROR_ARGS);
			return 1;
		}
		fe_expr **es = NULL;
		size_t ne = 0;
		for (size_t i = 1; i < as.n; i++) {
			fe_expr *e = fe_ctx_expr(c, as.v[i], ref_var);
			if (!e)
				return 1;
			if (e->bool_ || e->wide) {
				fe_cadd(c, FE_REJECTED, FE_SB014, as.v[i], "`BPF::Scx.error` formats Integers (i64), not a Bool or a u64 value");
				return 1;
			}
			T_PUSH(es, ne, e);
		}
		*out = fe_stmt_new("scx");
		out->op = name;
		out->path = f;
		set_args(out, es, ne);
		out->pos = pos;
		*ok = 1;
		return 1;
	}
	if (sr_eqc(name, "exit_info")) {
		t_nodes as = t_args(c->a, n);
		if (!sr_eqc(c->prog->so_member, "exit")) {
			fe_cadd(c, FE_REJECTED, FE_SB002, n, "`BPF::Scx.exit_info` reads the exit info argument of the `exit` member — not of `%s`",
				c->prog->so_member);
			return 1;
		}
		fe_global_decl *g = as.n == 2 && t_is(as.v[1], "ConstantReadNode") ? fe_name_get(&c->z->top->globals, nm(as.v[1])) : NULL;
		if (as.n != 2 || !fe_is_var_read(c, as.v[0], c->param) || !t_is(as.v[1], "ConstantReadNode") || !g ||
		    !sr_eqc(g->class_name, "ExitInfo")) {
			fe_cadd(c, FE_REJECTED, FE_SB002, n, "`BPF::Scx.exit_info(%s, U)` takes the context and a BPF::ExitInfo constant", c->param);
			return 1;
		}
		fe_ptr_set_add(&c->used_globals, g);
		fe_so_add_index(c->prog, 0);
		*out = fe_stmt_new("scxexit");
		out->glob = g;
		out->pos = pos;
		*ok = 1;
		return 1;
	}
	sr_str t;
	fe_kernel_type_decl *kt;
	fe_expr **es;
	size_t ne;
	if (!scx_args(c, n, ref_var, &t, &kt, &es, &ne))
		return 1;
	*out = fe_stmt_new("scx");
	out->op = name;
	out->var = t;
	out->kt = kt;
	set_args(out, es, ne);
	out->pos = pos;
	*ok = 1;
	return 1;
}

/* scxExpr */
fe_expr *fe_scx_expr(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	sr_str name = nm(n);
	if (!place_ok(c, n))
		return NULL;
	const char *res = op_of(name)->res;
	if (!strcmp(res, "bool")) {
	} else if (!strcmp(res, "status")) {
		if (!fe_status_parent_ok(c, n)) {
			fe_cadd(c, FE_REJECTED, FE_SB026, n,
				"the status of `BPF::Scx.%s` is accepted only as `st = BPF::Scx.%s(…)` (read later), as an operand of a comparison, or as "
				"`_ = BPF::Scx.%s(…)` — not as an argument, an arithmetic operand or another value",
				name, name, name);
			return NULL;
		}
	} else if (!strcmp(res, "pair")) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "%S", pair_msg);
		return NULL;
	} else {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "`BPF::Scx.%s` has no value — call it as a statement", name);
		return NULL;
	}
	sr_str t;
	fe_kernel_type_decl *kt;
	fe_expr **es;
	size_t ne;
	if (!scx_args(c, n, ref_var, &t, &kt, &es, &ne))
		return NULL;
	fe_expr *e = fe_expr_new("scx", fe_cpos(c, n));
	e->op = name;
	fe_expr_args(e, es, ne);
	if (!strcmp(res, "bool"))
		e->bool_ = 1;
	else
		e->iv = i32_range();
	return e;
}

/* scxConst: BPF::Scx::<NAME> (handled is 0 when n is not one) */
fe_expr *fe_scx_const(fe_prog_ctx *c, const sr_node *n, int *handled)
{
	sr_str cn = fe_const_name(c->a, n);
	*handled = 0;
	if (cn.n < 10 || memcmp(cn.p, "BPF::Scx::", 10))
		return NULL;
	*handled = 1;
	sr_str k = {cn.p + 10, cn.n - 10};
	const char *full = sr_eqc(k, "DSQ_LOCAL") ? "SCX_DSQ_LOCAL" : sr_eqc(k, "SLICE_DFL") ? "SCX_SLICE_DFL" : NULL;
	if (!full) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n,
			"%s is not an SCX constant of this version — a program reads BPF::Scx::DSQ_LOCAL and BPF::Scx::SLICE_DFL", cn);
		return NULL;
	}
	if (!is_sched_ext(c)) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "%s is a sched_ext constant — only a callback of a sched_ext_ops table reads it, not a %s program",
			cn, prog_what(c));
		return NULL;
	}
	c->prog->scx = 1;
	fe_expr *e = fe_expr_new("scxconst", fe_cpos(c, n));
	e->path = t_s(full);
	e->iv = fe_iv(intv_from_i64(0), fe_u64_max);
	e->wide = 1;
	return e;
}

/* poisonTargets */
static void poison_targets(fe_prog_ctx *c, const sr_node *n)
{
	t_nodes ts = t_arr(c->a, n, "lefts");
	for (size_t i = 0; i < ts.n; i++)
		if (t_is(ts.v[i], "LocalVariableTargetNode"))
			fe_name_set(&c->poisoned, nm(ts.v[i]), TRUE_);
}

/* scxMultiRefused */
void fe_scx_multi_refused(fe_prog_ctx *c, const sr_node *n)
{
	poison_targets(c, n);
	fe_cadd(c, FE_REJECTED, FE_SB001, n,
		"a multiple assignment in a struct_ops program is accepted only as `cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)`");
}

static fe_var_info *var_of(int is_bool, fe_ival iv)
{
	fe_var_info *v = sr_alloc(sizeof *v);
	memset(v, 0, sizeof *v);
	v->bool_ = is_bool;
	v->iv = iv;
	v->from_nil = 1;
	return v;
}

static int scx_select_inner(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out)
{
	t_nodes ts = t_arr(c->a, n, "lefts");
	const sr_node *v = t_ref(c->a, n, "value");
	if (!place_ok(c, v))
		return 0;
	if (ts.n != 2 || !t_is(ts.v[0], "LocalVariableTargetNode") || !t_is(ts.v[1], "LocalVariableTargetNode") || t_ref(c->a, n, "rest") ||
	    t_arr(c->a, n, "rights").n != 0) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "`cpu, idle = BPF::Scx.select_cpu_dfl(p, prev, wake)` assigns two plain locals");
		return 0;
	}
	sr_str cpu = nm(ts.v[0]), idle = nm(ts.v[1]);
	sr_str both[2] = {cpu, idle};
	for (int i = 0; i < 2; i++) {
		sr_str name = both[i];
		if (sr_eqc(name, "_") || sr_eq(name, c->param) || fe_name_get(&c->refs, name) || fe_name_get(&c->wins, name) ||
		    fe_name_get(&c->kptrs, name)) {
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "`%s` cannot receive a value of `BPF::Scx.select_cpu_dfl` — use a plain local", name);
			return 0;
		}
		if (!fe_wide_rebind_ok(c, name, n))
			return 0;
	}
	sr_str t;
	fe_kernel_type_decl *kt;
	fe_expr **es;
	size_t ne;
	if (!scx_args(c, v, ref_var, &t, &kt, &es, &ne))
		return 0;
	fe_name_set(&c->env, cpu, var_of(0, i32_range()));
	fe_name_set(&c->env, idle, var_of(1, (fe_ival){0}));
	*out = fe_stmt_new("scxsel");
	out->var = t;
	out->kt = kt;
	out->path = t_cat(t_cat(cpu, t_s(",")), idle);
	set_args(out, es, ne);
	out->pos = fe_cpos(c, n);
	return 1;
}

/* scxSelect: 1 when the value is `BPF::Scx.select_cpu_dfl(…)` (handled), with *ok and *out; a refused form poisons its targets */
int fe_scx_select(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok)
{
	const sr_node *v = t_ref(c->a, n, "value");
	*ok = 0;
	if (!fe_is_scx_call(c, v) || !sr_eqc(nm(v), "select_cpu_dfl"))
		return 0;
	*ok = scx_select_inner(c, n, ref_var, out);
	if (!*ok)
		poison_targets(c, n);
	return 1;
}

/* create_dsq's status as `st = …` or `_ = …` (program.go's LocalVariableWriteNode case): 1 when handled (the caller continues),
 * with a drop Stmt in *out when *push */
int fe_scx_status_local(fe_prog_ctx *c, const sr_node *n, const sr_node *v, sr_str ref_var, fe_stmt *out, int *push)
{
	*push = 0;
	if (!fe_is_scx_call(c, v) || !sr_eqc(nm(v), "create_dsq"))
		return 0;
	if (sr_eqc(nm(n), "_")) {
		fe_expr *e = fe_ctx_expr(c, v, ref_var);
		if (e) {
			*out = fe_stmt_new("drop");
			out->val = e;
			out->pos = fe_cpos(c, n);
			*push = 1;
		}
		return 1;
	}
	if (!fe_status_local_ok(c, n, &scx_status_decl, t_s("create_dsq"))) {
		fe_name_set(&c->poisoned, nm(n), TRUE_);
		return 1;
	}
	return 0;
}
