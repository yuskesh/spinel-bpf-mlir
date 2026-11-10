/* core.h — declarations shared by the core's C files, beyond the group contract in body.h. Not for the groups: a group
 * that needs one of these asks the core's owner to move it into body.h (a contract change). */
#ifndef FRONTEND_CORE_H
#define FRONTEND_CORE_H

#include "body.h"
#include "top_int.h"

/* ---- interval.go (interval.c). The bounds are intv (128 bits) where Go has *big.Int: an operation that leaves 128 bits sets
 * fe_iv_overflow, and fe_analyze turns it into a not-ported stop (the C never wraps a bound). ---- */
extern int fe_iv_overflow;
intv fe_iv_add1(intv a, intv b); /* a + b, or the overflow flag */
intv fe_iv_sub1(intv a, intv b);
intv fe_iv_mul1(intv a, intv b);
fe_ival fe_union(fe_ival a, fe_ival b);
fe_ival fe_iv_add(fe_ival a, fe_ival b);
fe_ival fe_iv_sub(fe_ival a, fe_ival b);
fe_ival fe_iv_mul(fe_ival a, fe_ival b);
fe_ival fe_iv_neg(fe_ival a);
fe_ival fe_iv_not(fe_ival a);
fe_ival fe_iv_bit(const char *op, fe_ival a, fe_ival b);
int fe_iv_within(fe_ival a, intv lo, intv hi);
int fe_iv_fits_i64(fe_ival a);
int fe_iv_non_neg(fe_ival a);
int fe_iv_is_point(fe_ival a, intv *v);
intv fe_floor_div(intv x, intv d);
int fe_is_pow2_mag(intv d);
/* Ival.String: "[lo, hi]" (Go prints "[<nil>, <nil>]" for the zero Ival) */
sr_str fe_ival_string(fe_ival a);
extern const intv fe_i64_min, fe_i64_max, fe_u32_max, fe_i32_min, fe_i32_max, fe_u64_max;
extern const fe_ival fe_full_i64;
intv fe_intv_of_big(const bigint *x, int *ok); /* a *big.Int that fits 128 bits */
bigint *fe_big_of_intv(intv v);

/* ---- narrow.go (narrow.c) ---- */
fe_name_table fe_narrow_env(const fe_name_table *env, const fe_expr *cond, int positive);
fe_name_table fe_join_env(const fe_name_table *a, const fe_name_table *b);
fe_name_table fe_union_refs(const fe_name_table *a, const fe_name_table *b); /* a From set; nil and empty are one */

/* ---- program.go (prog.c, prog2.c) ---- */
#define FE_MAX_LOOP_COUNT 64
extern const char *const fe_loop_forms; /* loop.go loopForms */
int fe_in_map_ops(sr_str s);
int fe_in_bin_ops(sr_str s);
int fe_in_cmp_ops(sr_str s);
int fe_in_operators(sr_str s);
int fe_window_read_len(sr_str name, int64_t *n);
int fe_ctx_field(sr_str kind, sr_str name);
const char *fe_ctx_reads(sr_str kind);
int fe_has_packet(sr_str kind);
sr_str fe_cfmt(fe_z *z, int *ok, const char *fmt, ...); /* t_fmt's verbs plus %I (fe_ival) and %V (sr_str *, size_t) */
fe_pos fe_cpos(fe_prog_ctx *c, const sr_node *n);
void fe_cadd(fe_prog_ctx *c, fe_verdict v, fe_code code, const sr_node *n, const char *fmt, ...);
size_t fe_type_count(fe_prog_ctx *c, const sr_node *n);
fe_prog_ctx *fe_new_ctx(fe_analysis *z, const sr_ast *a, const sr_node *d, sr_str name);
fe_program *fe_program_of(fe_analysis *z, const sr_ast *a, const sr_node *d, const fe_root_decl *r);
int fe_class_in_lib(fe_analysis *z, const sr_ast *a, sr_str name);
fe_stmt fe_stmt_new(const char *kind);
fe_expr *fe_expr_new(const char *kind, fe_pos p);
void fe_expr_args(fe_expr *e, fe_expr **args, size_t n);
int fe_wide_rebind_ok(fe_prog_ctx *c, sr_str name, const sr_node *n);
int fe_mixed_read_ok(fe_prog_ctx *c, sr_str name, const sr_node *n);
int fe_assign(fe_prog_ctx *c, const sr_node *n, sr_str name, const sr_node *v, sr_str ref_var, fe_stmt *out);
int fe_op_assign(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out);
int fe_if_stmt(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out);
fe_expr *fe_cond(fe_prog_ctx *c, const sr_node *n, sr_str ref_var);
fe_expr *fe_call_expr(fe_prog_ctx *c, const sr_node *n, sr_str ref_var);
fe_expr *fe_int_expr(fe_prog_ctx *c, const sr_node *n, sr_str ref_var);
int fe_fits(fe_prog_ctx *c, const sr_node *n, fe_expr *e);
fe_expr *fe_binary(fe_prog_ctx *c, const sr_node *n, sr_str op, fe_expr *l, fe_expr *r, const sr_node *rn);
int fe_member_read(fe_prog_ctx *c, const sr_node *n);
int fe_has_member_read(fe_prog_ctx *c, const sr_node *n);
sr_str fe_callee_op(fe_prog_ctx *c, const sr_node *n, int member_recv, int *ok);
fe_expr *fe_u64_op(fe_prog_ctx *c, const sr_node *n, sr_str name, t_nodes as, sr_str ref_var, fe_pos p); /* u64ops.go u64Op */
fe_name_table fe_origin(fe_prog_ctx *c, const sr_node *n);
sr_str *fe_sorted_set(const fe_name_table *t, size_t *n);
/* part B (prog2.c) */
int fe_map_call(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out);
int fe_lookup_check(fe_prog_ctx *c, const sr_node *w, const sr_node *ifn, sr_str ref_var, fe_stmt *out);
int fe_in_if_of(const sr_ast *a, const sr_node *x, const sr_node *ifn);
void fe_reject_mid_returns(fe_prog_ctx *c, const sr_node *n);
bigint *fe_literal_arg(fe_prog_ctx *c, const sr_node *n, const char *what);
void fe_verdict_of(fe_prog_ctx *c, const sr_node *n);
const sr_node *fe_cond_assign(const sr_ast *a, const sr_node *n);
int fe_window_check(fe_prog_ctx *c, const sr_node *w, const sr_node *ifn, sr_str ref_var, fe_stmt *out);
fe_expr *fe_window_read(fe_prog_ctx *c, const sr_node *n, const sr_node *recv, const sr_node *const *as, size_t n_as);
int fe_reads_bad(fe_prog_ctx *c, const sr_node *n);
sr_str fe_verdict_want(sr_str kind, sr_str dflt);
sr_str fe_ctx_use(sr_str kind, sr_str param);
fe_expr *fe_tracing_read(fe_prog_ctx *c, const sr_node *n, sr_str name, const sr_node *const *as, size_t n_as, fe_pos p);
sr_str fe_verdict_kind_text(sr_str vk);
sr_str fe_verdict_kind_of(sr_str const_name);
int fe_is_adjust_pkt(fe_prog_ctx *c, const sr_node *n);
fe_expr *fe_adjust_pkt(fe_prog_ctx *c, const sr_node *n, sr_str ref_var);

/* ---- subprogram.go (sub.c) ---- */
sr_str *fe_ctx_path(fe_prog_ctx *c, size_t *n);
fe_func_info *fe_user_call(fe_analysis *z, const sr_ast *a, const sr_node *n);
fe_expr *fe_sub_call(fe_prog_ctx *c, const sr_node *n, fe_func_info *fi, sr_str ref_var);
int fe_calls_bad_func(fe_prog_ctx *c, const sr_node *n);
int fe_borrow_arg_use(fe_prog_ctx *c, const sr_node *x);
void fe_scan_subprograms(fe_analysis *z, const sr_ast *a, const fe_name_table *defs);
fe_func_info **fe_call_graph(fe_analysis *z, const sr_ast *a, const fe_name_table *defs, size_t *n_order);
fe_program *fe_function(fe_analysis *z, const sr_ast *a, fe_func_info *fi);
void fe_resolve_subprograms(fe_analysis *z, fe_func_info **order, size_t n_order, fe_program **programs, size_t n_programs);
int fe_integer_sig(sr_str sig);
sr_str *fe_ring_path(fe_prog_ctx *c, fe_func_info *f, size_t *n);

/* ---- loop.go (loop.c), guard.go (guard.c) ---- */
int fe_is_iter_call(fe_prog_ctx *c, const sr_node *n);
int fe_loop_stmt(fe_prog_ctx *c, const sr_node *n, fe_stmt *out);
int fe_escape(fe_prog_ctx *c, const sr_node *n, int last, fe_stmt *out);
fe_stmts fe_guard_stmts(fe_prog_ctx *c, const sr_node *const *ns, size_t n);

/* ---- analyze.go steps 4-7 (steps.c) ---- */
void fe_steps_4_to_7(fe_analysis *an, fe_result *res);

/* ---- a stub hit: a function not written yet names itself here, and fe_analyze turns it into a not-ported stop. The group stubs
 * (g1_stubs.c, g2_stubs.c) that used it are gone since G1 and G2 were merged; it stays for a later stage's stubs. ---- */
extern const char *fe_stub_hit;

/* ---- small helpers ---- */
int fe_streq(sr_str s, const char *c);

#endif
