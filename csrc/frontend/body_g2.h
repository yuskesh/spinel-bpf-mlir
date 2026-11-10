/* body_g2 — G2's own helpers that more than one of its files calls. Not part of the contract (body.h); nothing outside
 * the G2 files includes it. */
#ifndef BODY_G2_H
#define BODY_G2_H
#include "body.h"

sr_str fe_g2_output_argv_shape(const fe_ring_decl *r, sr_str src); /* argv.go outputArgvShape */

/* core functions outside body.h that G2 calls (each asked of the core's owner as a contract request) */
fe_stmt fe_stmt_new(const char *kind); /* prog.c: a Stmt with the nil flags of Go's zero Stmt */
const char *fe_ctx_reads(sr_str kind); /* prog.c: program.go ctxReads[kind] */
sr_str fe_ival_string(fe_ival a);                /* interval.c: Ival.String */
int fe_iv_within(fe_ival a, intv lo, intv hi);  /* interval.c: Ival.within */
intv fe_intv_of_big(const bigint *x, int *ok); /* interval.c: a *big.Int that fits 128 bits */
const char *t_ctx_class(sr_str kind);           /* top_util.c: analyze.go ctxClass[kind] (NULL when absent) */
extern const fe_ival fe_full_i64;               /* interval.c: fullI64 */
extern const char *fe_stub_hit;                /* analyze.c: a function left stubbed names itself here */

int g2_record_type(sr_str t, int64_t *bits, int *is_signed); /* record.go recordTypes */
int g2_big_i64(const bigint *x, int64_t *v);                 /* (*big.Int).IsInt64 and Int64 */

extern void *const g2_true;                                  /* the value of a set flag in a map[string]bool table */
sr_str g2_str(const sr_node *n, const char *k);              /* n.Str[k] ("" when absent) */
int g2_is(const sr_node *n, const char *type);               /* n != nil && n.Type == type */
const sr_node *g2_parent(const sr_ast *a, const sr_node *n); /* a.node(a.Parent[n.ID]) (Go reads id 0 when there is none) */
fe_expr *g2_expr(const char *kind, fe_pos p);                /* &Expr{Kind: kind, Pos: p} */
fe_pos g2_pos(fe_prog_ctx *c, const sr_node *n);             /* c.z.pos(c.a, n) */
/* c.add(Rejected, code, n, fmt, …): %s an sr_str, %c a C string, %d an int64_t, %q an sr_str quoted (strconv.Quote), %B a
 * const bigint * (%s of a *big.Int), %I an fe_ival (Ival.String) */
void g2_reject(fe_prog_ctx *c, fe_code code, const sr_node *n, const char *fmt, ...);
/* int(nb.Int64()) of a literal: 0 and a not-ported stop when nb is not an int64 (the core's rule for Int64 reads) */
int g2_lit_int(fe_prog_ctx *c, const sr_node *lit, int64_t *v);

#endif
