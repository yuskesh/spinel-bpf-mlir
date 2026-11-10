/* body_priv — G1's own helpers that more than one of its files (or its tests) call. Not part of the contract (body.h);
 * nothing outside body_*.c and G1's tests (csrc/e188) includes it. */
#ifndef FRONTEND_BODY_PRIV_H
#define FRONTEND_BODY_PRIV_H

#include "body.h"

int64_t fe_pow2_above(int64_t n);       /* record.go pow2Above */
sr_str fe_index_hint(int64_t n);        /* record.go indexHint */
int fe_g1_map_is_hash(const fe_map_decl *m);                          /* analyze.go MapDecl.IsHash */
int fe_g1_map_is_array(const fe_map_decl *m);                         /* analyze.go MapDecl.IsArray */
sr_str fe_g1_map_class_name(const fe_map_decl *m);                    /* analyze.go MapDecl.ClassName */
sr_str fe_g1_map_key_type_name(const fe_map_decl *m);                 /* analyze.go MapDecl.KeyTypeName */
sr_str fe_ival_text(fe_ival v);                                    /* interval.go Ival.String */
int fe_ival_within(fe_ival v, intv lo, intv hi);                   /* interval.go Ival.within */
int fe_load_callee(fe_prog_ctx *c, const sr_node *load);           /* record.go loadCallee */
fe_stmt fe_stmt_new(const char *kind); /* core: a Stmt with the nil flags of Go's zero Stmt */
fe_expr *fe_field_value(fe_prog_ctx *c, const sr_node *n, fe_record_field *f, fe_map_decl *m, sr_str ref_var); /* record.go fieldValue */
int fe_zero_array(fe_prog_ctx *c, const sr_node *x, int64_t n);                                                   /* ring.go zeroArray */
int fe_big_is_i64(const bigint *x, int64_t *v);                                  /* (*big.Int).IsInt64 and Int64 */

#endif
