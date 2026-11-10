/* lower.h — Lower (internal/frontend/lower.go) and VerifyWorld (bpfworld.go) in C (the lowering to .mlir).
 *
 * The Go code stays the canon. The C reads the analysis's fe_result and writes the same .mlir text byte for byte; the differential
 * compares the two as the last part of the canonical dump. Go's mutation hooks (mutation("...")) are not ported: they are off in every
 * build but Go's mutation test build. */
#ifndef FRONTEND_LOWER_H
#define FRONTEND_LOWER_H

#include "body.h"

/* Lower: SR_OK with the text in *out; SR_ERR with Go's error text (an internal error, or VerifyWorld's); SR_NOT_PORTED when the
 * C cannot reproduce Go's bytes (z->np holds the stop). */
sr_result fe_lower(fe_z *z, const fe_result *r, sr_buf *out);

/* VerifyWorld: 1 when every op of text is in the allowed set; else 0 and Go's error text in *err. */
int fe_verify_world(sr_str text, sr_buf *err);
/* MlirOps: the op names of text in order, one per line, into *out. */
void fe_mlir_ops(sr_str text, sr_buf *out);
/* AllowedOps: the allowed set, sorted (Go's string order), one per line. */
void fe_allowed_ops(sr_buf *out);

#endif
