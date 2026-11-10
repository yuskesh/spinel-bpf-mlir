/* dump.h — the canonical dump (dump.c) and the C analyze() that produces what it prints (analyze.c). */
#ifndef FRONTEND_DUMP_H
#define FRONTEND_DUMP_H

#include "body.h"

/* DomainGraph (schema.go): the JSON bytes, ending in "\n". */
void fe_domain_graph(sr_buf *b, const fe_result *r);

/* The dump of a Result (Analyze returned no error): "domain = …", the registry, then "result…" lines. Returns NULL, or the
 * dumper's failure text (the dump is then not valid; the Go dumper fails on the same inputs). */
const char *fe_result_dump(sr_buf *out, const fe_result *r);

/* The dump of an Analyze error: "error = <q>". */
void fe_error_dump(sr_buf *out, sr_str err);

/* analyze() (analyze.go) in C: steps 1-2 by top.h's fe_top_run, then steps 3-7. `inject_expr` is analyzeOpts.inject (""). Returns
 * sr_ok with *res filled, or SR_ERR with Go's error text, or SR_NOT_PORTED (the first not-ported stop). */
sr_result fe_analyze(fe_z *z, const sr_spinel *sp, const char *work, sr_str inject_expr, fe_result *res);

#endif
