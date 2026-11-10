/* fe — the shared core of the C frontend's analysis (owned by the core, used by the steps 1-2 code).
 *
 * This is the C form of internal/frontend/result.go (Verdict, Code, Pos, Diag, Diags, Error) and the analyzer's common fields and
 * helpers in analyze.go (add, pos, slice, literal). The Go code stays the canon; every function names the Go it follows.
 *
 * Rules for both users:
 * - memory comes from the spinelread arena (sr_alloc); nothing is freed before exit, except bigint storage (bigint_free);
 * - a message is built in an sr_buf with the fe_fmt_* helpers below, which follow Go's fmt verbs, then passed to fe_add;
 * - where the C cannot reproduce Go's bytes (for example %q of non-ASCII text), call fe_not_ported. The first such stop
 *   is kept in z->np, and the result can then never compare equal with Go. */
#ifndef FRONTEND_FE_H
#define FRONTEND_FE_H

#include "../intv/intv.h"
#include "../spinelread/sr.h"

/* ---- Verdict (result.go) ---- */
typedef enum { FE_VERIFIED = 0, FE_REJECTED = 1, FE_CONDITIONAL = 2, FE_UNKNOWN = 3 } fe_verdict;
const char *fe_verdict_string(fe_verdict v); /* Verdict.String */

/* ---- Code (result.go): the code text ("SB001") and its Name() ---- */
typedef enum {
	FE_SB000, FE_SB001, FE_SB002, FE_SB003, FE_SB004, FE_SB005, FE_SB006, FE_SB007, FE_SB008, FE_SB009,
	FE_SB010, FE_SB011, FE_SB012, FE_SB013, FE_SB014, FE_SB015, FE_SB016, FE_SB017, FE_SB018, FE_SB019,
	FE_SB020, FE_SB021, FE_SB022, FE_SB023, FE_SB024, FE_SB025, FE_SB026, FE_SB027, FE_SB028, FE_SB029,
	FE_SB030, FE_SB031, FE_SB032, FE_SB033, FE_SB034, FE_SB035,
	FE_NCODES
} fe_code;
const char *fe_code_text(fe_code c); /* "SB001" */
const char *fe_code_name(fe_code c); /* Code.Name: "UnsupportedConstruct" */

/* ---- Pos (result.go) ---- */
typedef struct {
	sr_str file;
	int64_t line, col;
} fe_pos;
void fe_pos_string(sr_buf *b, fe_pos p); /* Pos.String */

/* ---- Diag and Diags (result.go) ---- */
typedef struct {
	fe_verdict verdict;
	fe_code code;
	fe_pos pos;
	sr_str *path; /* the call path from the root; n_path == 0 means none (Go's omitempty) */
	size_t n_path;
	sr_str msg;
} fe_diag;
void fe_diag_string(sr_buf *b, const fe_diag *d); /* Diag.String */

typedef struct {
	fe_diag *v;
	size_t n, cap;
} fe_diags;
void fe_diags_push(fe_diags *ds, fe_diag d);
int fe_diags_blocking(const fe_diags *ds);          /* Diags.Blocking */
fe_diags fe_diags_sorted(const fe_diags *ds);       /* Diags.Sorted: a stable copy by file, line, col, code */
void fe_error_string(sr_buf *b, const fe_diags *ds); /* (*Error).Error: Sorted, one Diag.String per line */

/* ---- the analyzer's common fields (analyze.go analyzer) ---- */
typedef struct {
	sr_str base;    /* filepath.Base of the source path */
	sr_str text;    /* the source, with a final "\n" added when missing */
	sr_str *lines;  /* strings.Split(strings.TrimSuffix(text, "\n"), "\n") */
	size_t n_lines;
	int64_t user_lines; /* len(lines) at the start */
	sr_str lib;     /* the absolute path of bpf.rb */
	sr_str src_dir; /* filepath.Dir of the source path */
	fe_diags diags; /* in append order */
	sr_result np;   /* the first not-ported stop; np.kind == SR_OK while there is none */
} fe_z;

/* Fills base, text, lines, user_lines, lib and src_dir as analyze() does before its first Spinel run. lib_dir is sp.LibDir.
 * Returns SR_ERR with Go's error text when filepath.Abs fails (it cannot for an absolute lib_dir). */
sr_result fe_z_init(fe_z *z, sr_str source_path, sr_str text, sr_str lib_dir);

/* z.add: msg is taken as is (build it with sr_buf and the fe_fmt_* helpers). */
void fe_add(fe_z *z, fe_verdict v, fe_code c, fe_pos p, sr_str msg);
/* Records the first not-ported stop (later ones are dropped). */
void fe_not_ported(fe_z *z, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* z.pos: the file is kept when it is base, else filepath.Base of it; the column is Spinel's plus 1. */
fe_pos fe_pos_of(const fe_z *z, const sr_ast *a, const sr_node *n);
/* z.slice: the source text of a one-line node, or "" (n.p may then be NULL). */
sr_str fe_slice(const fe_z *z, const sr_node *n);
/* z.literal: the value of an IntegerNode from the source text, checked against Spinel's IntText "value". On failure it adds
 * Go's SB001 or SB014 and returns 0 (out is then zero); on success 1. The caller frees out with bigint_free. */
int fe_literal(fe_z *z, const sr_ast *a, const sr_node *n, bigint *out);

/* ---- node fields (ast.go Node maps; absent gives the zero value and *ok == 0) ---- */
sr_str fe_node_str(const sr_node *n, const char *k, int *ok);
int64_t fe_node_int(const sr_node *n, const char *k, int *ok);
sr_str fe_node_inttext(const sr_node *n, const char *k, int *ok);
int64_t fe_node_ref(const sr_node *n, const char *k, int *ok);
const int64_t *fe_node_arr(const sr_node *n, const char *k, size_t *count, int *ok);

/* ---- Go's fmt verbs into an sr_buf (Go's %q, and each %v use written out in its Go form) ---- */
void fe_fmt_s(sr_buf *b, sr_str s);                 /* %s */
void fe_fmt_d(sr_buf *b, int64_t v);                /* %d */
int fe_fmt_q(fe_z *z, sr_buf *b, sr_str s);         /* %q (strconv.Quote); non-ASCII is not ported: 0 and fe_not_ported */
void fe_fmt_big(sr_buf *b, const bigint *x);        /* %s or %d of a *big.Int */

/* ---- path/filepath (Go's filepath semantics in C) ---- */
sr_str fe_path_base(sr_str p); /* filepath.Base */
sr_str fe_path_dir(sr_str p);  /* filepath.Dir */
sr_str fe_path_clean(sr_str p); /* filepath.Clean */
sr_str fe_path_join(const sr_str *elems, size_t n); /* filepath.Join */

#endif
