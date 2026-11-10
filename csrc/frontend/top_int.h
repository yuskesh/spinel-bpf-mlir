/* top_int.h — helpers shared by the steps 1-2 C files (not part of the fe_top interface). */
#ifndef SPINEL_FRONTEND_TOP_INT_H
#define SPINEL_FRONTEND_TOP_INT_H

#include "top.h"

/* ---- the AST (ast.go node / ref / arr, analyze.go constName / args / topStatements / walk) ---- */
typedef struct {
	const sr_node **v;
	size_t n;
} t_nodes;

const sr_node *t_node(const sr_ast *a, int64_t id);                    /* a.node: NULL for id < 0 or a missing node */
const sr_node *t_ref(const sr_ast *a, const sr_node *n, const char *k); /* a.ref (NULL n gives NULL) */
t_nodes t_arr(const sr_ast *a, const sr_node *n, const char *k);        /* a.arr: missing children are left out */
sr_str t_str(const sr_node *n, const char *k);                         /* n.Str[k] ("" when absent) */
int t_is(const sr_node *n, const char *type);                          /* n != NULL && n.Type == type */
sr_str t_const_name(const sr_ast *a, const sr_node *n);                 /* constName */
t_nodes t_args(const sr_ast *a, const sr_node *call);                   /* args */
t_nodes t_top_statements(const sr_ast *a, int64_t fid);                 /* topStatements */
int64_t t_user_file_id(const sr_ast *a, sr_str base);                   /* userFileID (-1 when absent) */
/* walk: preorder; f returns 0 to skip the children. The children are visited by Go's order of "R"+field / "A"+field. */
void t_walk(const sr_ast *a, const sr_node *n, int (*f)(void *ctx, const sr_node *n), void *ctx);
const sr_node *t_root(const sr_ast *a);
/* Set when t_ref / t_arr / t_pos meet a NULL node, where Go panics; fe_top_run turns it into a named not-ported stop. */
extern int t_nil_panic;

/* ---- messages: z.add with Go's format text ----
 * Verbs: %s an sr_str, %S a const char *, %d an int64_t, %u a uint64_t, %q an sr_str as Go's %q, %B a const bigint * (Go's %s of
 * a *big.Int), %% a percent sign. %q of non-ASCII text is a not-ported stop (fe_fmt_q); the diagnostic is then not added. */
void t_add(fe_z *z, fe_verdict v, fe_code c, fe_pos p, const char *fmt, ...);
sr_str t_fmt(fe_z *z, int *ok, const char *fmt, ...);

/* ---- integers ---- */
int t_big_sign(const bigint *x);
int t_big_int64(const bigint *x, int64_t *out);  /* IsInt64 (and the value) */
int t_big_uint64(const bigint *x, uint64_t *out); /* IsUint64 (and the value) */
/* z.literal with Go's (lit, ok); the bigint is freed by t_lit_done. */
int t_literal(fe_z *z, const sr_ast *a, const sr_node *n, bigint *out);

/* ---- regular expressions (hand-written matchers; each names its Go pattern) ---- */
int t_reserved_prefix(sr_str s); /* `^_?spinelbpf_` */
int t_lower_ident(sr_str s);     /* `^[a-z_][a-z0-9_]*$` */
int t_tp_ident(sr_str s);        /* `^[A-Za-z_][A-Za-z0-9_]*$` */
int t_pad_name(sr_str s);        /* `^_pad[0-9]+$` */
/* `^\s*(require_relative|load)\b`: 1 and the group's span [*g0, *g1) when it matches. */
int t_rel_require(sr_str s, size_t *g0, size_t *g1);

/* ---- fixed tables ---- */
int t_record_type(sr_str t, int64_t *bits, int *is_signed); /* recordTypes */
int t_int_type(sr_str t, int64_t *bits, int *is_signed);    /* intTypes (hash.go) */
int t_in(sr_str s, const char *const *list);               /* membership in a NULL-terminated list */
const char *t_ctx_class(sr_str kind);                     /* ctxClass */
int t_root_kind(sr_str name);                             /* rootKindOf */
extern const char *const t_lib_names[], *const t_builtin_reopen[], *const t_dynamic_defs[], *const t_dynamic_calls[],
    *const t_thread_consts[], *const t_ruby_keywords[];

/* ---- strings ---- */
sr_str t_join(const sr_str *v, size_t n, const char *sep);
sr_str t_cat(sr_str a, sr_str b);
sr_str t_s(const char *s); /* sr_cstr */

/* ---- growing arrays ---- */
#define T_PUSH(arr, n, val)                                                                                                       \
	do {                                                                                                                       \
		(arr) = sr_grow((arr), (n) * sizeof *(arr), ((n) + 1) * sizeof *(arr));                                            \
		(arr)[(n)++] = (val);                                                                                              \
	} while (0)

/* ---- the declaration helpers (one file per Go file) ---- */
typedef struct {
	sr_str *names; /* nil names: n_names 0 */
	size_t n_names;
	fe_pos pos;
	sr_str bad; /* "" when the Struct is usable */
} t_struct_info;

typedef struct {
	sr_str key;
	t_struct_info *val;
} t_struct_entry;

typedef struct {
	t_struct_entry *e;
	size_t n;
} t_structs;

t_struct_info *t_structs_get(const t_structs *s, sr_str key);

typedef struct {
	fe_z *z;
	const sr_ast *a;
	fe_top *t;
} t_ctx;

fe_pos t_pos(t_ctx *c, const sr_node *n); /* z.pos (a NULL n sets t_nil_panic and gives a zero Pos) */

/* record.go */
int t_struct_of(t_ctx *c, const sr_node *n, t_struct_info **out);
void t_record_decl(t_ctx *c, const sr_node *n, const t_structs *structs);
void t_record_map_decl(t_ctx *c, const sr_node *n);
void t_check_member_defs(t_ctx *c, int64_t fid, const fe_root_decl *roots, size_t n_roots);
int t_sample_args(t_ctx *c, t_nodes sas, const fe_record_decl *r, const char *zero_msg, const char *where);
/* ring.go, hash.go, globals.go, analyze.go mapDecl */
void t_ring_decl(t_ctx *c, const sr_node *n);
void t_hash_map_decl(t_ctx *c, const sr_node *n, const char *kind, int record, const char *class_name);
int t_hash_class(sr_str recv, const char **kind, int *record, const char **class_name);
int t_global_decl(t_ctx *c, const sr_node *n);
void t_check_global_names(t_ctx *c, const fe_root_decl *roots, size_t n_roots);
void t_map_decl(t_ctx *c, const sr_node *n);
/* kernel.go */
void t_kernel_type_decl(t_ctx *c, const sr_node *n, const t_structs *structs);
void t_kernel_types_resolve(t_ctx *c);
void t_kernel_handle_decl(t_ctx *c, const sr_node *n);
int t_struct_args_decl(t_ctx *c, const sr_node *n, t_nodes as, const char *kind, fe_root_decl *r);
/* tracepoint.go, uprobe.go, fmodret.go: bad_code is the SB008 `bad` of rootCall */
int t_tracepoint_decl(t_ctx *c, const sr_node *n, t_nodes as, fe_root_decl *r);
int t_uprobe_decl(t_ctx *c, const sr_node *n, t_nodes as, fe_root_decl *r);
int t_fmod_ret_decl(t_ctx *c, const sr_node *n, t_nodes as, fe_root_decl *r);
/* structops.go structOpsDecl: 1 with the declaration and one root per member (*roots, *n_roots), or 0 after an SB008 */
int t_struct_ops_decl(t_ctx *c, const sr_node *n, fe_struct_ops_decl **out, fe_root_decl **roots, size_t *n_roots);
/* analyze.go rootCall, scanTop, scanProgramWide */
int t_root_call(t_ctx *c, const sr_node *n, fe_root_decl *r);
void t_scan_top(t_ctx *c, int64_t fid);
void t_scan_program_wide(t_ctx *c, int64_t fid);
int t_tp_btf_decl(t_ctx *c, const sr_node *n, t_nodes as, fe_root_decl *r);

/* rootCall's bad(): the SB008 at the call n (the enclosing function's c and n), and return 0 */
#define BAD(...)                                                                                                                   \
	do {                                                                                                                       \
		t_add(c->z, FE_REJECTED, FE_SB008, t_pos(c, n), __VA_ARGS__);                                                      \
		return 0;                                                                                                          \
	} while (0)

#endif
