/* top.h — the analyzer state after steps 1-2 of analyze() (top-level declarations and roots), handed to the later steps.
 *
 * The Go code (internal/frontend/analyze.go analyze() up to the end of step 2, and the declaration helpers it calls) stays the
 * canon. Translation rules: one struct per Go type, named fe_<snake_case>; fields in Go's order, in
 * snake_case; string -> sr_str, int -> int64_t, bool -> int, uint64 -> uint64_t; a slice -> pointer + count, plus <name>_nil
 * (1 when Go holds a nil slice, 0 for an empty non-nil one); a pointer -> a C pointer (NULL is Go's nil); map[string]*T and
 * map[string]bool -> a table of entries in first-insertion order with a lookup by name. Go never iterates these maps for output
 * (it uses the order slices), so the table order is only a convenience; a Go `delete` marks the entry removed. Memory comes from
 * the spinelread arena (sr_alloc). */
#ifndef SPINEL_FRONTEND_TOP_H
#define SPINEL_FRONTEND_TOP_H

#include <stddef.h>
#include <stdint.h>

#include "../spinelread/sr.h"
#include "fe.h" /* fe_z, fe_pos, fe_diag (the shared core) */

/* ---- record.go ---- */

/* RecordField */
typedef struct {
	sr_str name;
	int64_t bits;
	int is_signed; /* Go: Signed */
	int pad;
	int64_t offset;
	int64_t count; /* array member: number of elements; 0 for an integer member */
} fe_record_field;

/* RecordDecl */
typedef struct fe_record_decl {
	sr_str const_name; /* Go: Const */
	fe_record_field *fields;
	size_t n_fields;
	int fields_nil;
	int64_t size;
	int64_t align;
	fe_pos pos;
	fe_pos struct_pos;
} fe_record_decl;

/* The library's lpm_trie key record (Go: lpmKey4, a package-level *RecordDecl that every lpm_trie MapDecl.KeyRecord points to). */
extern fe_record_decl fe_lpm_key4;

/* ---- analyze.go ---- */

/* MapDecl */
typedef struct {
	sr_str const_name; /* Go: Const */
	sr_str name;
	int64_t value_bits;
	int is_signed; /* Go: Signed */
	uint64_t max_entries;
	fe_record_decl *record; /* NULL: an integer map */
	sr_str kind;            /* "" is array */
	sr_str class_name;      /* Go: Class */
	int64_t key_bits;
	int key_signed;
	fe_record_decl *key_record;
	fe_pos pos;
} fe_map_decl;

/* KParam */
typedef struct {
	int64_t n;
	sr_str type;
} fe_kparam;

/* ---- kernel.go ---- */

/* KernelField */
typedef struct {
	sr_str name;
	sr_str kind;
	int64_t bits;
	int is_signed; /* Go: Signed */
	sr_str ptr;    /* kptr / struct: the target kernel_type's Struct constant */
	int64_t count; /* array: number of 8-bit elements */
} fe_kernel_field;

/* KernelTypeDecl */
typedef struct fe_kernel_type_decl {
	sr_str const_name; /* Go: Const */
	sr_str name;
	fe_kernel_field *fields;
	size_t n_fields;
	int fields_nil;
	fe_pos pos;
	fe_pos struct_pos;
	fe_pos *handle_poss;
	size_t n_handle_poss;
	int handle_poss_nil;
} fe_kernel_type_decl;

/* TpArg */
typedef struct {
	int64_t idx;
	fe_kernel_type_decl *kt; /* NULL: an integer argument (type) */
	sr_str type;
	int null; /* nullable struct argument */
} fe_tp_arg;

/* ---- tracepoint.go ---- */

/* TpField */
typedef struct {
	sr_str name;
	int64_t offset;
	sr_str type;
	int64_t n; /* fixed byte array element count; 0 is not an array */
} fe_tp_field;

/* ---- ring.go ---- */

/* RingDecl */
typedef struct {
	sr_str const_name; /* Go: Const */
	sr_str name;
	fe_record_decl *record;
	uint64_t size;
	fe_pos pos;
} fe_ring_decl;

/* ---- globals.go ---- */

/* GlobalDecl */
typedef struct {
	sr_str const_name; /* Go: Const */
	sr_str name;
	sr_str class_name; /* Go: Class — "Config" / "OptionalConfig" / "Counter" */
	sr_str section;    /* "rodata" / "bss" */
	int64_t bits;
	int is_signed; /* Go: Signed */
	int optional;
	fe_pos pos;
} fe_global_decl;

/* ---- analyze.go: rootDecl and threadRef ---- */

/* rootDecl */
typedef struct {
	sr_str name;
	sr_str kind;
	fe_pos pos;
	sr_str target;
	int64_t nargs;
	sr_str ret;
	fe_kparam *params;
	size_t n_params;
	int params_nil;
	sr_str binary_sha; /* uprobe: SHA-256 hex of the target binary (bml_build_sha256) */
	sr_str binary_path;
	sr_str sys_target;
	fe_tp_arg *targs; /* Go: TArgs */
	size_t n_targs;
	int targs_nil;
	fe_tp_field *tfields; /* Go: TFields */
	size_t n_tfields;
	int tfields_nil;
} fe_root_decl;

/* threadRef */
typedef struct {
	sr_str name;
	fe_pos pos;
	int64_t line;
} fe_thread_ref;

/* ---- name tables (Go map[string]*T / map[string]bool) ---- */

typedef struct {
	sr_str key;
	void *val; /* the *T; for a map[string]bool set, non-NULL means true */
	int removed;
} fe_name_entry;

typedef struct {
	fe_name_entry *e;
	size_t n, cap;
} fe_name_table;

void *fe_name_get(const fe_name_table *t, sr_str key);      /* NULL when absent or removed (Go's zero value) */
int fe_name_has(const fe_name_table *t, sr_str key);        /* Go: `_, ok := m[key]` */
void fe_name_set(fe_name_table *t, sr_str key, void *val);  /* Go: m[key] = val (a removed key is set again in place) */
void fe_name_delete(fe_name_table *t, sr_str key);          /* Go: delete(m, key) */

/* A Go []string held as a name-table value (Membership: function -> the sides that reach it). */
typedef struct {
	sr_str *v;
	size_t n;
} fe_str_list;

/* ---- the state handed over ---- */

/* How analyze() left steps 1-2. */
enum {
	FE_TOP_CONTINUE = 0, /* steps 1-2 finished with at least one root: fe_analyze continues with step 3 (inject is set) */
	FE_TOP_RETURNED = 1, /* analyze() returned (res, nil) inside steps 1-2: res_diags is Result.Diags, nothing else runs */
	FE_TOP_ERROR = 2     /* analyze() returned (nil, err): err holds Go's error text, or z->np after a not-ported stop */
};

typedef struct {
	int outcome;
	sr_result err;      /* FE_TOP_ERROR only */
	fe_diag *res_diags; /* FE_TOP_RETURNED only: Result.Diags as returned (Spinel's own diagnostics, or z.diags) */
	size_t n_res_diags;
	int res_diags_nil;

	/* z.plain: the plain run (spinelread), with the splice correction applied in place; FE_TOP_CONTINUE only */
	sr_analysis plain;

	/* the analyzer fields after step 2 (Go: analyzer) */
	fe_thread_ref *thread_refs;
	size_t n_thread_refs;
	int thread_refs_nil;
	fe_name_table kts;        /* Struct constant -> fe_kernel_type_decl* */
	fe_kernel_type_decl **kt_order;
	size_t n_kt_order;
	int kt_order_nil;
	fe_name_table kt_handles; /* handle constant -> fe_kernel_type_decl* */
	fe_name_table maps;       /* constant -> fe_map_decl* */
	fe_map_decl **map_order;
	size_t n_map_order;
	int map_order_nil;
	fe_name_table records;    /* Struct constant -> fe_record_decl* */
	fe_name_table rings;      /* constant -> fe_ring_decl* */
	fe_ring_decl **ring_order;
	size_t n_ring_order;
	int ring_order_nil;
	fe_name_table bad_rings;  /* set */
	fe_name_table bad_maps;   /* set */
	fe_name_table globals;    /* constant -> fe_global_decl* */
	fe_global_decl **global_order;
	size_t n_global_order;
	int global_order_nil;
	fe_name_table bad_globals; /* set */
	sr_str *root_kinds;
	size_t n_root_kinds;
	int root_kinds_nil;
	fe_name_table bad_hash;   /* set */
	fe_name_table bad_recs;   /* set */

	/* scanTop's result */
	fe_root_decl *roots;
	size_t n_roots;
	int roots_nil;

	/* z.diags is not copied: it stays in fe_z (z->diags, in append order; Go nil is z->diags.v == NULL) */

	/* step 3: the injected text (the plain text + "if false\n" + one call per root + "end\n"); FE_TOP_CONTINUE only */
	sr_str inject;
} fe_top;

/* Steps 1-2 of analyze() and the step 3 text: the plain Spinel run (sr_analyze in <work>/plain) and sr_uses_threads, as Go does.
 * `z` comes from fe_z_init; the diagnostics stay in z->diags. `inject_expr` is analyzeOpts.inject ("" in the user path). Returns
 * sr_ok, or the result stored in out->err with outcome FE_TOP_ERROR: Go's error text, or z->np when a not-ported stop was hit. */
sr_result fe_top_run(fe_z *z, const sr_spinel *sp, const char *work, sr_str inject_expr, fe_top *out);

/* alignSplice (splice.go): when Spinel spliced a builtins file, measure the line shift k of `base` against `text` and move the
 * user file's nodes and type / codegen / diagnostic records back by k (then sr_reindex_types). Returns 1 (ok; *k set, 0 when there
 * was no splice) or 0 (no single k fits: the caller adds the SB000). fe_analyze calls it for the typing run too. */
int fe_align_splice(sr_analysis *an, sr_str base, sr_str text, int64_t *k);

/* flushThreadRefs (analyze.go): every collected Thread reference on a line of a function whose membership holds "bpf" becomes an
 * SB027; then t's thread references are cleared (Go nil). membership: function -> fe_str_list *; defs: function -> const sr_node *
 * (its line .. end_line); NULL is a Go nil map. fe_top_run calls it at the no-roots return; fe_analyze calls it after the typing run's
 * diagnostics and at the end. */
void fe_flush_thread_refs(fe_z *z, fe_top *t, const fe_name_table *membership, const fe_name_table *defs);

/* The canonical dump compared with the Go dumper (e187_dump_test.go), including z->diags. */
void fe_top_dump(sr_buf *b, const fe_z *z, const fe_top *t);

#endif
