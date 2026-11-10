/* body — the contract between the core of the C analysis after steps 1-2 (bodies, reach, domain and diagnostics) and its feature
 * groups: G1, maps and records, and G2, tracing and kernel.
 *
 * It holds the IR of internal/frontend's Result (program.go Expr and Stmt, analyze.go Program, Edge and Result), the body walk's
 * state (program.go progCtx and the helper types of loop.go and subprogram.go), and every function that crosses a group boundary,
 * in both directions, as measured from the Go code at main c204310 (the calls of progCtx methods across files).
 *
 * Ownership. The core owns this file. A group implements the prototypes marked with its name and calls the others. A change a group
 * needs goes through the core, and after the groups start, any change here is a contract change announced to both group owners
 * (a design decision of 2026-11-13).
 *
 * Contract change 1 (2026-11-13): fe_str_list moved to top.h (the steps 1-2 code, commit 1533904). The core keeps the MapDecl
 * methods and RecordDecl.Field, and takes oneReasonEach, usedGlobalsOf, widthRange and usesKernelTypes. G1 implements the 13 other
 * methods of the declaration types (body_decl.c, signatures from G1's owner).
 * Contract change 2 (2026-11-13, at two requests from G2's owner): the core also keeps KernelTypeDecl.field and Program.tpArg,
 * which the core and G1 call as well as G2. tpstr.go outputTpStr has only G2 callers, so it stays G2-private (static in G2's file).
 *
 * Translation rules (top.h's, plus):
 * - one struct per Go type, fe_<snake_case>, fields in Go's order; `*big.Int` → `bigint *` (NULL is nil); Ival → fe_ival;
 * - a Go slice of values ([]Stmt) → fe_stmts; of pointers → a pointer array, a count and a _nil flag;
 * - map[string]X → fe_name_table (top.h); map[*T]bool → fe_ptr_set; map[int]X → sr_imap (spinelread);
 * - results: the first non-bool result is the return value, or an out parameter when it is a struct (fe_stmt); each later
 *   result is an out parameter named as in Go, or ok, ok2 for unnamed bools;
 * - a message (Go's format and args) is built by the caller with fe.h's fe_fmt_* helpers and passed as one sr_str;
 * - Go's `func` parameters → a C function pointer plus a `void *` for its state.
 * Each prototype names the Go function it ports, as file:line at main c204310. */
#ifndef FRONTEND_BODY_H
#define FRONTEND_BODY_H

#include "fe.h"
#include "top.h"

/* ---- interval.go Ival: the closed interval [lo, hi]; set == 0 is Go's zero Ival (both bounds nil, for Bool expressions) ---- */
typedef struct {
	int set;
	intv lo, hi;
} fe_ival;

/* ---- a set of pointers (Go map[*T]bool); insertion order kept ---- */
typedef struct {
	const void **v;
	size_t n, cap;
} fe_ptr_set;
int fe_ptr_set_has(const fe_ptr_set *s, const void *p);
void fe_ptr_set_add(fe_ptr_set *s, const void *p);

typedef struct fe_expr fe_expr;
typedef struct fe_stmt fe_stmt;
typedef struct fe_program fe_program;
typedef struct fe_func_info fe_func_info;

/* ---- program.go Expr ---- */
struct fe_expr {
	sr_str kind;
	sr_str op;
	fe_expr **args;
	size_t n_args;
	int args_nil;
	fe_tp_field *tp_copy;
	bigint *lit;
	int b;
	sr_str var;
	sr_str ref;
	fe_map_decl *map;
	int bool_; /* Go's Bool */
	fe_ival iv;
	int wide;
	sr_str div;
	int64_t idx;
	fe_record_field *field;
	fe_ring_decl *ring;
	int64_t len;
	fe_global_decl *glob;
	sr_str path;
	fe_pos pos;
};

/* ---- program.go Stmt, and []Stmt ---- */
typedef struct {
	fe_stmt *v;
	size_t n, cap;
	int nil;
} fe_stmts;
void fe_stmts_push(fe_stmts *s, fe_stmt st);

struct fe_stmt {
	sr_str kind;
	fe_record_field *field;
	sr_str op;
	fe_ring_decl *ring;
	sr_str var;
	fe_global_decl *glob;
	fe_expr *off;
	int64_t len;
	fe_expr *val;
	fe_expr *cond;
	fe_stmts then;
	fe_stmts else_;
	fe_map_decl *map;
	fe_expr *key;
	fe_expr *value;
	fe_pos pos;
	fe_pos if_pos;
	int64_t count;
	fe_expr *bound;
	sr_str path;
	int clamp;
	int incl;
	sr_str *carried;
	size_t n_carried;
	int carried_nil;
	fe_kernel_type_decl *kt;
	sr_str ptr_of;
	fe_kernel_type_decl *ptr_of_kt;
	sr_str k_str;
	int comm;
	fe_tp_field *tp_copy;
	fe_tp_field *tp_str;
	int argv;
	fe_record_field *index;
	sr_str str_ssa;  /* lower only; always "" here */
	int64_t index_v; /* lower only; always 0 here */
	int buf;
	fe_expr *buf_len;
	fe_record_field *count_f;
	fe_expr **scx_args; /* scx / scxsel: the Integer operands of a sched_ext op (Go: ScxArgs) */
	size_t n_scx_args;
	int scx_args_nil;
};

/* ---- analyze.go Program ---- */
struct fe_program {
	sr_str name;
	sr_str kind;
	sr_str target;
	int64_t nargs;
	sr_str ret;
	fe_kparam *params;
	size_t n_params;
	int params_nil;
	fe_tp_arg *t_args;
	size_t n_t_args;
	int t_args_nil;
	fe_tp_field *t_fields;
	size_t n_t_fields;
	int t_fields_nil;
	sr_str *f_params;
	size_t n_f_params;
	int f_params_nil;
	fe_expr *f_ret;
	int64_t f_borrow;
	fe_map_decl *f_borrow_map;
	int64_t f_win;
	int64_t f_win_len;
	int64_t f_ctx;
	sr_str f_ctx_kind;
	sr_str binary_sha;
	sr_str binary_path;
	sr_str sys_target;
	fe_global_decl **globals;
	size_t n_globals;
	int globals_nil;
	fe_pos pos;
	fe_pos decl_pos;
	fe_stmts body;
	sr_str verdict;
	sr_str verdict_const;
	fe_map_decl *redir_map;
	fe_expr *redir_key;
	sr_str guard_verdict;
	fe_expr *fmod_val;
	bigint *fmod_guard;
	fe_pos verdict_pos;
	int64_t end_line;
	fe_map_decl **maps;
	size_t n_maps;
	int maps_nil;
	fe_ring_decl **rings;
	size_t n_rings;
	int rings_nil;
	sr_str so_type;   /* struct_ops: the kernel type (Go: SOType) */
	sr_str so_member; /* struct_ops: the member (Go: SOMember) */
	int64_t *so_args; /* struct_ops: the argument indexes read, ascending and once each (Go: SOArgs; nil when n_so_args 0) */
	size_t n_so_args;
	fe_expr *so_val; /* struct_ops: the return value of an integer member (Go: SOVal) */
	int scx; /* the program calls a sched_ext op (Go: Scx; the module carries ebpf.scx_kfuncs = "insert") */
};

/* ---- analyze.go Edge and Result ---- */
typedef struct {
	sr_str from, to;
	fe_pos pos;
	sr_str dispatch;
} fe_edge;

typedef struct {
	sr_str source;
	fe_program **programs;
	size_t n_programs;
	int programs_nil;
	fe_map_decl **maps;
	size_t n_maps;
	int maps_nil;
	fe_ring_decl **rings;
	size_t n_rings;
	int rings_nil;
	fe_global_decl **globals;
	size_t n_globals;
	int globals_nil;
	fe_kernel_type_decl **kernel_types;
	size_t n_kernel_types;
	int kernel_types_nil;
	fe_program **funcs;
	size_t n_funcs;
	int funcs_nil;
	fe_struct_ops_decl **struct_ops; /* Go: StructOps */
	size_t n_struct_ops;
	int struct_ops_nil;
	fe_name_table membership; /* function -> fe_str_list * (top.h); nil map when membership_nil */
	int membership_nil;
	fe_edge *edges;
	size_t n_edges;
	int edges_nil;
	fe_diags diags;
} fe_result;

/* ---- program.go winInfo, varInfo ---- */
typedef struct {
	int64_t len;
	int active;
} fe_win_info;

typedef struct {
	int bool_;
	fe_ival iv;
	fe_name_table from; /* immutable: a join makes a new set */
	int from_nil;
	int wide, mixed, kread; /* kread: a Wide value from ctx.read on every path (its diagnostics keep the ctx.read text) */
} fe_var_info;

/* ---- loop.go loopFrame and ctxSnapshot ---- */
typedef struct {
	int64_t n;
	fe_name_table *breaks; /* each an env: name -> fe_var_info* */
	size_t n_breaks;
	fe_name_table *nexts;
	size_t n_nexts;
} fe_loop_frame;

typedef struct {
	int64_t diags;
	fe_name_table refs, ref_map, ref_key, wins;
	fe_ptr_set used, used_globals, used_rings;
	fe_name_table bad_bind, poisoned, status_reported, locals;
	sr_imap skip_ifs;
} fe_ctx_snapshot;

/* ---- subprogram.go funcInfo, flowSrc, flow, callSite, fnFlows ---- */
struct fe_func_info {
	sr_str name;
	const sr_node *def;
	sr_str *params;
	size_t n_params;
	int64_t decl;
	fe_ival *arg_iv; /* NULL is nil (no call site) */
	size_t n_arg_iv;
	sr_str *path;
	size_t n_path;
	fe_program *prog;
	int bad;
	int called;
	int64_t borrow_idx;
	fe_map_decl *borrow_map;
	int64_t win_idx;
	int64_t win_len;
	int64_t ctx_idx;
	sr_str ctx_kind;
	sr_str shape_err;
	sr_imap w;      /* argument index -> fe_name_table* (a set of sinks) */
	fe_name_table r_maps;
	sr_imap r_param; /* index -> non-NULL */
};

typedef struct {
	fe_name_table maps;
	sr_imap params;
	sr_imap rets;
} fe_flow_src;

typedef struct {
	fe_flow_src src;
	sr_str sink;
	fe_pos pos;
	sr_str *path;
	size_t n_path;
} fe_flow;

typedef struct {
	int64_t id;
	sr_str caller;
	fe_func_info *callee;
	fe_flow_src *args;
	size_t n_args;
	fe_pos pos;
	sr_str *path;
	size_t n_path;
} fe_call_site;

typedef struct {
	fe_flow *flows;
	size_t n_flows, cap_flows;
	fe_call_site **sites;
	size_t n_sites, cap_sites;
} fe_fn_flows;

/* ---- the analyzer during steps 3-7: the steps 1-2 state plus the body phase's fields (analyze.go analyzer) ---- */
typedef struct {
	fe_z *z;      /* the common fields, diags among them */
	fe_top *top;  /* kts, maps, records, rings, globals, the bad sets, root_kinds, roots, plain, ... (top.h) */
	sr_analysis typing;
	fe_name_table funcs;    /* name -> fe_func_info* */
	fe_name_table flows_of; /* name -> fe_fn_flows* */
	sr_imap site_by_node;   /* node id -> fe_call_site* */
	int any_bad_func;
} fe_analysis;

/* ---- program.go progCtx ---- */
typedef struct {
	fe_name_table status_reported;
	fe_analysis *z;
	const sr_ast *a;
	const sr_types *t;
	fe_program *prog;
	sr_str name;
	sr_str param;
	const sr_node *def;
	fe_name_table refs;    /* -> const sr_node* */
	fe_name_table ref_map; /* -> fe_map_decl* */
	fe_name_table ref_key; /* -> fe_expr* */
	fe_name_table wins;    /* -> fe_win_info* */
	fe_ptr_set used;
	fe_ptr_set used_globals;
	fe_ptr_set used_rings;
	fe_name_table bad_bind;
	fe_name_table ostrs;
	int ring_make;
	fe_name_table ostr_live;
	fe_name_table kptrs; /* -> fe_kernel_type_decl* */
	fe_name_table kchecked;
	fe_name_table so_sock; /* the socket-argument rule: kernel pointer locals that are a struct_ops member's checked socket argument (writable by the socket-write rule) */
	sr_str *fpath;
	size_t n_fpath;
	sr_str ctx_kind;
	fe_name_table poisoned;
	sr_imap skip_ifs;
	fe_name_table env; /* -> fe_var_info* */
	fe_loop_frame **loops;
	size_t n_loops;
	sr_str esc_arm;
	fe_name_table block_locals;
	sr_imap guard_returns; /* node id -> non-NULL */
} fe_prog_ctx;

typedef sr_str (*fe_msg_fn)(void *u, sr_str ref);
typedef int (*fe_walk_fn)(void *u, const sr_node *n);

/* =========================================================================================================================
 * Core: called by G1 and G2
 * ========================================================================================================================= */
void fe_ctx_add(fe_prog_ctx *c, fe_verdict v, fe_code code, const sr_node *n, sr_str msg); /* program.go add */
sr_str fe_rbs(fe_prog_ctx *c, const sr_node *n);                                           /* program.go rbs */
int fe_typed(fe_prog_ctx *c, const sr_node *x);                                             /* program.go typed */
fe_stmts fe_ctx_stmts(fe_prog_ctx *c, const sr_node *const *ns, size_t n, sr_str ref_var);  /* program.go stmts */
int fe_is_var_read(fe_prog_ctx *c, const sr_node *n, sr_str name);                          /* program.go isVarRead */
int fe_value_ok(fe_prog_ctx *c, fe_expr *e, const sr_node *n);                              /* program.go valueOK */
fe_expr *fe_ctx_expr(fe_prog_ctx *c, const sr_node *n, sr_str ref_var);                     /* program.go expr */
sr_str fe_callee(fe_prog_ctx *c, const sr_node *n, int *ok);                                /* program.go callee */
fe_map_decl *fe_map_of(fe_prog_ctx *c, const sr_node *recv, const sr_node *call);           /* program.go mapOf */
fe_expr *fe_ctx_key(fe_prog_ctx *c, const sr_node *n, fe_map_decl *m, sr_str ref_var);      /* program.go key */
fe_expr *fe_ctx_value(fe_prog_ctx *c, const sr_node *n, fe_map_decl *m, sr_str ref_var, sr_str role); /* program.go value */
int fe_rmw_first(fe_prog_ctx *c, const sr_node *n, const sr_node *val, fe_map_decl *m, fe_expr *k, fe_msg_fn msg,
		 void *u);                                                                   /* program.go rmwFirst */
fe_name_table fe_derived_refs(fe_prog_ctx *c, const sr_node *n);                            /* program.go derivedRefs */
int fe_reads_ref_via(fe_prog_ctx *c, const sr_node *n, sr_str ref);                         /* program.go readsRefVia */
void fe_note_flow(fe_prog_ctx *c, const sr_node *val, fe_map_decl *m, const sr_node *at);   /* subprogram.go noteFlow */
void fe_note_flow_key(fe_prog_ctx *c, const sr_node *val, sr_str k, const sr_node *at);     /* subprogram.go noteFlowKey */
sr_str fe_ctx_kind_of(fe_prog_ctx *c);                                                      /* subprogram.go ctxKindOf */

/* free functions of the core */
const sr_node **fe_args(const sr_ast *a, const sr_node *call, size_t *n);                   /* analyze.go args */
sr_str fe_const_name(const sr_ast *a, const sr_node *n);                                    /* analyze.go constName */
fe_ival fe_iv(intv lo, intv hi);                                                            /* interval.go iv */
fe_ival fe_point(intv v);                                                                   /* interval.go point */
sr_str fe_reads_map(const fe_expr *e, const fe_map_decl *m, int *ok);                       /* program.go readsMap */
fe_ival fe_type_range(const fe_map_decl *m);                                                /* program.go typeRange */
fe_name_table fe_verdicts_of(sr_str kind);                                                  /* analyze.go verdictsOf (-> sr_str*) */
void fe_walk(const sr_ast *a, const sr_node *n, fe_walk_fn f, void *u);                     /* analyze.go walk */
fe_name_table fe_copy_env(const fe_name_table *e);                                          /* program.go copyEnv */
int fe_escapes(const fe_stmts *ss);                                                         /* loop.go escapes */
fe_name_table fe_join_arms(const fe_name_table *pre, const fe_name_table *a, const fe_name_table *b, int esc_a,
			   int esc_b);                                                       /* program.go joinArms */
sr_str fe_verdict_returns(sr_str kind);                                                     /* program.go verdictReturns */
/* also from fe.h: fe_literal (analyzer.literal), fe_pos_of (analyzer.pos); AST access: fe_node_ref, fe_node_arr and the spinelread
 * sr_ast nodes map (AST.ref, AST.arr, AST.node) */
const sr_node *fe_ast_ref(const sr_ast *a, const sr_node *n, const char *field);            /* ast.go AST.ref */
const sr_node **fe_ast_arr(const sr_ast *a, const sr_node *n, const char *field, size_t *count); /* ast.go AST.arr */
const sr_node *fe_ast_node(const sr_ast *a, int64_t id);                                    /* ast.go AST.node */
/* methods of the shared declaration types kept by the core (contract change 1, 2026-11-13) */
fe_record_field *fe_record_decl_field(fe_record_decl *r, sr_str name);                      /* record.go RecordDecl.Field (NULL = nil) */
fe_kernel_field *fe_kernel_type_decl_field(fe_kernel_type_decl *k, sr_str name);            /* kernel.go KernelTypeDecl.field (NULL = nil); contract change 2 */
fe_tp_arg *fe_program_tp_arg(fe_program *p, int64_t i);                                      /* kernel.go Program.tpArg (NULL = nil); contract change 2 */
sr_str fe_map_kind(const fe_map_decl *m);                                                   /* analyze.go MapDecl.MapKind */
int fe_map_is_hash(const fe_map_decl *m);                                                   /* analyze.go IsHash */
int fe_map_is_array(const fe_map_decl *m);                                                  /* analyze.go IsArray */
int fe_map_per_cpu(const fe_map_decl *m);                                                   /* analyze.go PerCPU */
sr_str fe_map_class_name(const fe_map_decl *m);                                             /* analyze.go ClassName */
sr_str fe_map_key_type_name(const fe_map_decl *m);                                          /* analyze.go KeyTypeName */
sr_str fe_map_type_name(const fe_map_decl *m);                                              /* analyze.go TypeName */
/* step 7's free functions, moved to the core (contract change 1; were G1 / G2) */
fe_diags fe_one_reason_each(const fe_diags *ds);                                           /* record.go oneReasonEach */
fe_global_decl **fe_used_globals_of(fe_global_decl *const *order, size_t n_order, fe_program *const *progs, size_t n_progs,
				    size_t *n_out);                                          /* globals.go usedGlobalsOf */
fe_ival fe_width_range(int64_t bits, int is_signed);                                       /* globals.go widthRange */
int fe_uses_kernel_types(const fe_program *p);                                             /* kernel.go usesKernelTypes */

/* =========================================================================================================================
 * G1, maps and records: called by the core or by G2
 *
 * The (Stmt, bool, bool) functions (fe_record_call, fe_ref_atomic, fe_per_cpu_add): the return is Go's first bool, "handled"
 * (the statement is this form); *ok2 is Go's second bool, "ok" (no diagnostic stopped it); *out is the Stmt, read only when both
 * are true. A false return leaves *ok2 unread.
 * ========================================================================================================================= */
fe_expr *fe_field_read(fe_prog_ctx *c, const sr_node *n, const sr_node *load, sr_str ref_var); /* record.go fieldRead */
int fe_record_call(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2); /* record.go recordCall: returns Go's first bool */
int fe_record_update(fe_prog_ctx *c, const sr_node *n, sr_str name, fe_map_decl *m, const sr_node *const *as, size_t n_as,
		     sr_str ref_var, fe_stmt *out);                                          /* record.go recordUpdate */
fe_expr *fe_elem_read(fe_prog_ctx *c, const sr_node *n, const sr_node *mem, const sr_node *load, sr_str ref_var); /* record.go elemRead */
int fe_exempt(fe_prog_ctx *c, const fe_map_decl *m);                                       /* hash.go exempt */
fe_map_decl *fe_status_call(fe_prog_ctx *c, const sr_node *n, int *bad, int *ok);         /* hash.go statusCall */
int fe_status_parent_ok(fe_prog_ctx *c, const sr_node *n);                                 /* hash.go statusParentOK */
int fe_status_local_ok(fe_prog_ctx *c, const sr_node *w, fe_map_decl *m, sr_str op);       /* hash.go statusLocalOK */
fe_expr *fe_status_expr(fe_prog_ctx *c, const sr_node *n, fe_map_decl *m, sr_str ref_var); /* hash.go statusExpr */
fe_expr *fe_hash_key(fe_prog_ctx *c, const sr_node *n, fe_map_decl *m, sr_str ref_var);   /* hash.go hashKey */
int fe_ref_atomic(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2); /* hash.go refAtomic */
int fe_per_cpu_add(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2); /* hash.go perCPUAdd */
fe_expr *fe_lpm_key(fe_prog_ctx *c, const sr_node *call, fe_map_decl *m, const sr_node *const *as, size_t n_as,
		    sr_str ref_var);                                                         /* lpm.go lpmKey */
fe_ring_decl *fe_ring_of(fe_prog_ctx *c, const sr_node *recv);                             /* ring.go ringOf (also G2) */
int fe_is_output(fe_prog_ctx *c, const sr_node *n);                                        /* ring.go isOutput */
int fe_output_of_bad_ring(fe_prog_ctx *c, const sr_node *n);                               /* ring.go outputOfBadRing */
fe_expr *fe_ring_output(fe_prog_ctx *c, const sr_node *n, sr_str ref_var);                 /* ring.go ringOutput */
fe_expr *fe_record_make(fe_prog_ctx *c, const sr_node *mk, fe_record_decl *rec, fe_map_decl *m, sr_str ref_var); /* ring.go recordMake (G2) */
int fe_output_is_condition(fe_prog_ctx *c, const sr_node *n);                              /* ring.go outputIsCondition */
fe_expr *fe_global_read(fe_prog_ctx *c, const sr_node *n, fe_global_decl *g, sr_str name, const sr_node *const *as,
			size_t n_as, fe_pos p);                                              /* globals.go globalRead */
int fe_global_add(fe_prog_ctx *c, const sr_node *n, fe_global_decl *g, const sr_node *const *as, size_t n_as,
		  sr_str ref_var, fe_stmt *out);                                             /* globals.go globalAdd */
fe_global_decl *fe_counter_read(fe_prog_ctx *c, const sr_node *n);                         /* globals.go counterRead */
int fe_global_stmt(fe_prog_ctx *c, const sr_node *n, fe_global_decl *g, const sr_node *const *as, size_t n_as, sr_str ref_var, fe_stmt *out,
		   int *handled); /* globals.go globalStmt */
void fe_redirect_verdict(fe_prog_ctx *c, const sr_node *n, const sr_node *v);              /* devmap.go redirectVerdict */
int fe_is_sk_assign(fe_prog_ctx *c, const sr_node *v);                                     /* sklookup.go isSkAssign */
int fe_sk_assign_stmt(fe_prog_ctx *c, const sr_node *w, fe_stmt *out);                     /* sklookup.go skAssignStmt */
int fe_output_comm(fe_prog_ctx *c, const sr_node *call, sr_str name, sr_str ref_var, fe_stmt *out); /* comm.go outputComm (G2) */
int fe_output_buf(fe_prog_ctx *c, const sr_node *call, sr_str name, sr_str ref_var, fe_stmt *out);  /* outputbuf.go outputBuf (G2) */
/* G1 free functions used elsewhere */
int fe_member_like(sr_str name);                                                           /* record.go memberLike (G2) */
sr_str fe_dropped_msg(const fe_ring_decl *r);                                              /* ring.go droppedMsg */
sr_str fe_output_buf_form(sr_str param);                                                   /* outputbuf.go outputBufForm */
sr_str fe_output_comm_shape(const fe_ring_decl *r);                                        /* comm.go outputCommShape */
int fe_per_cpu_exempt(const fe_map_decl *m, const sr_str *kinds, size_t n_kinds);          /* hash.go perCPUExempt */
sr_str fe_status_ignored(const fe_map_decl *m, sr_str op);                                 /* hash.go statusIgnored */
sr_str fe_value_types_text(sr_str kind);                                                   /* lpm.go valueTypesText */
sr_str fe_value_types_words(sr_str kind);                                                  /* lpm.go valueTypesWords */
/* methods of the shared declaration types, implemented by G1 in body_decl.c (contract change 1, 2026-11-13; strings are arena sr_str) */
int64_t fe_record_field_size(const fe_record_field *f);                                    /* record.go RecordField.Size */
sr_str fe_record_field_decl_type(const fe_record_field *f);                                /* record.go DeclType */
void fe_record_field_flat(const fe_record_field *f, sr_str **names, int64_t **offsets, size_t *n); /* record.go Flat: n >= 1, never nil */
sr_str fe_record_field_type_name(const fe_record_field *f);                                /* record.go TypeName */
fe_ival fe_record_field_range(const fe_record_field *f);                                   /* record.go Range (set = 1 always) */
int fe_record_decl_has_array(const fe_record_decl *r);                                     /* record.go HasArray */
sr_str fe_record_decl_mlir_type(const fe_record_decl *r);                                  /* record.go MLIRType */
sr_str fe_record_decl_shape(const fe_record_decl *r);                                      /* record.go Shape */
int fe_global_counter(const fe_global_decl *g);                                            /* globals.go Counter */
sr_str fe_global_type_name(const fe_global_decl *g);                                       /* globals.go TypeName */
int fe_map_is_lpm(const fe_map_decl *m);                                                   /* lpm.go IsLpm */
uint64_t fe_map_flags(const fe_map_decl *m);                                               /* lpm.go Flags */
int fe_map_is_devmap(const fe_map_decl *m);                                                /* devmap.go IsDevmap */

/* =========================================================================================================================
 * G2, tracing and kernel: called by the core or by G1
 * ========================================================================================================================= */
int fe_kptr_call(fe_prog_ctx *c, const sr_node *v);                                        /* kernel.go kptrCall */
int fe_kptr_bind(fe_prog_ctx *c, const sr_node *w, int top, fe_stmt *out);                 /* kernel.go kptrBind */
fe_expr *fe_kfield_read(fe_prog_ctx *c, const sr_node *n, const sr_node *recv, fe_pos p);  /* kernel.go kfieldRead */
void fe_kptr_misuse(fe_prog_ctx *c, const sr_node *n, sr_str name);                        /* kernel.go kptrMisuse */
int fe_is_kptr_read(fe_prog_ctx *c, const sr_node *n);                                     /* kernel.go isKptrRead (G1) */
int fe_top_level(fe_prog_ctx *c, const sr_node *n);                                        /* kernel.go topLevel */
int fe_kcheck_call(fe_prog_ctx *c, const sr_node *v);                                      /* kernel.go kcheckCall */
int fe_kcheck_stmt(fe_prog_ctx *c, const sr_node *w, const sr_node *ifn, sr_str ref_var, fe_stmt *out); /* kernel.go kcheckStmt */
void fe_so_add_index(fe_program *pg, int64_t v); /* structops.go soAddIndex */
fe_tp_arg *fe_struct_ops_sock(fe_prog_ctx *c, const sr_node *v, const sr_node **as, int64_t i, fe_kernel_type_decl *h); /* structops.go structOpsSock */
void fe_struct_ops_kptr_refused(fe_prog_ctx *c, const sr_node *n); /* structops.go structOpsKptrRefused */
int fe_kstore_call(fe_prog_ctx *c, const sr_node *n, fe_stmt *out, int *ok); /* structops.go kstoreCall */
/* scx.go (body_scx.c) */
int fe_is_scx_call(fe_prog_ctx *c, const sr_node *n);
int fe_scx_stmt(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok);
fe_expr *fe_scx_expr(fe_prog_ctx *c, const sr_node *n, sr_str ref_var);
fe_expr *fe_scx_const(fe_prog_ctx *c, const sr_node *n, int *handled);
int fe_wide_kread(fe_prog_ctx *c, const fe_expr *e); /* program.go wideKread */
int fe_is_u64_op(sr_str name);                        /* u64ops.go u64Ops */
int fe_scx_select(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok);
void fe_scx_multi_refused(fe_prog_ctx *c, const sr_node *n);
int fe_scx_status_local(fe_prog_ctx *c, const sr_node *n, const sr_node *v, sr_str ref_var, fe_stmt *out, int *push);
int fe_scx_op_bits(sr_str op, int i);
sr_str fe_kchecked_root(fe_prog_ctx *c, const sr_node *n);                                 /* kernel.go kcheckedRoot */
int fe_kcopy_stmt(fe_prog_ctx *c, const sr_node *n, const sr_node *cp, sr_str ref, fe_map_decl *m, fe_record_field *rf,
		  fe_stmt *out);                                                             /* kernel.go kcopyStmt (G1) */
fe_expr *fe_kpath_read(fe_prog_ctx *c, const sr_node *n, fe_pos p, int *ok);               /* kernel.go kpathRead */
int fe_kptr_path_recv(fe_prog_ctx *c, const sr_node *recv);                                /* kernel.go kptrPathRecv (G1) */
fe_kparam *fe_uprobe_param(fe_prog_ctx *c, const sr_node *n, const sr_node *const *as, size_t n_as); /* uprobe.go uprobeParam (also G1) */
int fe_is_output_str(fe_prog_ctx *c, const sr_node *n);                                    /* uprobe.go isOutputStr */
int fe_output_str(fe_prog_ctx *c, const sr_node *call, sr_str name, sr_str ref_var, fe_stmt *out); /* uprobe.go outputStr */
int fe_output_str_make(fe_prog_ctx *c, const sr_node *call, const sr_node *const *as, size_t n_as, fe_ring_decl *r,
		       sr_str meth, fe_record_field *f, fe_record_field *st, sr_str name, sr_str ref_var,
		       fe_stmt *out);                                                        /* uprobe.go outputStrMake (G1) */
fe_stmts fe_output_str_check(fe_prog_ctx *c, const sr_node *w, const sr_node *ifn, sr_str ref_var, int *ok); /* uprobe.go outputStrCheck */
fe_expr *fe_ostr_status(fe_prog_ctx *c, const sr_node *n, const sr_node *recv, fe_pos p);  /* uprobe.go ostrStatus */
fe_expr *fe_kaddr_read(fe_prog_ctx *c, const sr_node *n, const sr_node *recv, fe_pos p);   /* kpath.go kaddrRead */
int fe_is_fmod_return(fe_prog_ctx *c, const sr_node *n);                                   /* fmodret.go isFmodReturn */
void fe_fmod_verdict(fe_prog_ctx *c, const sr_node *n, const sr_node *v);                  /* fmodret.go fmodVerdict */
bigint *fe_fmod_guard_value(fe_prog_ctx *c, const sr_node *r, const sr_node *v, int *ok);  /* fmodret.go fmodGuardValue */
int fe_kread_stmt(fe_prog_ctx *c, const sr_node *n, fe_stmt *out);                         /* kread.go kreadStmt */
int fe_kread_status_ok(fe_prog_ctx *c, const sr_node *t, sr_str name, sr_str what, sr_str failed); /* kread.go kreadStatusOK (G1) */
int fe_is_tp_copy(fe_prog_ctx *c, const sr_node *x);                                      /* tpcopy.go isTpCopy (G1) */
int fe_ctx_copy_other_kind(fe_prog_ctx *c, const sr_node *x);                              /* tpcopy.go ctxCopyOtherKind (G1) */
fe_tp_field *fe_tp_copy_field(fe_prog_ctx *c, const sr_node *x, const sr_node *at, fe_record_field *rf, sr_str rec_const,
			      int *ok);                                              /* tpcopy.go tpCopyField (G1) */
int fe_tpcopy_stmt(fe_prog_ctx *c, const sr_node *n, const sr_node *cp, sr_str ref, fe_map_decl *m, fe_record_field *rf,
		   fe_stmt *out);                                                            /* tpcopy.go tpcopyStmt (G1) */
fe_expr *fe_flow_key_read(fe_prog_ctx *c, const sr_node *n, sr_str ref_var);               /* flow.go flowKeyRead */
int fe_flow_key_store(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out);     /* flow.go flowKeyStore */
/* G2 free functions used elsewhere */
sr_str fe_output_str_shape(const fe_ring_decl *r);                                         /* uprobe.go outputStrShape */

#endif
