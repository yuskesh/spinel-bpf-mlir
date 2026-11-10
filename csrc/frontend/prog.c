/* prog.c — internal/frontend/program.go, part A: progCtx's helpers, program(), the statement
 * walker, assignments, if, conditions, expressions, operators, the callee checks and the map key / value rules.
 * The Go code stays the canon; every function names the Go it follows. */
#include "core.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static int one_ = 1;
#define TRUE_ ((void *)&one_)
#define S(x) sr_cstr(x)

/* ---- tables (program.go binOps, cmpOps, mapOps, windowReads, analyze.go operators, hash.go errnoConsts, program.go ctxReads / ctxFields) ---- */
static const char *const map_ops[] = {"atomic_add", "update", "lookup", "insert", "replace", "delete", "add_or_init", NULL};
static const char *const bin_ops[] = {"+", "-", "*", "&", "|", "^", "<<", ">>", "/", "%", NULL};
static const char *const cmp_ops[] = {"==", "!=", "<", "<=", ">", ">=", NULL};
static const char *const operators[] = {"+",  "-",  "*", "/", "%",  "**", "==", "!=", "<",   "<=",  ">",  ">=", "<=>",
					"&",  "|",  "^", "<<", ">>", "!", "~",  "-@", "+@", "===", "[]", "[]=", NULL};

int fe_in_map_ops(sr_str s) { return t_in(s, map_ops); }
int fe_in_bin_ops(sr_str s) { return t_in(s, bin_ops); }
int fe_in_cmp_ops(sr_str s) { return t_in(s, cmp_ops); }
int fe_in_operators(sr_str s) { return t_in(s, operators); }

static int errno_const(sr_str cn, int64_t *v)
{
	static const struct {
		const char *n;
		int64_t v;
	} t[] = {{"BPF::ENOENT", -2}, {"BPF::E2BIG", -7}, {"BPF::ENOMEM", -12}, {"BPF::EEXIST", -17}};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (fe_streq(cn, t[i].n)) {
			*v = t[i].v;
			return 1;
		}
	return 0;
}

int fe_window_read_len(sr_str name, int64_t *n)
{
	static const struct {
		const char *n;
		int64_t v;
	} t[] = {{"u8", 1}, {"be16", 2}, {"be32", 4}, {"le16", 2}, {"le32", 4}};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (fe_streq(name, t[i].n)) {
			if (n)
				*n = t[i].v;
			return 1;
		}
	return 0;
}

int fe_ctx_field(sr_str kind, sr_str name)
{
	if (fe_streq(kind, "xdp"))
		return fe_streq(name, "ingress_ifindex");
	if (fe_streq(kind, "sched_cls"))
		return fe_streq(name, "len") || fe_streq(name, "mark");
	if (fe_streq(kind, "cgroup_skb"))
		return fe_streq(name, "len");
	if (fe_streq(kind, "sk_lookup"))
		return fe_streq(name, "local_port");
	return 0;
}

const char *fe_ctx_reads(sr_str kind)
{
	static const char *const t[][2] = {
	    {"fentry", "`ctx.arg(i)` (an integer argument declared in `BPF.fentry … args:`) and `q = ctx.kptr_or_null(i, T)` (a struct argument)"},
	    {"fexit", "`ctx.ret` (the declared return type)"},
	    {"kprobe", "`ctx.arg(n)` with n a declared parameter number (1..6)"},
	    {"ksyscall", "`ctx.arg(n)` with n a declared syscall argument number (1..6 — the syscall convention, the 4th is r10)"},
	    {"kretprobe", "`ctx.ret` (the declared return type — the return register; arguments are not readable on return)"},
	    {"tracepoint", "`ctx.field(:name)` with name a field declared in `BPF.tracepoint … fields:` (its declared type)"},
	    {"raw_tp", "`ctx.arg(i)` with i an Integer literal 0..11 (the tracepoint's args[i], 0-origin — a raw u64: narrow it with `x & M` / `x >> K` or store it in a u64 map)"},
	    {"uretprobe", "`ctx.ret` (the declared return type — the return register; arguments are not readable on return)"},
	    {"uprobe", "`ctx.arg(n)` (an integer parameter) and `ctx.str_arg(n)` (a :user_str parameter — only as the third argument of `R.output_str`) with n a declared parameter number (1..6)"},
	    {"tp_btf", "`t = ctx.kptr(i, T)` (a struct argument — then `t.load.m`) and `ctx.arg(i)` (an integer argument) with i declared in `BPF.tp_btf … args:`"},
	    {"socket_filter", "`ctx.len` (the packet length, u32 — a socket_filter cannot read the packet itself in bpf-mlir v1.14.0)"},
	    {"netfilter", "`st = ctx.state(T)` (nf_hook_state) and `sk = ctx.skb(T)` (sk_buff) — then `st.load.hook` etc. (a netfilter program has no packet window)"},
	    {"fmod_ret", "`ctx.arg(i)` (an integer argument declared in `BPF.fmod_ret … args:`)"},
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (fe_streq(kind, t[i][0]))
			return t[i][1];
	return "";
}

/* hasPacket (analyze.go) */
int fe_has_packet(sr_str kind)
{
	return fe_streq(kind, "xdp") || fe_streq(kind, "sched_cls") || fe_streq(kind, "cgroup_skb") || fe_streq(kind, "flow_dissector");
}

/* ---- RecordDecl.Field (record.go; the MapDecl methods are in steps.c) ---- */
fe_record_field *fe_record_decl_field(fe_record_decl *r, sr_str name)
{
	for (size_t i = 0; i < r->n_fields; i++)
		if (sr_eq(r->fields[i].name, name))
			return &r->fields[i];
	return NULL;
}

/* KernelTypeDecl.field (kernel.go) and Program.tpArg (kernel.go): the core keeps them, since G1 and the core call them
 * as well as G2 (contract change 2) */
fe_kernel_field *fe_kernel_type_decl_field(fe_kernel_type_decl *k, sr_str name)
{
	for (size_t i = 0; i < k->n_fields; i++)
		if (sr_eq(k->fields[i].name, name))
			return &k->fields[i];
	return NULL;
}

fe_tp_arg *fe_program_tp_arg(fe_program *p, int64_t i)
{
	for (size_t k = 0; k < p->n_t_args; k++)
		if (p->t_args[k].idx == i)
			return &p->t_args[k];
	return NULL;
}

/* ---- messages: t_fmt's verbs, plus %I (an fe_ival, Ival.String) and %V (Go's %v of a []string: an sr_str * and a size_t) ---- */
static int vfmt(fe_z *z, sr_buf *b, const char *fmt, va_list ap)
{
	for (const char *p = fmt; *p; p++) {
		if (*p != '%') {
			sr_putc(b, *p);
			continue;
		}
		switch (*++p) {
		case 's':
			sr_putstr(b, va_arg(ap, sr_str));
			break;
		case 'S':
			sr_puts(b, va_arg(ap, const char *));
			break;
		case 'd':
			fe_fmt_d(b, va_arg(ap, int64_t));
			break;
		case 'u':
			sr_printf(b, "%llu", (unsigned long long)va_arg(ap, uint64_t));
			break;
		case 'q':
			if (!fe_fmt_q(z, b, va_arg(ap, sr_str)))
				return 0;
			break;
		case 'B':
			fe_fmt_big(b, va_arg(ap, const bigint *));
			break;
		case 'I':
			sr_putstr(b, fe_ival_string(va_arg(ap, fe_ival)));
			break;
		case 'V': {
			const sr_str *v = va_arg(ap, const sr_str *);
			size_t n = va_arg(ap, size_t);
			sr_putc(b, '[');
			for (size_t i = 0; i < n; i++) {
				if (i)
					sr_putc(b, ' ');
				sr_putstr(b, v[i]);
			}
			sr_putc(b, ']');
			break;
		}
		case '%':
			sr_putc(b, '%');
			break;
		default:
			abort(); /* a verb this file does not define: a defect of the port */
		}
	}
	return 1;
}

sr_str fe_cfmt(fe_z *z, int *ok, const char *fmt, ...)
{
	sr_buf b = {0};
	va_list ap;
	va_start(ap, fmt);
	*ok = vfmt(z, &b, fmt, ap);
	va_end(ap);
	return sr_bufstr(&b);
}

/* z.pos with Go's nil panic recorded */
fe_pos fe_cpos(fe_prog_ctx *c, const sr_node *n)
{
	if (!n) {
		t_nil_panic = 1;
		return (fe_pos){0};
	}
	return fe_pos_of(c->z->z, c->a, n);
}

/* progCtx.add (program.go) with a format */
void fe_cadd(fe_prog_ctx *c, fe_verdict v, fe_code code, const sr_node *n, const char *fmt, ...)
{
	sr_buf b = {0};
	va_list ap;
	va_start(ap, fmt);
	int ok = vfmt(c->z->z, &b, fmt, ap);
	va_end(ap);
	if (ok)
		fe_ctx_add(c, v, code, n, sr_bufstr(&b));
}

void fe_ctx_add(fe_prog_ctx *c, fe_verdict v, fe_code code, const sr_node *n, sr_str msg)
{
	size_t np;
	sr_str *path = fe_ctx_path(c, &np);
	fe_diags_push(&c->z->z->diags, (fe_diag){v, code, fe_cpos(c, n), path, np, msg});
}

/* ---- AST access for the groups (body.h) ---- */
const sr_node *fe_ast_ref(const sr_ast *a, const sr_node *n, const char *field) { return t_ref(a, n, field); }
const sr_node **fe_ast_arr(const sr_ast *a, const sr_node *n, const char *field, size_t *count)
{
	t_nodes v = t_arr(a, n, field);
	*count = v.n;
	return v.v;
}
const sr_node *fe_ast_node(const sr_ast *a, int64_t id) { return t_node(a, id); }
const sr_node **fe_args(const sr_ast *a, const sr_node *call, size_t *n)
{
	t_nodes v = t_args(a, call);
	*n = v.n;
	return v.v;
}
sr_str fe_const_name(const sr_ast *a, const sr_node *n) { return t_const_name(a, n); }

typedef struct {
	fe_walk_fn f;
	void *u;
} walk_adapter;
static int walk_adapt(void *ctx, const sr_node *n)
{
	walk_adapter *w = ctx;
	return w->f(w->u, n);
}
void fe_walk(const sr_ast *a, const sr_node *n, fe_walk_fn f, void *u)
{
	walk_adapter w = {f, u};
	if (n)
		t_walk(a, n, walk_adapt, &w);
}

/* ---- progCtx's helpers (program.go progCtx.rbs, progCtx.typed) ---- */

/* rbs */
sr_str fe_rbs(fe_prog_ctx *c, const sr_node *n)
{
	size_t cnt;
	long i = sr_type_of(c->t, c->a, n, &cnt);
	if (i < 0)
		return (sr_str){0};
	return c->t->types[i].rbs;
}

/* the TypeOf count */
size_t fe_type_count(fe_prog_ctx *c, const sr_node *n)
{
	size_t cnt;
	long i = sr_type_of(c->t, c->a, n, &cnt);
	return i >= 0 ? 1 : cnt;
}

int fe_is_var_read(fe_prog_ctx *c, const sr_node *n, sr_str name)
{
	(void)c;
	return n && t_is(n, "LocalVariableReadNode") && sr_eq(t_str(n, "name"), name);
}

/* typed */
int fe_typed(fe_prog_ctx *c, const sr_node *x)
{
	size_t cnt = fe_type_count(c, x);
	if (cnt > 1) {
		fe_cadd(c, FE_REJECTED, FE_SB015, x, "Spinel gives this %s %d types (a specialised node) — the eBPF side needs exactly one", x->type,
			(int64_t)cnt);
		return 0;
	}
	if (cnt == 0 && c->prog && fe_streq(c->prog->kind, "fentry") && t_is(x, "CallNode") && fe_streq(t_str(x, "name"), "kptr") &&
	    fe_is_var_read(c, t_ref(c->a, x, "receiver"), c->param)) {
		fe_cadd(c, FE_REJECTED, FE_SB033, x,
			"a fentry program reads its struct arguments only as `q = %s.kptr_or_null(i, T)` and `if q` (fentry pointers may always be NULL — declare `i => [:or_null, T]`)",
			c->param);
		return 0;
	}
	if (cnt == 0 && c->prog && !fe_has_packet(c->prog->kind) && t_is(x, "CallNode") &&
	    fe_is_var_read(c, t_ref(c->a, x, "receiver"), c->param)) {
		fe_cadd(c, FE_REJECTED, FE_SB028, x, "the %s context has no `%s` — it reads %S", c->prog->kind, t_str(x, "name"),
			fe_ctx_reads(c->prog->kind));
		return 0;
	}
	if (cnt == 0) {
		fe_cadd(c, FE_UNKNOWN, FE_SB001, x, "Spinel gives this %s no type — outside the typed subset (fail closed)", x->type);
		return 0;
	}
	return 1;
}

/* ---- program (program.go) ---- */

static fe_prog_ctx *new_ctx(fe_analysis *z, const sr_ast *a, const sr_node *d, sr_str name)
{
	fe_prog_ctx *c = sr_alloc(sizeof *c);
	c->z = z;
	c->a = a;
	c->t = z->typing.types;
	c->def = d;
	c->name = name;
	return c;
}

fe_prog_ctx *fe_new_ctx(fe_analysis *z, const sr_ast *a, const sr_node *d, sr_str name) { return new_ctx(z, a, d, name); }

typedef struct {
	fe_prog_ctx *c;
	sr_str kind;
	int bad;
} kind_walk;

static int kind_walk_fn(void *u, const sr_node *x)
{
	kind_walk *w = u;
	fe_prog_ctx *c = w->c;
	if (!w->bad && !fe_streq(w->kind, "fmod_ret") && fe_is_fmod_return(c, x)) {
		fe_cadd(c, FE_REJECTED, FE_SB028, x, "`BPF.fmod_return` ends only a fmod_ret program — %s", fe_verdict_returns(w->kind));
		w->bad = 1;
	}
	if (!w->bad && t_is(x, "ConstantPathNode")) {
		sr_str cn = t_const_name(c->a, x);
		sr_str vk = fe_verdict_kind_of(cn);
		sr_str rk = w->kind;
		if (vk.n == 0 || sr_eq(vk, rk)) {
		} else if (fe_streq(vk, "socket_filter") || fe_streq(rk, "socket_filter") || fe_streq(vk, "cgroup_skb") || fe_streq(rk, "cgroup_skb") ||
			   fe_streq(vk, "netfilter") || fe_streq(rk, "netfilter") || fe_streq(vk, "flow_dissector") ||
			   fe_streq(rk, "flow_dissector") || fe_streq(vk, "fmod_ret") || fe_streq(rk, "fmod_ret")) {
			fe_cadd(c, FE_REJECTED, FE_SB028, x, "%s is %s verdict — %s", cn, fe_verdict_kind_text(vk), fe_verdict_returns(rk));
			w->bad = 1;
		} else if (fe_streq(vk, "xdp") && fe_verdicts_of(rk).n == 0) {
			fe_cadd(c, FE_REJECTED, FE_SB028, x, "%s is an XDP verdict — a %s program returns nothing (its last value is dropped)", cn, rk);
			w->bad = 1;
		} else if (fe_verdicts_of(rk).n == 0) {
			fe_cadd(c, FE_REJECTED, FE_SB028, x,
				"%s is a sched_cls (tcx) verdict — a %s program returns nothing (its last value is dropped)", cn, rk);
			w->bad = 1;
		} else if (fe_streq(vk, "xdp")) {
			fe_cadd(c, FE_REJECTED, FE_SB028, x,
				"%s is an XDP verdict — a sched_cls (`BPF.tcx`) program returns BPF::TC_PASS or BPF::TC_DROP", cn);
			w->bad = 1;
		} else {
			fe_cadd(c, FE_REJECTED, FE_SB028, x,
				"%s is a sched_cls (tcx) verdict — an XDP program returns BPF::XDP_ABORTED / XDP_DROP / XDP_PASS / XDP_TX", cn);
			w->bad = 1;
		}
	}
	return !w->bad;
}

static int blocking_since(const fe_diags *ds, size_t before)
{
	for (size_t i = before; i < ds->n; i++)
		if (ds->v[i].verdict != FE_CONDITIONAL && ds->v[i].verdict != FE_VERIFIED)
			return 1;
	return 0;
}

fe_program *fe_program_of(fe_analysis *z, const sr_ast *a, const sr_node *d, const fe_root_decl *r)
{
	fe_prog_ctx *c = new_ctx(z, a, d, r->name);
	fe_program *p = sr_alloc(sizeof *p);
	c->prog = p;
	p->name = r->name;
	p->kind = r->kind;
	p->pos = fe_cpos(c, d);
	p->decl_pos = r->pos;
	p->end_line = d->end_line;
	p->target = r->target;
	p->nargs = r->nargs;
	p->ret = r->ret;
	p->params = r->params;
	p->n_params = r->n_params;
	p->params_nil = r->params_nil;
	p->binary_sha = r->binary_sha;
	p->binary_path = r->binary_path;
	p->sys_target = r->sys_target;
	p->t_args = r->targs;
	p->n_t_args = r->n_targs;
	p->t_args_nil = r->targs_nil;
	p->t_fields = r->tfields; /* shared with the root, as Go shares the slice */
	p->n_t_fields = r->n_tfields;
	p->t_fields_nil = r->tfields_nil;
	p->f_params_nil = p->globals_nil = p->maps_nil = p->rings_nil = 1;
	p->body.nil = 1;
	size_t before = z->z->diags.n;

	const sr_node *pn = t_ref(a, d, "parameters");
	t_nodes reqs = t_arr(a, pn, "requireds");
	if (reqs.n == 0) {
		t_nil_panic = 1; /* Go indexes [0] and panics */
		return NULL;
	}
	const sr_node *param = reqs.v[0];
	c->param = t_str(param, "name");
	sr_str cls = S(t_ctx_class(r->kind));
	size_t cnt;
	long pi = sr_type_of(c->t, a, param, &cnt);
	if (pi < 0 || !sr_eq(c->t->types[pi].rbs, cls) || !fe_class_in_lib(z, a, cls)) {
		sr_str got = S("(no type)");
		if (pi >= 0)
			got = c->t->types[pi].rbs;
		fe_cadd(c, FE_REJECTED, FE_SB010, param,
			"the context parameter `%s` must be typed BPF::%s (from ruby/lib/bpf.rb) by the typing probe, got %s", c->param, cls, got);
	}

	const sr_node *body = t_ref(a, d, "body");
	t_nodes stmts = {0};
	if (body) {
		if (!t_is(body, "StatementsNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB001, body,
				"the program body must be a plain sequence of statements (no rescue / ensure), got %s", body->type);
			return NULL;
		}
		stmts = t_arr(a, body, "body");
	}
	kind_walk kw = {c, r->kind, 0};
	t_walk(a, d, kind_walk_fn, &kw);
	if (kw.bad)
		return NULL;
	if (fe_verdicts_of(r->kind).n == 0) {
		p->body = fe_ctx_stmts(c, stmts.v, stmts.n, (sr_str){0});
		p->verdict = S("done");
		p->verdict_pos = fe_cpos(c, d);
	} else {
		if (stmts.n == 0) {
			fe_cadd(c, FE_REJECTED, FE_SB008, d, "the program `%s` must end with %s", r->name,
				fe_verdict_want(r->kind, S("an XDP verdict (BPF::XDP_PASS etc.)")));
			return NULL;
		}
		const sr_node *last = stmts.v[stmts.n - 1];
		memset(&c->guard_returns, 0, sizeof c->guard_returns);
		p->body = fe_guard_stmts(c, stmts.v, stmts.n - 1);
		fe_verdict_of(c, last);
	}
	fe_top *t = z->top;
	for (size_t i = 0; i < t->n_map_order; i++)
		if (fe_ptr_set_has(&c->used, t->map_order[i])) {
			T_PUSH(p->maps, p->n_maps, t->map_order[i]);
			p->maps_nil = 0;
		}
	for (size_t i = 0; i < t->n_ring_order; i++)
		if (fe_ptr_set_has(&c->used_rings, t->ring_order[i])) {
			T_PUSH(p->rings, p->n_rings, t->ring_order[i]);
			p->rings_nil = 0;
		}
	for (size_t i = 0; i < t->n_global_order; i++)
		if (fe_ptr_set_has(&c->used_globals, t->global_order[i])) {
			T_PUSH(p->globals, p->n_globals, t->global_order[i]);
			p->globals_nil = 0;
		}
	if (z->z->diags.n > before && blocking_since(&z->z->diags, before))
		return NULL;
	return p;
}

/* classInLib (program.go) */
typedef struct {
	fe_analysis *z;
	const sr_ast *a;
	sr_str name;
	int in_lib, elsewhere;
} class_walk;

static int class_walk_fn(void *u, const sr_node *n)
{
	class_walk *w = u;
	if (t_is(n, "ClassNode")) {
		sr_str cn = t_const_name(w->a, t_ref(w->a, n, "constant_path"));
		if (sr_eq(cn, w->name) || sr_eq(cn, t_cat(S("BPF::"), w->name))) {
			if (sr_eq(sr_ast_file(w->a, n), w->z->z->lib))
				w->in_lib = 1;
			else
				w->elsewhere = 1;
		}
	}
	return 1;
}

int fe_class_in_lib(fe_analysis *z, const sr_ast *a, sr_str name)
{
	class_walk w = {z, a, name, 0, 0};
	t_walk(a, t_root(a), class_walk_fn, &w);
	return w.in_lib && !w.elsewhere;
}

/* ---- the statement walker (program.go progCtx.stmts) ---- */

static void stmts_push(fe_stmts *out, fe_stmt s)
{
	fe_stmts_push(out, s);
}

/* a Go map[*T]bool used as a set: membership only, never iterated (callers walk a declaration order and ask has) */
int fe_ptr_set_has(const fe_ptr_set *s, const void *p)
{
	for (size_t i = 0; i < s->n; i++)
		if (s->v[i] == p)
			return 1;
	return 0;
}

void fe_ptr_set_add(fe_ptr_set *s, const void *p)
{
	if (fe_ptr_set_has(s, p))
		return;
	if (s->n == s->cap) {
		size_t nc = s->cap ? 2 * s->cap : 8;
		const void **nv = sr_alloc(nc * sizeof *nv);
		if (s->n)
			memcpy(nv, s->v, s->n * sizeof *nv);
		s->v = nv;
		s->cap = nc;
	}
	s->v[s->n++] = p;
}

void fe_stmts_push(fe_stmts *s, fe_stmt st)
{
	if (s->n == s->cap) {
		size_t nc = s->cap ? 2 * s->cap : 4;
		fe_stmt *nv = sr_alloc(nc * sizeof *nv);
		if (s->n)
			memcpy(nv, s->v, s->n * sizeof *nv);
		s->v = nv;
		s->cap = nc;
	}
	s->v[s->n++] = st;
	s->nil = 0;
}

static fe_stmt stmt_new(const char *kind)
{
	fe_stmt s;
	memset(&s, 0, sizeof s);
	s.kind = S(kind);
	s.then.nil = s.else_.nil = 1;
	s.carried_nil = 1;
	return s;
}

fe_stmt fe_stmt_new(const char *kind) { return stmt_new(kind); }

fe_expr *fe_expr_new(const char *kind, fe_pos p)
{
	fe_expr *e = sr_alloc(sizeof *e);
	e->kind = S(kind);
	e->args_nil = 1;
	e->pos = p;
	return e;
}

void fe_expr_args(fe_expr *e, fe_expr **args, size_t n)
{
	e->args = sr_alloc(n * sizeof *args);
	memcpy(e->args, args, n * sizeof *args);
	e->n_args = n;
	e->args_nil = 0;
}

static int is_if_on(fe_prog_ctx *c, const sr_node *const *ns, size_t n, size_t i, sr_str name)
{
	return i + 1 < n && t_is(ns[i + 1], "IfNode") && fe_is_var_read(c, t_ref(c->a, ns[i + 1], "predicate"), name);
}

static void set_flag(fe_name_table *t, sr_str k, int v) { fe_name_set(t, k, v ? TRUE_ : NULL); }
static int flag(const fe_name_table *t, sr_str k) { return fe_name_get(t, k) != NULL; }
static void skip_if(fe_prog_ctx *c, const sr_node *n)
{
	int created;
	*sr_imap_slot(&c->skip_ifs, n->id, &created) = TRUE_;
}

fe_stmts fe_ctx_stmts(fe_prog_ctx *c, const sr_node *const *ns, size_t nn, sr_str ref_var)
{
	fe_stmts out = {0};
	out.nil = 1;
	const sr_ast *a = c->a;
	for (size_t i = 0; i < nn; i++) {
		const sr_node *n = ns[i];
		sr_str nm = t_str(n, "name");
		if (t_is(n, "CallNode")) {
			fe_func_info *fi = fe_user_call(c->z, a, n);
			if (fi) {
				fe_expr *e = fe_sub_call(c, n, fi, ref_var);
				if (e) {
					fe_stmt s = stmt_new("drop");
					s.val = e;
					s.pos = fe_cpos(c, n);
					stmts_push(&out, s);
				}
				continue;
			}
			if (fe_is_iter_call(c, n)) {
				fe_stmt s;
				if (fe_loop_stmt(c, n, &s))
					stmts_push(&out, s);
				continue;
			}
			if (fe_output_of_bad_ring(c, n))
				continue;
			if (fe_is_output(c, n)) {
				fe_cadd(c, FE_REJECTED, FE_SB025, n, "%s", fe_dropped_msg(fe_ring_of(c, t_ref(a, n, "receiver"))));
				continue;
			}
			if (fe_is_output_str(c, n)) {
				sr_str shape = fe_output_str_shape(fe_ring_of(c, t_ref(a, n, "receiver")));
				if (fe_streq(nm, "output_comm"))
					shape = fe_output_comm_shape(fe_ring_of(c, t_ref(a, n, "receiver")));
				fe_cadd(c, FE_REJECTED, FE_SB025, n, "the result of %s (nil when the ring is full) is dropped — use %s", nm, shape);
				continue;
			}
			if (fe_is_adjust_pkt(c, n)) {
				fe_cadd(c, FE_REJECTED, FE_SB026, n,
					"the status of `%s.%s(d)` (0 or −errno) is dropped — use `st = %s.%s(d)` (read later) or `_ = %s.%s(d)`", c->param,
					nm, c->param, nm, c->param, nm);
				continue;
			}
			{
				int bad, ok;
				fe_map_decl *m = fe_status_call(c, n, &bad, &ok);
				if (ok) {
					if (!bad && !fe_reads_bad(c, n))
						fe_cadd(c, FE_REJECTED, FE_SB026, n, "%s", fe_status_ignored(m, nm));
					continue;
				}
			}
			{
				fe_stmt s;
				int ok;
				if (fe_ref_atomic(c, n, ref_var, &s, &ok)) {
					if (ok)
						stmts_push(&out, s);
					continue;
				}
				if (fe_record_call(c, n, ref_var, &s, &ok)) {
					if (ok)
						stmts_push(&out, s);
					continue;
				}
				if (fe_map_call(c, n, ref_var, &s))
					stmts_push(&out, s);
			}
		} else if (t_is(n, "CallOperatorWriteNode") || t_is(n, "CallOrWriteNode") || t_is(n, "CallAndWriteNode")) {
			fe_stmt s;
			int ok;
			if (fe_per_cpu_add(c, n, ref_var, &s, &ok)) {
				if (ok)
					stmts_push(&out, s);
				continue;
			}
			fe_cadd(c, FE_REJECTED, FE_SB019, n,
				"`.%s %s= …` on a record member reads and writes the map value — concurrent CPUs lose updates; use `p.atomic_add(:%s, d)`", nm,
				t_str(n, "binary_operator"), nm);
		} else if (t_is(n, "LocalVariableWriteNode")) {
			const sr_node *v = t_ref(a, n, "value");
			if (fe_is_sk_assign(c, v)) {
				fe_stmt s;
				if (fe_sk_assign_stmt(c, n, &s))
					stmts_push(&out, s);
				else
					set_flag(&c->poisoned, nm, 1);
				continue;
			}
			if (fe_output_of_bad_ring(c, v))
				continue;
			if (fe_kcheck_call(c, v)) {
				if (!is_if_on(c, ns, nn, i, nm)) {
					fe_cadd(c, FE_REJECTED, FE_SB005, n,
						"`%s = %s(…)` (a nullable kernel pointer) must be followed immediately by `if %s`", nm, t_str(v, "name"), nm);
					set_flag(&c->bad_bind, nm, 1);
					continue;
				}
				fe_stmt s;
				if (fe_kcheck_stmt(c, n, ns[i + 1], ref_var, &s)) {
					stmts_push(&out, s);
				} else {
					set_flag(&c->bad_bind, nm, 1);
					skip_if(c, ns[i + 1]);
				}
				i++;
				continue;
			}
			if (fe_kptr_call(c, v)) {
				fe_stmt s;
				if (fe_kptr_bind(c, n, fe_top_level(c, n), &s))
					stmts_push(&out, s);
				else
					set_flag(&c->bad_bind, nm, 1);
				continue;
			}
			if (fe_is_output_str(c, v)) {
				if (fe_streq(nm, "_")) {
					fe_stmt s;
					if (fe_output_str(c, v, (sr_str){0}, ref_var, &s))
						stmts_push(&out, s);
					continue;
				}
				if (!is_if_on(c, ns, nn, i, nm)) {
					fe_ring_decl *r = fe_ring_of(c, t_ref(a, v, "receiver"));
					if (!r) {
						t_nil_panic = 1; /* Go reads .Const of a nil ring */
						continue;
					}
					fe_cadd(c, FE_REJECTED, FE_SB025, n, "`%s = %s.output_str(…)` must be followed immediately by `if %s` — %s", nm,
						r->const_name, nm, fe_output_str_shape(r));
					set_flag(&c->bad_bind, nm, 1);
					continue;
				}
				int ok;
				fe_stmts ss = fe_output_str_check(c, n, ns[i + 1], ref_var, &ok);
				if (ok) {
					for (size_t k = 0; k < ss.n; k++)
						stmts_push(&out, ss.v[k]);
				} else {
					set_flag(&c->bad_bind, nm, 1);
					skip_if(c, ns[i + 1]);
				}
				i++;
				continue;
			}
			if (fe_is_output(c, v)) {
				fe_ring_decl *r = fe_ring_of(c, t_ref(a, v, "receiver"));
				if (!fe_streq(nm, "_")) {
					if (!r) {
						t_nil_panic = 1;
						continue;
					}
					fe_cadd(c, FE_REJECTED, FE_SB025, n,
						"`%s = %s.output(…)` — the result is accepted only as an `if` / `unless` condition or `_ = …` (a bool local can carry it to a path that drops it)",
						nm, r->const_name);
					set_flag(&c->poisoned, nm, 1);
					continue;
				}
				fe_expr *e = fe_ring_output(c, v, ref_var);
				if (e) {
					fe_stmt s = stmt_new("ringout");
					s.ring = r;
					s.value = e->n_args ? e->args[0] : NULL;
					s.pos = fe_cpos(c, n);
					stmts_push(&out, s);
				}
				continue;
			}
			if (fe_is_adjust_pkt(c, v) && fe_streq(nm, "_")) {
				fe_expr *e = fe_ctx_expr(c, v, ref_var);
				if (e) {
					fe_stmt s = stmt_new("drop");
					s.val = e;
					s.pos = fe_cpos(c, n);
					stmts_push(&out, s);
				}
				continue;
			}
			{
				int bad, ok;
				fe_map_decl *m = fe_status_call(c, v, &bad, &ok);
				if (ok) {
					if (bad || fe_reads_bad(c, v)) {
						set_flag(&c->poisoned, nm, 1);
						continue;
					}
					if (fe_streq(nm, "_")) {
						fe_expr *e = fe_status_expr(c, v, m, ref_var);
						if (e) {
							fe_stmt s = stmt_new("drop");
							s.val = e;
							s.pos = fe_cpos(c, n);
							stmts_push(&out, s);
						}
						continue;
					}
					if (!fe_status_local_ok(c, n, m, t_str(v, "name"))) {
						set_flag(&c->poisoned, nm, 1);
						continue;
					}
				}
			}
			if (v && t_is(v, "CallNode") && fe_streq(t_str(v, "name"), "lookup")) {
				if (!is_if_on(c, ns, nn, i, nm)) {
					fe_cadd(c, FE_REJECTED, FE_SB005, n,
						"`%s = %s.lookup(…)` must be followed immediately by `if %s` (the present / absent check)", nm,
						t_const_name(a, t_ref(a, v, "receiver")), nm);
					set_flag(&c->bad_bind, nm, 1);
					continue;
				}
				fe_stmt s;
				if (fe_lookup_check(c, n, ns[i + 1], ref_var, &s)) {
					stmts_push(&out, s);
				} else {
					const sr_node *bound = fe_name_get(&c->refs, nm);
					set_flag(&c->bad_bind, nm, bound == NULL || bound != n);
					skip_if(c, ns[i + 1]);
				}
				i++;
				continue;
			}
			if (v && t_is(v, "CallNode") && fe_streq(t_str(v, "name"), "check") && fe_is_var_read(c, t_ref(a, v, "receiver"), c->param) &&
			    fe_has_packet(fe_ctx_kind_of(c))) {
				if (!is_if_on(c, ns, nn, i, nm)) {
					fe_cadd(c, FE_REJECTED, FE_SB005, n,
						"`%s = %s.check(off, len)` must be followed immediately by `if %s` (the in-range / out-of-range check)", nm,
						c->param, nm);
					set_flag(&c->bad_bind, nm, 1);
					continue;
				}
				fe_stmt s;
				if (fe_window_check(c, n, ns[i + 1], ref_var, &s)) {
					stmts_push(&out, s);
				} else {
					if (!fe_name_get(&c->wins, nm))
						set_flag(&c->bad_bind, nm, 1);
					skip_if(c, ns[i + 1]);
				}
				i++;
				continue;
			}
			fe_stmt s;
			if (fe_assign(c, n, nm, v, ref_var, &s))
				stmts_push(&out, s);
		} else if (t_is(n, "MultiWriteNode")) {
			fe_stmt s;
			if (fe_kread_stmt(c, n, &s))
				stmts_push(&out, s);
		} else if (t_is(n, "LocalVariableOperatorWriteNode")) {
			fe_stmt s;
			if (fe_op_assign(c, n, ref_var, &s))
				stmts_push(&out, s);
		} else if (t_is(n, "IfNode") || t_is(n, "UnlessNode")) {
			fe_stmt s;
			if (fe_if_stmt(c, n, ref_var, &s))
				stmts_push(&out, s);
		} else if (t_is(n, "ReturnNode")) {
			continue;
		} else if (t_is(n, "LocalVariableReadNode")) {
			if (sr_eq(nm, c->param))
				fe_cadd(c, FE_REJECTED, FE_SB001, n, "the context `%s` is used only as `w = %s.check(off, len)` right before `if w`", c->param,
					c->param);
			else
				fe_cadd(c, FE_REJECTED, FE_SB001, n, "a bare expression statement is not accepted");
		} else if (t_is(n, "BreakNode") || t_is(n, "NextNode")) {
			fe_stmt s;
			if (fe_escape(c, n, i == nn - 1, &s))
				stmts_push(&out, s);
		} else if (t_is(n, "WhileNode") || t_is(n, "UntilNode") || t_is(n, "ForNode") || t_is(n, "RedoNode")) {
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "%s has no static bound — write %S with a bound ≤ %d", n->type, fe_loop_forms,
				(int64_t)FE_MAX_LOOP_COUNT);
		} else {
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "%s is not accepted on the eBPF side", n->type);
		}
	}
	return out;
}

/* ---- assignments (program.go progCtx.assign, progCtx.opAssign, progCtx.wideRebindOK, progCtx.mixedReadOK, progCtx.valueOK) ---- */

/* wideRebindOK */
int fe_wide_rebind_ok(fe_prog_ctx *c, sr_str name, const sr_node *n)
{
	const fe_var_info *info = fe_name_get(&c->env, name);
	if (info && info->wide) {
		fe_cadd(c, FE_REJECTED, FE_SB014, n,
			"`%s` holds a u64 ctx.read value and is bound once — narrow it into a new name (`y = %s & M` or `y = %s >> K`)", name, name,
			name);
		return 0;
	}
	return 1;
}

/* mixedReadOK */
int fe_mixed_read_ok(fe_prog_ctx *c, sr_str name, const sr_node *n)
{
	const fe_var_info *info = fe_name_get(&c->env, name);
	if (info && info->mixed) {
		fe_cadd(c, FE_REJECTED, FE_SB014, n,
			"`%s` is a u64 ctx.read value on one path and an Integer on another — bind the narrowed value to a new name on every path", name);
		return 0;
	}
	return 1;
}

/* valueOK */
int fe_value_ok(fe_prog_ctx *c, fe_expr *e, const sr_node *n)
{
	if (e->wide && fe_streq(e->kind, "var")) {
		fe_cadd(c, FE_REJECTED, FE_SB014, n,
			"a u64 ctx.read value %I does not fit Ruby's Integer — narrow it first (`x & M` or `x >> K`), or pass it straight to a u64 map or record member",
			e->iv);
		return 0;
	}
	if (e->wide) {
		fe_cadd(c, FE_REJECTED, FE_SB014, n,
			"a u64 value %I (a u64 map value or BPF.ktime_ns) does not fit Ruby's Integer — narrow it first (`x & M` or `x >> K`), or pass it straight to a u64 map or record member",
			e->iv);
		return 0;
	}
	return 1;
}

static fe_var_info *var_new(int is_bool, fe_ival iv, fe_name_table from)
{
	fe_var_info *v = sr_alloc(sizeof *v);
	v->bool_ = is_bool;
	v->iv = iv;
	v->from = from;
	return v;
}

/* assign (program.go) */
int fe_assign(fe_prog_ctx *c, const sr_node *n, sr_str name, const sr_node *v, sr_str ref_var, fe_stmt *out)
{
	if (flag(&c->bad_bind, name) || fe_reads_bad(c, v)) {
		set_flag(&c->poisoned, name, 1);
		return 0;
	}
	if (sr_eq(name, c->param) || fe_name_get(&c->refs, name) || fe_name_get(&c->wins, name)) {
		fe_cadd(c, FE_REJECTED, FE_SB005, n, "`%s` cannot be reassigned (the context / a lookup result / a window is bound once)", name);
		return 0;
	}
	if (t_reserved_prefix(name)) {
		fe_cadd(c, FE_REJECTED, FE_SB007, n, "`%s` uses the reserved prefix spinelbpf_", name);
		return 0;
	}
	if (!fe_wide_rebind_ok(c, name, n)) {
		set_flag(&c->poisoned, name, 1);
		return 0;
	}
	if (!v || !fe_typed(c, n))
		return 0;
	fe_expr *e = fe_ctx_expr(c, v, ref_var);
	if (!e) {
		set_flag(&c->poisoned, name, 1);
		return 0;
	}
	if (!fe_value_ok(c, e, v)) {
		set_flag(&c->poisoned, name, 1);
		return 0;
	}
	const char *want = e->bool_ ? "bool" : "Integer";
	sr_str got = fe_rbs(c, n);
	if (!fe_streq(got, want)) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "`%s` is typed %q by Spinel, not %S — a local must keep one type (Integer or bool)", name, got,
			want);
		return 0;
	}
	const fe_var_info *old = fe_name_get(&c->env, name);
	if (fe_name_has(&c->env, name) && old && old->bool_ != e->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "`%s` changes between Integer and bool", name);
		return 0;
	}
	fe_name_set(&c->env, name, var_new(e->bool_, e->iv, fe_origin(c, v)));
	fe_stmt s = stmt_new("assign");
	s.var = name;
	s.val = e;
	s.pos = fe_cpos(c, n);
	*out = s;
	return 1;
}

/* opAssign (program.go) */
int fe_op_assign(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out)
{
	sr_str name = t_str(n, "name"), op = t_str(n, "binary_operator");
	const fe_var_info *info = fe_name_get(&c->env, name);
	if (!info) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "`%s %s= …` needs `%s` defined before (Ruby reads nil)", name, op, name);
		return 0;
	}
	if (info->bool_ || !t_in(op, bin_ops)) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "`%s %s= …` is not accepted", name, op);
		return 0;
	}
	if (!fe_wide_rebind_ok(c, name, n) || !fe_mixed_read_ok(c, name, n))
		return 0;
	if (!fe_typed(c, n))
		return 0;
	const sr_node *vn = t_ref(c->a, n, "value");
	fe_expr *rhs = fe_ctx_expr(c, vn, ref_var);
	if (!rhs)
		return 0;
	fe_expr *lhs = fe_expr_new("var", fe_cpos(c, n));
	lhs->var = name;
	lhs->iv = info->iv;
	fe_expr *e = fe_binary(c, n, op, lhs, rhs, vn);
	if (!e)
		return 0;
	fe_name_table org = fe_origin(c, vn);
	fe_name_set(&c->env, name, var_new(0, e->iv, fe_union_refs(&info->from, &org)));
	fe_stmt s = stmt_new("assign");
	s.var = name;
	s.val = e;
	s.pos = fe_cpos(c, n);
	*out = s;
	return 1;
}

/* ---- if (program.go progCtx.ifStmt) ---- */
int fe_if_stmt(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out)
{
	const sr_ast *a = c->a;
	const sr_node *pred = t_ref(a, n, "predicate");
	if (fe_reads_bad(c, pred))
		return 0;
	if (pred && t_is(pred, "LocalVariableReadNode") && fe_name_get(&c->refs, t_str(pred, "name"))) {
		fe_cadd(c, FE_REJECTED, FE_SB005, n, "`if %s` is accepted only right after `%s = M.lookup(k)`", t_str(pred, "name"), t_str(pred, "name"));
		return 0;
	}
	if (pred && t_is(pred, "LocalVariableReadNode") && fe_name_get(&c->wins, t_str(pred, "name"))) {
		sr_str pn = t_str(pred, "name");
		fe_cadd(c, FE_REJECTED, FE_SB005, n,
			"`%S %s` is not accepted — a window is checked only as `if %s` right after `%s = %s.check(off, len)`",
			t_is(n, "IfNode") ? "if" : t_is(n, "UnlessNode") ? "unless" : "", pn, pn, pn, c->param);
		return 0;
	}
	const sr_node *w = fe_cond_assign(a, pred);
	if (w) {
		fe_cadd(c, FE_REJECTED, FE_SB005, n, "an assignment inside the condition is not accepted — write `%s = …` on its own line, then `if %s`",
			t_str(w, "name"), t_str(w, "name"));
		return 0;
	}
	fe_expr *cond = fe_cond(c, pred, ref_var);
	if (!cond)
		return 0;
	if (t_is(n, "UnlessNode")) {
		fe_expr *nc = fe_expr_new("not", cond->pos);
		fe_expr_args(nc, &cond, 1);
		nc->bool_ = 1;
		cond = nc;
	}
	t_nodes then_n = {0};
	const sr_node *st = t_ref(a, n, "statements");
	if (st)
		then_n = t_arr(a, st, "body");
	const sr_node *else_node = t_is(n, "IfNode") ? t_ref(a, n, "subsequent") : t_ref(a, n, "else_clause");
	fe_name_table pre = c->env;
	c->env = fe_narrow_env(&pre, cond, 1);
	sr_str saved_arm = c->esc_arm;
	if (!fe_streq(c->esc_arm, "window"))
		c->esc_arm = S("if");
	fe_stmt s = stmt_new("if");
	s.cond = cond;
	s.pos = fe_cpos(c, n);
	s.then = fe_ctx_stmts(c, then_n.v, then_n.n, ref_var);
	fe_name_table then_env = c->env;
	c->env = fe_narrow_env(&pre, cond, 0);
	if (else_node) {
		if (t_is(else_node, "ElseNode")) {
			t_nodes else_n = {0};
			const sr_node *es = t_ref(a, else_node, "statements");
			if (es)
				else_n = t_arr(a, es, "body");
			s.else_ = fe_ctx_stmts(c, else_n.v, else_n.n, ref_var);
		} else if (t_is(else_node, "IfNode")) {
			fe_stmt es;
			if (fe_if_stmt(c, else_node, ref_var, &es)) {
				fe_stmts one = {0};
				fe_stmts_push(&one, es);
				s.else_ = one;
			}
		} else {
			fe_cadd(c, FE_REJECTED, FE_SB001, else_node, "%s after `if` is not accepted", else_node->type);
		}
	}
	c->env = fe_join_arms(&pre, &then_env, &c->env, fe_escapes(&s.then), fe_escapes(&s.else_));
	c->esc_arm = saved_arm; /* Go's deferred restore */
	*out = s;
	return 1;
}

/* cond (program.go) */
fe_expr *fe_cond(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	if (!n || !fe_typed(c, n))
		return NULL;
	sr_str got = fe_rbs(c, n);
	if (!fe_streq(got, "bool")) {
		fe_cadd(c, FE_REJECTED, FE_SB005, n,
			"the condition is typed %q — conditions must be bool (Ruby treats 0 as true and nil as false, BPF does not; compare explicitly, e.g. `x != 0`)",
			got);
		return NULL;
	}
	fe_expr *e = fe_ctx_expr(c, n, ref_var);
	if (!e)
		return NULL;
	if (!e->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB005, n, "the condition must be a bool expression");
		return NULL;
	}
	return e;
}

/* ---- expressions (program.go progCtx.expr) ---- */

typedef struct {
	int side_effect;
} and_walk;

static int and_walk_fn(void *u, const sr_node *x)
{
	and_walk *w = u;
	if (t_is(x, "CallNode") && t_in(t_str(x, "name"), map_ops))
		w->side_effect = 1;
	return 1;
}

static const intv *literal_lo(void)
{
	static intv v;
	static int init;
	if (!init) {
		v = fe_iv_add1(fe_i64_min, intv_from_i64(1));
		init = 1;
	}
	return &v;
}

fe_expr *fe_ctx_expr(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	if (!n || fe_calls_bad_func(c, n))
		return NULL;
	const sr_ast *a = c->a;
	fe_pos p = fe_cpos(c, n);
	if (t_is(n, "ParenthesesNode")) {
		const sr_node *b = t_ref(a, n, "body");
		size_t cnt = 0;
		if (b)
			fe_node_arr(b, "body", &cnt, &(int){0});
		if (!b || !t_is(b, "StatementsNode") || cnt != 1) {
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "a parenthesised expression must hold one expression");
			return NULL;
		}
		t_nodes bs = t_arr(a, b, "body");
		if (bs.n == 0) {
			t_nil_panic = 1;
			return NULL;
		}
		return fe_ctx_expr(c, bs.v[0], ref_var);
	}
	if (t_is(n, "IntegerNode")) {
		if (!fe_typed(c, n))
			return NULL;
		bigint *v = sr_alloc(sizeof *v);
		if (!fe_literal(c->z->z, a, n, v))
			return NULL;
		int ok;
		intv iv = fe_intv_of_big(v, &ok);
		if (!ok) {
			fe_not_ported(c->z->z, "an integer literal beyond 128 bits");
			return NULL;
		}
		if (intv_cmp(iv, *literal_lo()) < 0) {
			fe_cadd(c, FE_REJECTED, FE_SB014, n,
				"integer literal %B is Spinel's nil marker (−2^63) — literals must be within [−2^63+1, 2^63−1]", (const bigint *)v);
			return NULL;
		}
		fe_expr *e = fe_expr_new("lit", p);
		e->lit = v;
		e->iv = fe_point(iv);
		return e;
	}
	if (t_is(n, "TrueNode") || t_is(n, "FalseNode")) {
		fe_expr *e = fe_expr_new("blit", p);
		e->b = t_is(n, "TrueNode");
		e->bool_ = 1;
		return e;
	}
	if (t_is(n, "NilNode")) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "nil is not a value on the eBPF side");
		return NULL;
	}
	if (t_is(n, "LocalVariableReadNode")) {
		sr_str name = t_str(n, "name");
		if (flag(&c->bad_bind, name) || (flag(&c->poisoned, name) && !fe_name_get(&c->env, name)))
			return NULL;
		if (sr_eq(name, c->param)) {
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "the context `%s` is used only as %s", c->param, fe_ctx_use(fe_ctx_kind_of(c), c->param));
			return NULL;
		}
		if (fe_name_get(&c->refs, name)) {
			fe_cadd(c, FE_REJECTED, FE_SB005, n, "`%s` may be read only as `if %s` and as `%s.load` inside it", name, name, name);
			return NULL;
		}
		if (fe_name_get(&c->kptrs, name)) {
			fe_kptr_misuse(c, n, name);
			return NULL;
		}
		if (flag(&c->kchecked, name)) {
			fe_cadd(c, FE_REJECTED, FE_SB005, n,
				"`%s` (a nullable kernel pointer) may be read only as `if %s` and as `%s.load.m` / `%s.ptr(…)` inside it", name, name, name,
				name);
			return NULL;
		}
		if (flag(&c->ostrs, name)) {
			fe_cadd(c, FE_REJECTED, FE_SB005, n, "`%s` (an output_str result) may be read only as `if %s` and as `%s.status` inside it", name,
				name, name);
			return NULL;
		}
		if (fe_name_get(&c->wins, name)) {
			fe_cadd(c, FE_REJECTED, FE_SB005, n,
				"window `%s` may be read only as `if %s` and as `%s.u8(i)` / `be16` / `be32` / `le16` / `le32` inside it", name, name, name);
			return NULL;
		}
		const fe_var_info *info = fe_name_get(&c->env, name);
		if (!info) {
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "`%s` is not defined on every path here (Ruby would read nil)", name);
			return NULL;
		}
		if (!fe_typed(c, n))
			return NULL;
		if (!fe_mixed_read_ok(c, name, n))
			return NULL;
		fe_expr *e = fe_expr_new("var", p);
		e->var = name;
		e->bool_ = info->bool_;
		e->iv = info->iv;
		e->wide = info->wide;
		return e;
	}
	if (t_is(n, "AndNode") || t_is(n, "OrNode")) {
		const sr_node *l = t_ref(a, n, "left"), *r = t_ref(a, n, "right");
		and_walk w = {0};
		if (r)
			t_walk(a, r, and_walk_fn, &w);
		if (w.side_effect) {
			fe_cadd(c, FE_REJECTED, FE_SB018, n,
				"the right operand of `%S` calls a map operation — Ruby may skip it (short-circuit); move it into its own statement",
				t_is(n, "AndNode") ? "&&" : "||");
			return NULL;
		}
		fe_expr *le = fe_cond(c, l, ref_var);
		fe_expr *re = fe_cond(c, r, ref_var);
		if (!le || !re)
			return NULL;
		fe_expr *e = fe_expr_new(t_is(n, "OrNode") ? "or" : "and", p);
		fe_expr *as[2] = {le, re};
		fe_expr_args(e, as, 2);
		e->bool_ = 1;
		return e;
	}
	if (t_is(n, "IfNode")) {
		fe_expr *cond = fe_cond(c, t_ref(a, n, "predicate"), ref_var);
		const sr_node *st = t_ref(a, n, "statements"), *sub = t_ref(a, n, "subsequent");
		if (!cond)
			return NULL;
		size_t n_st = 0, n_sub = 0;
		const sr_node *sub_st = sub ? t_ref(a, sub, "statements") : NULL;
		if (st)
			fe_node_arr(st, "body", &n_st, &(int){0});
		if (sub_st)
			fe_node_arr(sub_st, "body", &n_sub, &(int){0});
		if (!st || n_st != 1 || !sub || !t_is(sub, "ElseNode") || !sub_st || n_sub != 1) {
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "an `if` used as a value must be `c ? a : b` with one expression in each arm");
			return NULL;
		}
		t_nodes sa = t_arr(a, st, "body"), sb = t_arr(a, sub_st, "body");
		if (sa.n == 0 || sb.n == 0) {
			t_nil_panic = 1;
			return NULL;
		}
		fe_expr *ea = fe_ctx_expr(c, sa.v[0], ref_var);
		fe_expr *eb = fe_ctx_expr(c, sb.v[0], ref_var);
		if (!ea || !eb)
			return NULL;
		if (ea->bool_ != eb->bool_ || ea->wide || eb->wide) {
			fe_cadd(c, FE_REJECTED, FE_SB001, n, "both arms of `c ? a : b` must be the same type (Integer or bool)");
			return NULL;
		}
		fe_expr *e = fe_expr_new("sel", p);
		fe_expr *as[3] = {cond, ea, eb};
		fe_expr_args(e, as, 3);
		e->bool_ = ea->bool_;
		if (!ea->bool_)
			e->iv = fe_union(ea->iv, eb->iv);
		return e;
	}
	if (t_is(n, "CallNode"))
		return fe_call_expr(c, n, ref_var);
	if (t_is(n, "ConstantPathNode")) {
		int64_t v;
		if (errno_const(t_const_name(a, n), &v)) {
			fe_expr *e = fe_expr_new("lit", p);
			e->lit = fe_big_of_intv(intv_from_i64(v));
			e->iv = fe_point(intv_from_i64(v));
			return e;
		}
	}
	fe_cadd(c, FE_REJECTED, FE_SB001, n, "%s is not accepted in an expression on the eBPF side", n->type);
	return NULL;
}

/* callExpr (program.go) */
fe_expr *fe_call_expr(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	const sr_ast *a = c->a;
	sr_str name = t_str(n, "name");
	fe_pos p = fe_cpos(c, n);
	const sr_node *recv = t_ref(a, n, "receiver");
	t_nodes as = t_args(a, n);
	if (fe_is_iter_call(c, n)) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n,
			"the value of `%s` (its receiver, or a break value) is not used on the eBPF side — write the loop as a statement and keep results in locals",
			name);
		return NULL;
	}
	if (!recv && as.n == 0 && !t_ref(a, n, "block") && flag(&c->block_locals, name)) {
		fe_cadd(c, FE_REJECTED, FE_SB030, n,
			"`%s` was first assigned inside a loop block — Ruby does not keep it after the loop (it reads a method call); assign it before the loop",
			name);
		return NULL;
	}
	if (recv && t_is(recv, "ConstantReadNode")) {
		fe_global_decl *g = fe_name_get(&c->z->top->globals, t_str(recv, "name"));
		if (g)
			return fe_global_read(c, n, g, name, as.v, as.n, p);
		if (fe_name_get(&c->z->top->bad_globals, t_str(recv, "name")))
			return NULL;
	}
	{
		int bad, ok;
		fe_map_decl *m = fe_status_call(c, n, &bad, &ok);
		if (ok) {
			if (bad)
				return NULL;
			if (!fe_status_parent_ok(c, n)) {
				fe_cadd(c, FE_REJECTED, FE_SB026, n,
					"the status of `%s.%s` is accepted only as `st = %s.%s(…)` (read later), as an operand of a comparison, or as `_ = %s.%s(…)` — not as an argument, an arithmetic operand or another value",
					m->const_name, name, m->const_name, name, m->const_name, name);
				return NULL;
			}
			return fe_status_expr(c, n, m, ref_var);
		}
	}
	if (t_in(name, map_ops)) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "`%s` is a statement, not a value (its result is not used on the eBPF side)", name);
		return NULL;
	}
	fe_map_decl *rm = ref_var.n ? fe_name_get(&c->ref_map, ref_var) : NULL;
	if (fe_streq(name, "[]") && recv && t_is(recv, "CallNode") && ref_var.n) {
		const sr_node *ld = t_ref(a, recv, "receiver");
		if (ld && t_is(ld, "CallNode") && fe_streq(t_str(ld, "name"), "load") && fe_is_var_read(c, t_ref(a, ld, "receiver"), ref_var)) {
			if (!rm) {
				t_nil_panic = 1;
				return NULL;
			}
			if (rm->record)
				return fe_elem_read(c, n, recv, ld, ref_var);
		}
	}
	if (recv && t_is(recv, "CallNode") && fe_streq(t_str(recv, "name"), "load") && ref_var.n &&
	    fe_is_var_read(c, t_ref(a, recv, "receiver"), ref_var)) {
		if (!rm) {
			t_nil_panic = 1;
			return NULL;
		}
		if (rm->record)
			return fe_field_read(c, n, recv, ref_var);
	}
	if (fe_streq(name, "load") && ref_var.n && fe_is_var_read(c, recv, ref_var)) {
		if (!rm) {
			t_nil_panic = 1;
			return NULL;
		}
		if (rm->record) {
			fe_cadd(c, FE_REJECTED, FE_SB005, n, "`%s.load` of a record is not a value — read a member (`%s.load.<member>`)", ref_var, ref_var);
			return NULL;
		}
	}
	if (fe_streq(name, "load") && fe_is_kptr_read(c, recv)) {
		fe_kptr_misuse(c, n, t_str(recv, "name"));
		return NULL;
	}
	if (fe_streq(name, "load")) {
		if (!fe_is_var_read(c, recv, ref_var) || ref_var.n == 0 || as.n != 0) {
			fe_cadd(c, FE_REJECTED, FE_SB005, n, "`p.load` is accepted only inside `if p` right after `p = M.lookup(k)`");
			return NULL;
		}
		int ok;
		sr_str callee = fe_callee(c, n, &ok);
		if (!ok)
			return NULL;
		if (!fe_streq(callee, "MapRef#load")) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n, "`load` resolves to %s, not BPF::MapRef#load", callee);
			return NULL;
		}
		fe_map_decl *m = rm;
		if (!m) {
			t_nil_panic = 1;
			return NULL;
		}
		fe_expr *e = fe_expr_new("load", p);
		e->ref = ref_var;
		e->map = m;
		if (m->value_bits == 32 && !m->is_signed)
			e->iv = fe_iv(intv_from_i64(0), fe_u32_max);
		else if (m->value_bits == 32)
			e->iv = fe_iv(fe_i32_min, fe_i32_max);
		else if (m->is_signed)
			e->iv = fe_full_i64;
		else {
			e->iv = fe_iv(intv_from_i64(0), fe_u64_max);
			e->wide = 1;
		}
		return e;
	}
	if (!fe_has_packet(c->prog->kind) && recv && fe_is_var_read(c, recv, c->param))
		return fe_tracing_read(c, n, name, as.v, as.n, p);
	if (fe_streq(c->prog->kind, "flow_dissector") && (fe_streq(name, "key") || fe_streq(name, "set_key")) && recv &&
	    fe_is_var_read(c, recv, c->param)) {
		if (fe_streq(name, "set_key")) {
			fe_cadd(c, FE_REJECTED, FE_SB002, n, "`%s.set_key(…)` is a statement — not a value", c->param);
			return NULL;
		}
		return fe_flow_key_read(c, n, ref_var);
	}
	if (fe_streq(c->prog->kind, "xdp") && (fe_streq(name, "adjust_head") || fe_streq(name, "adjust_tail")) && recv &&
	    fe_is_var_read(c, recv, c->param))
		return fe_adjust_pkt(c, n, ref_var);
	if (fe_ctx_field(c->prog->kind, name) && recv && fe_is_var_read(c, recv, c->param))
		return fe_tracing_read(c, n, name, as.v, as.n, p);
	if (fe_window_read_len(name, NULL))
		return fe_window_read(c, n, recv, as.v, as.n);
	if (fe_output_of_bad_ring(c, n))
		return NULL;
	if (fe_is_output(c, n)) {
		if (!fe_output_is_condition(c, n)) {
			fe_cadd(c, FE_REJECTED, FE_SB025, n, "%s — not as an operand, argument or value", fe_dropped_msg(fe_ring_of(c, recv)));
			return NULL;
		}
		return fe_ring_output(c, n, ref_var);
	}
	if (fe_is_output_str(c, n)) {
		fe_cadd(c, FE_REJECTED, FE_SB025, n, "the result of output_str is accepted only as %s", fe_output_str_shape(fe_ring_of(c, recv)));
		return NULL;
	}
	if ((fe_streq(name, "status") || fe_streq(name, "sent")) && recv && t_is(recv, "LocalVariableReadNode") &&
	    flag(&c->ostrs, t_str(recv, "name")))
		return fe_ostr_status(c, n, recv, p);
	{
		sr_str q = fe_kchecked_root(c, n);
		if (q.n) {
			fe_cadd(c, FE_REJECTED, FE_SB005, n,
				"`%s` (a nullable kernel pointer) may be read only as `if %s` and as `%s.load.m` / `%s.ptr(…)` inside it", q, q, q, q);
			return NULL;
		}
	}
	{
		int ok;
		fe_expr *e = fe_kpath_read(c, n, p, &ok);
		if (ok)
			return e;
	}
	if (recv && t_is(recv, "CallNode") && fe_streq(t_str(recv, "name"), "load") && fe_is_kptr_read(c, t_ref(a, recv, "receiver")))
		return fe_kfield_read(c, n, recv, p);
	if (fe_streq(name, "addr") && recv && fe_is_kptr_read(c, recv))
		return fe_kaddr_read(c, n, recv, p);
	if (recv && fe_is_kptr_read(c, recv)) {
		fe_kptr_misuse(c, n, t_str(recv, "name"));
		return NULL;
	}
	if ((fe_streq(name, "pid_tgid") || fe_streq(name, "ktime_ns")) && fe_streq(t_const_name(a, recv), "BPF")) {
		int is_pid = fe_streq(name, "pid_tgid");
		int ok;
		sr_str callee = fe_callee(c, n, &ok);
		if (!ok)
			return NULL;
		if (!fe_streq(callee, is_pid ? "BPF.pid_tgid" : "BPF.ktime_ns") || as.n != 0) {
			fe_cadd(c, FE_REJECTED, FE_SB011, n,
				is_pid ? "`BPF.pid_tgid` resolves to %q (with %d arguments), not the library's BPF.pid_tgid"
				       : "`BPF.ktime_ns` resolves to %q (with %d arguments), not the library's BPF.ktime_ns",
				callee, (int64_t)as.n);
			return NULL;
		}
		fe_expr *e = fe_expr_new(is_pid ? "pidtgid" : "ktime", p);
		e->iv = fe_iv(intv_from_i64(0), fe_u64_max);
		e->wide = 1;
		return e;
	}
	if (fe_streq(name, "**")) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "`**` is outside the eBPF side");
		return NULL;
	}
	int is_op = t_in(name, bin_ops) || t_in(name, cmp_ops) || fe_streq(name, "-@") || fe_streq(name, "~") || fe_streq(name, "!");
	if (!is_op && fe_streq(name, "new") && fe_name_get(&c->z->top->records, t_const_name(a, recv))) {
		fe_cadd(c, FE_REJECTED, FE_SB024, n,
			"a record value `%s.new(…)` is written directly as the argument of the map / ring buffer call that takes it (key, value or event) — it is not kept in a local or used as another value (bpf-mlir: a record.make result does not cross blocks)",
			t_const_name(a, recv));
		return NULL;
	}
	fe_func_info *fi = fe_user_call(c->z, a, n);
	if (fi && !is_op)
		return fe_sub_call(c, n, fi, ref_var);
	if (!is_op) {
		fe_cadd(c, FE_REJECTED, FE_SB002, n, "call `%s` is not accepted on the eBPF side", name);
		return NULL;
	}
	{
		int ok;
		fe_callee_op(c, n, fe_member_read(c, recv), &ok);
		if (!ok)
			return NULL;
	}
	if (fe_streq(name, "!")) {
		fe_expr *x = fe_cond(c, recv, ref_var);
		if (!x)
			return NULL;
		fe_expr *e = fe_expr_new("not", p);
		fe_expr_args(e, &x, 1);
		e->bool_ = 1;
		return e;
	}
	if (fe_streq(name, "-@") || fe_streq(name, "~")) {
		fe_expr *x = fe_int_expr(c, recv, ref_var);
		if (!x)
			return NULL;
		fe_expr *e = fe_expr_new("un", p);
		e->op = name;
		fe_expr_args(e, &x, 1);
		e->iv = fe_streq(name, "-@") ? fe_iv_neg(x->iv) : fe_iv_not(x->iv);
		if (!fe_fits(c, n, e))
			return NULL;
		return e;
	}
	if (as.n != 1) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "operator `%s` takes one operand", name);
		return NULL;
	}
	if (t_in(name, cmp_ops)) {
		fe_expr *l = fe_int_expr(c, recv, ref_var);
		fe_expr *r = fe_int_expr(c, as.v[0], ref_var);
		if (!l || !r)
			return NULL;
		fe_expr *e = fe_expr_new("cmp", p);
		e->op = name;
		fe_expr *ab[2] = {l, r};
		fe_expr_args(e, ab, 2);
		e->bool_ = 1;
		return e;
	}
	fe_expr *l = fe_ctx_expr(c, recv, ref_var);
	fe_expr *r = fe_ctx_expr(c, as.v[0], ref_var);
	if (!l || !r)
		return NULL;
	return fe_binary(c, n, name, l, r, as.v[0]);
}

/* intExpr (program.go) */
fe_expr *fe_int_expr(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	fe_expr *e = fe_ctx_expr(c, n, ref_var);
	if (!e)
		return NULL;
	if (e->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "an Integer is needed here, got a bool");
		return NULL;
	}
	if (e->wide) {
		fe_value_ok(c, e, n);
		return NULL;
	}
	return e;
}

/* fits (program.go) */
int fe_fits(fe_prog_ctx *c, const sr_node *n, fe_expr *e)
{
	if (!fe_iv_fits_i64(e->iv)) {
		fe_cadd(c, FE_REJECTED, FE_SB014, n,
			"`%s` may overflow: its value range %I does not fit a 64-bit Integer (Ruby grows / Spinel raises RangeError, BPF wraps) — narrow the operands (e.g. `x & 0xFFFF_FFFF`)",
			e->op, e->iv);
		return 0;
	}
	return 1;
}

/* binary (program.go) */
static int const_right(fe_prog_ctx *c, const sr_node *rn, sr_str op, const fe_expr *r, const char *what, intv *v)
{
	if (!fe_iv_is_point(r->iv, v) || !fe_streq(r->kind, "lit")) {
		fe_cadd(c, FE_REJECTED, FE_SB006, rn, "the %S of `%s` must be an integer literal", what, op);
		return 0;
	}
	return 1;
}

static int wide_value_ok(fe_prog_ctx *c, const sr_node *n, fe_expr *l, fe_expr *r)
{
	if (l->wide)
		fe_value_ok(c, l, n);
	else
		fe_value_ok(c, r, n);
	return 0;
}

fe_expr *fe_binary(fe_prog_ctx *c, const sr_node *n, sr_str op, fe_expr *l, fe_expr *r, const sr_node *rn)
{
	fe_pos p = fe_cpos(c, n);
	if (l->bool_ || r->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "operator `%s` needs Integer operands", op);
		return NULL;
	}
	fe_expr *e = fe_expr_new("bin", p);
	e->op = op;
	fe_expr *ab[2] = {l, r};
	fe_expr_args(e, ab, 2);
	intv zero = intv_from_i64(0), one = intv_from_i64(1);
	if (fe_streq(op, "&")) {
		if (l->wide) {
			intv m;
			if (!const_right(c, rn, op, r, "mask", &m))
				return NULL;
			if (intv_sign(m) < 0) {
				if (fe_streq(l->kind, "var")) {
					fe_cadd(c, FE_REJECTED, FE_SB014, rn, "a u64 ctx.read value may be masked only with a non-negative literal");
					return NULL;
				}
				fe_cadd(c, FE_REJECTED, FE_SB014, rn, "a u64 map value may be masked only with a non-negative literal");
				return NULL;
			}
			e->iv = fe_iv(zero, m);
			return e;
		}
		if (r->wide) {
			if (fe_streq(r->kind, "var")) {
				fe_cadd(c, FE_REJECTED, FE_SB014, n, "write the u64 ctx.read value on the left of `&` with a literal mask (`r & M`)");
				return NULL;
			}
			fe_cadd(c, FE_REJECTED, FE_SB014, n, "write the u64 map value on the left of `&` with a literal mask (`p.load & M`)");
			return NULL;
		}
		e->iv = fe_iv_bit("&", l->iv, r->iv);
	} else if (fe_streq(op, "|") || fe_streq(op, "^")) {
		if (l->wide || r->wide)
			return wide_value_ok(c, n, l, r), NULL;
		e->iv = fe_iv_bit(fe_streq(op, "|") ? "|" : "^", l->iv, r->iv);
	} else if (fe_streq(op, "<<") || fe_streq(op, ">>")) {
		if (r->wide) {
			fe_value_ok(c, r, n);
			return NULL;
		}
		intv k;
		if (!const_right(c, rn, op, r, "shift count", &k))
			return NULL;
		if (intv_sign(k) < 0 || intv_cmp(k, intv_from_i64(63)) > 0) {
			char kb[48];
			fe_cadd(c, FE_REJECTED, FE_SB014, rn, "shift count %S is outside [0, 63] (Ruby shifts the other way / to 0 or −1, BPF is poison)",
				intv_string(k, kb));
			return NULL;
		}
		uint64_t sh = (uint64_t)intv_int64(k);
		intv f;
		if (intv_lsh(one, sh, &f) != INTV_OK) {
			fe_iv_overflow = 1;
			return NULL;
		}
		if (l->wide) {
			if (!fe_streq(op, ">>") || sh == 0) {
				fe_value_ok(c, l, n);
				return NULL;
			}
			e->iv = fe_iv(zero, intv_rsh(fe_u64_max, sh));
			return e;
		}
		if (fe_streq(op, "<<"))
			e->iv = fe_iv(fe_iv_mul1(l->iv.lo, f), fe_iv_mul1(l->iv.hi, f));
		else
			e->iv = fe_iv(fe_floor_div(l->iv.lo, f), fe_floor_div(l->iv.hi, f));
	} else if (fe_streq(op, "/") || fe_streq(op, "%")) {
		if (l->wide || r->wide)
			return wide_value_ok(c, n, l, r), NULL;
		intv d;
		if (!const_right(c, rn, op, r, "divisor", &d))
			return NULL;
		if (intv_sign(d) == 0) {
			fe_cadd(c, FE_REJECTED, FE_SB014, rn, "division by zero (Ruby raises ZeroDivisionError)");
			return NULL;
		}
		if (fe_iv_non_neg(l->iv) && intv_sign(d) > 0) {
			e->div = S("u");
			if (fe_streq(op, "/")) {
				e->iv = fe_iv(intv_quo(l->iv.lo, d), intv_quo(l->iv.hi, d));
			} else {
				intv hi = fe_iv_sub1(d, one);
				if (intv_cmp(l->iv.hi, hi) < 0)
					hi = l->iv.hi;
				e->iv = fe_iv(zero, hi);
			}
		} else if (fe_is_pow2_mag(d)) {
			e->div = S("floor");
			if (fe_streq(op, "/")) {
				intv a1 = fe_floor_div(l->iv.lo, d), a2 = fe_floor_div(l->iv.hi, d);
				e->iv = intv_cmp(a1, a2) <= 0 ? fe_iv(a1, a2) : fe_iv(a2, a1);
			} else if (intv_sign(d) > 0) {
				e->iv = fe_iv(zero, fe_iv_sub1(d, one));
			} else {
				e->iv = fe_iv(fe_iv_add1(d, one), zero);
			}
		} else {
			char db[48];
			fe_cadd(c, FE_REJECTED, FE_SB014, n,
				"`%s %S` with a possibly negative dividend %I needs a divisor of ±2^k (Ruby floors; bpf-mlir divides i64 signed only by ±2^k)", op,
				intv_string(d, db), l->iv);
			return NULL;
		}
	} else {
		if (l->wide || r->wide)
			return wide_value_ok(c, n, l, r), NULL;
		if (fe_streq(op, "+"))
			e->iv = fe_iv_add(l->iv, r->iv);
		else if (fe_streq(op, "-"))
			e->iv = fe_iv_sub(l->iv, r->iv);
		else if (fe_streq(op, "*"))
			e->iv = fe_iv_mul(l->iv, r->iv);
	}
	if (!fe_fits(c, n, e))
		return NULL;
	return e;
}

/* memberRead (program.go) */
int fe_member_read(fe_prog_ctx *c, const sr_node *n)
{
	const sr_ast *a = c->a;
	if (!n || !t_is(n, "CallNode") || t_args(a, n).n != 0 || t_ref(a, n, "block"))
		return 0;
	const sr_node *ld = t_ref(a, n, "receiver");
	if (!ld || !t_is(ld, "CallNode") || !fe_streq(t_str(ld, "name"), "load") || t_args(a, ld).n != 0 || t_ref(a, ld, "block"))
		return 0;
	const sr_node *p = t_ref(a, ld, "receiver");
	if (!p || !t_is(p, "LocalVariableReadNode") || !fe_name_get(&c->refs, t_str(p, "name")))
		return 0;
	fe_map_decl *m = fe_name_get(&c->ref_map, t_str(p, "name"));
	if (!m || !m->record)
		return 0;
	fe_record_field *f = fe_record_decl_field(m->record, t_str(n, "name"));
	return f && !f->pad;
}

typedef struct {
	fe_prog_ctx *c;
	int found;
} member_walk;

static int member_walk_fn(void *u, const sr_node *x)
{
	member_walk *w = u;
	if (!w->found && fe_member_read(w->c, x))
		w->found = 1;
	return !w->found;
}

/* hasMemberRead (program.go) */
int fe_has_member_read(fe_prog_ctx *c, const sr_node *n)
{
	member_walk w = {c, 0};
	if (n)
		t_walk(c->a, n, member_walk_fn, &w);
	return w.found;
}

static const sr_codegen_rec *codegen_of(fe_prog_ctx *c, const sr_node *n, size_t *cnt)
{
	long i = sr_codegen_of(c->t, c->a, n, cnt);
	if (i < 0)
		return NULL;
	*cnt = 1;
	return &c->t->codegen[i];
}

/* calleeOp (program.go) */
sr_str fe_callee_op(fe_prog_ctx *c, const sr_node *n, int member_recv, int *ok)
{
	*ok = 0;
	if (!member_recv)
		return fe_callee(c, n, ok);
	if (!fe_typed(c, n))
		return (sr_str){0};
	size_t cnt;
	const sr_codegen_rec *cg = codegen_of(c, n, &cnt);
	sr_str name = t_str(n, "name");
	if (cnt != 1) {
		fe_cadd(c, FE_UNKNOWN, FE_SB004, n,
			"Spinel placed no single call for `%s` (%d codegen records) — the target cannot be resolved statically", name, (int64_t)cnt);
		return (sr_str){0};
	}
	if (cg->callee.n) {
		fe_cadd(c, FE_REJECTED, FE_SB009, n, "operator `%s` resolves to the user definition %s — redefined operators are refused", name,
			cg->callee);
		return (sr_str){0};
	}
	if (!fe_streq(cg->dispatch, "direct") && !fe_streq(cg->dispatch, "boxed")) {
		fe_cadd(c, FE_UNKNOWN, FE_SB004, n, "`%s` is dispatched dynamically (%s %V) — the eBPF side needs a static call target", name,
			cg->dispatch, (const sr_str *)cg->candidates, cg->n_candidates);
		return (sr_str){0};
	}
	*ok = 1;
	return (sr_str){0};
}

/* callee (program.go) */
sr_str fe_callee(fe_prog_ctx *c, const sr_node *n, int *ok)
{
	*ok = 0;
	if (!fe_typed(c, n))
		return (sr_str){0};
	size_t cnt;
	const sr_codegen_rec *cg = codegen_of(c, n, &cnt);
	sr_str name = t_str(n, "name");
	if (cnt != 1) {
		fe_cadd(c, FE_UNKNOWN, FE_SB004, n,
			"Spinel placed no single call for `%s` (%d codegen records) — the target cannot be resolved statically", name, (int64_t)cnt);
		return (sr_str){0};
	}
	if (t_in(name, operators) && cg->callee.n) {
		fe_cadd(c, FE_REJECTED, FE_SB009, n, "operator `%s` resolves to the user definition %s — redefined operators are refused", name,
			cg->callee);
		return (sr_str){0};
	}
	if (!fe_streq(cg->dispatch, "direct")) {
		const char *hint = "";
		if (t_in(name, operators) && fe_has_member_read(c, t_ref(c->a, n, "receiver")))
			hint = "; for an operator on a record member's arithmetic, assign it to a local first (`x = p.load.m & 0xFF`, then `x + 1`)";
		fe_cadd(c, FE_UNKNOWN, FE_SB004, n, "`%s` is dispatched dynamically (%s %V) — the eBPF side needs a static call target%S", name,
			cg->dispatch, (const sr_str *)cg->candidates, cg->n_candidates, hint);
		return (sr_str){0};
	}
	*ok = 1;
	return cg->callee;
}

/* mapOf (program.go) */
fe_map_decl *fe_map_of(fe_prog_ctx *c, const sr_node *recv, const sr_node *call)
{
	if (recv && !fe_typed(c, recv))
		return NULL;
	sr_str cn = t_const_name(c->a, recv);
	fe_map_decl *m = fe_name_get(&c->z->top->maps, cn);
	if (!m && fe_name_get(&c->z->top->bad_maps, cn))
		return NULL;
	if (!m || !t_is(recv, "ConstantReadNode")) {
		fe_cadd(c, FE_REJECTED, FE_SB002, call,
			"`%s` needs a map declared at the top level (`X = BPF::ArrayMap.new(\"X\", …)`) as its receiver", t_str(call, "name"));
		return NULL;
	}
	sr_str want = fe_map_class_name(m);
	if (!sr_eq(fe_rbs(c, recv), want)) {
		fe_cadd(c, FE_REJECTED, FE_SB011, recv, "map %s is typed %q, not BPF::%s", cn, fe_rbs(c, recv), want);
		return NULL;
	}
	fe_ptr_set_add(&c->used, m);
	return m;
}

/* typeRange (program.go) */
fe_ival fe_type_range(const fe_map_decl *m)
{
	if (m->value_bits == 32 && !m->is_signed)
		return fe_iv(intv_from_i64(0), fe_u32_max);
	if (m->value_bits == 32)
		return fe_iv(fe_i32_min, fe_i32_max);
	if (m->is_signed)
		return fe_full_i64;
	return fe_iv(intv_from_i64(0), fe_i64_max);
}

/* key (program.go) */
fe_expr *fe_ctx_key(fe_prog_ctx *c, const sr_node *n, fe_map_decl *m, sr_str ref_var)
{
	if (fe_map_is_hash(m))
		return fe_hash_key(c, n, m, ref_var);
	fe_expr *e = fe_ctx_expr(c, n, ref_var);
	if (!e)
		return NULL;
	if (e->bool_ || e->wide) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "a map key must be an Integer (not a bool, not an unnarrowed u64 value)");
		return NULL;
	}
	intv max = intv_from_u64(m->max_entries - 1);
	if (!fe_iv_within(e->iv, intv_from_i64(0), max)) {
		if (fe_streq(e->kind, "lit") && e->lit) {
			int ok;
			intv lv = fe_intv_of_big(e->lit, &ok);
			if (intv_cmp(lv, fe_u32_max) > 0 || intv_sign(lv) < 0) {
				fe_cadd(c, FE_REJECTED, FE_SB014, n, "the key literal %B is outside [0, 4294967295] (u32 on the eBPF side; Ruby would not wrap it)",
					(const bigint *)e->lit);
				return NULL;
			}
		}
		fe_cadd(c, FE_REJECTED, FE_SB020, n,
			"the key's range %I is not within [0, %u] of map %s — an out-of-range array update fails silently; narrow it (e.g. `k %% %u`, `k & M`)",
			e->iv, m->max_entries - 1, m->name, m->max_entries);
		return NULL;
	}
	return e;
}

/* value (program.go) */
fe_expr *fe_ctx_value(fe_prog_ctx *c, const sr_node *n, fe_map_decl *m, sr_str ref_var, sr_str role)
{
	fe_expr *e = fe_ctx_expr(c, n, ref_var);
	if (!e)
		return NULL;
	if (e->bool_) {
		fe_cadd(c, FE_REJECTED, FE_SB001, n, "a bool cannot be stored in a map (%s)", role);
		return NULL;
	}
	if (e->wide) {
		static const char *const wide_kinds[] = {"load", "ktime", "pidtgid", "retval", "kparg", "rawarg", "tpfield", "gload", "kfload", NULL};
		if (m->value_bits == 64 && !m->is_signed && ((fe_streq(e->kind, "var") && e->wide) || t_in(e->kind, wide_kinds)))
			return e;
		fe_value_ok(c, e, n);
		return NULL;
	}
	fe_ival tr = fe_type_range(m);
	if (!fe_iv_within(e->iv, tr.lo, tr.hi)) {
		if (fe_streq(e->kind, "lit"))
			fe_cadd(c, FE_REJECTED, FE_SB014, n, "the %s literal %B is outside %I (%s on the eBPF side; Ruby would not wrap it)", role,
				(const bigint *)e->lit, tr, fe_map_type_name(m));
		else
			fe_cadd(c, FE_REJECTED, FE_SB014, n,
				"the %s's range %I does not fit map %s's %s values %I — the store would truncate silently; narrow it (e.g. `& 0xFFFF_FFFF`)",
				role, e->iv, m->name, fe_map_type_name(m), tr);
		return NULL;
	}
	return e;
}

/* rmwFirst (program.go) */
int fe_rmw_first(fe_prog_ctx *c, const sr_node *n, const sr_node *val, fe_map_decl *m, fe_expr *k, fe_msg_fn msg, void *u)
{
	fe_note_flow(c, val, m, n);
	if (!k || fe_exempt(c, m))
		return 0;
	fe_name_table refs = fe_derived_refs(c, val);
	size_t nk;
	sr_str *keys = fe_sorted_set(&refs, &nk);
	for (size_t i = 0; i < nk; i++) {
		sr_str ref = keys[i];
		if (fe_name_get(&c->ref_map, ref) != m)
			continue;
		fe_expr *lk = fe_name_get(&c->ref_key, ref);
		if (lk && fe_streq(lk->kind, "lit") && fe_streq(k->kind, "lit") && bigint_cmp(lk->lit, k->lit) != 0)
			continue;
		fe_cadd(c, FE_REJECTED, FE_SB019, n, "%s", msg(u, ref));
		return 1;
	}
	return 0;
}

/* derivedRefs (program.go) */
typedef struct {
	fe_prog_ctx *c;
	fe_name_table out;
} refs_walk;

static int refs_walk_fn(void *u, const sr_node *x)
{
	refs_walk *w = u;
	fe_prog_ctx *c = w->c;
	if (c->z->funcs.n && fe_user_call(c->z, c->a, x)) {
		sr_buf b = {0};
		sr_printf(&b, "@r%lld", (long long)x->id);
		fe_name_set(&w->out, sr_bufstr(&b), TRUE_);
		return 0;
	}
	fe_global_decl *g = fe_counter_read(c, x);
	if (g) {
		fe_name_set(&w->out, t_cat(S("@g"), g->const_name), TRUE_);
		return 0;
	}
	if (!t_is(x, "LocalVariableReadNode"))
		return 1;
	sr_str name = t_str(x, "name");
	if (fe_name_get(&c->refs, name)) {
		fe_name_set(&w->out, name, TRUE_);
	} else {
		const fe_var_info *info = fe_name_get(&c->env, name);
		if (info)
			for (size_t i = 0; i < info->from.n; i++)
				if (!info->from.e[i].removed && info->from.e[i].val)
					fe_name_set(&w->out, info->from.e[i].key, TRUE_);
	}
	return 1;
}

fe_name_table fe_derived_refs(fe_prog_ctx *c, const sr_node *n)
{
	refs_walk w = {c, {0}};
	if (n)
		t_walk(c->a, n, refs_walk_fn, &w);
	return w.out;
}

/* origin (program.go) */
fe_name_table fe_origin(fe_prog_ctx *c, const sr_node *n) { return fe_derived_refs(c, n); }

/* readsRefVia (program.go) */
int fe_reads_ref_via(fe_prog_ctx *c, const sr_node *n, sr_str ref)
{
	fe_name_table t = fe_derived_refs(c, n);
	return fe_name_get(&t, ref) != NULL;
}

/* sortedSet (program.go): the set's true keys, sorted */
sr_str *fe_sorted_set(const fe_name_table *t, size_t *n)
{
	sr_str *k = sr_alloc((t->n + 1) * sizeof *k);
	size_t m = 0;
	for (size_t i = 0; i < t->n; i++)
		if (!t->e[i].removed && t->e[i].val)
			k[m++] = t->e[i].key;
	for (size_t i = 1; i < m; i++)
		for (size_t j = i; j > 0; j--) {
			sr_str x = k[j], y = k[j - 1];
			size_t mn = x.n < y.n ? x.n : y.n;
			int cmp = mn ? memcmp(x.p, y.p, mn) : 0;
			if (cmp > 0 || (cmp == 0 && x.n >= y.n))
				break;
			k[j] = y;
			k[j - 1] = x;
		}
	*n = m;
	return k;
}

/* readsMap (program.go) */
sr_str fe_reads_map(const fe_expr *e, const fe_map_decl *m, int *ok)
{
	*ok = 0;
	if (!e)
		return (sr_str){0};
	if ((fe_streq(e->kind, "load") || fe_streq(e->kind, "fload")) && e->map == m) {
		*ok = 1;
		return e->ref;
	}
	for (size_t i = 0; i < e->n_args; i++) {
		sr_str r = fe_reads_map(e->args[i], m, ok);
		if (*ok)
			return r;
	}
	return (sr_str){0};
}
