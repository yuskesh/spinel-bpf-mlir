/* dump.c — the canonical dump of a Result and its DomainGraph: the C twin of internal/frontend/e178_dump_test.go (a registry
 * of declarations first; an anonymous one printed in full where reached). The bytes must equal the Go dumper's; the Go file
 * holds the format's description.
 * Field orders follow the Go structs (analyze.go Result, Program, Edge, MapDecl, KParam; program.go Expr, Stmt; record.go
 * RecordDecl, RecordField; ring.go RingDecl; globals.go GlobalDecl; kernel.go KernelTypeDecl, KernelField, TpArg; tracepoint.go
 * TpField; result.go Diag, Pos). A change to one of those structs must change this file and the Go dumper together. */
#include "body.h"
#include "dump.h"

#include <stdlib.h>
#include <string.h>

enum { K_MAP, K_RECORD, K_RING, K_GLOBAL, K_KTYPE, K_N };
static const char *const kind_name[K_N] = {"map", "record", "ring", "global", "ktype"};

typedef struct {
	int kind;
	sr_str name;
	const void *p;
} reg_entry;

typedef struct {
	const void *p;
	const char *ref;
} field_ref;

typedef struct {
	sr_buf *b;
	int collect;
	const void *self;
	reg_entry *reg;
	size_t n_reg, cap_reg;
	field_ref *fields;
	size_t n_fields, cap_fields;
	const char *err; /* the first failure; the dump is then refused */
} dumper;

/* ---- paths and lines ---- */

static const char *cat(const char *a, const char *b)
{
	size_t na = strlen(a), nb = strlen(b);
	char *s = sr_alloc(na + nb + 1);
	memcpy(s, a, na);
	memcpy(s + na, b, nb);
	return s;
}

static const char *idx(const char *path, size_t i)
{
	sr_buf b = {0};
	sr_printf(&b, "%s[%zu]", path, i);
	sr_putc(&b, 0);
	return b.p;
}

static const char *keyed(const char *path, sr_str k)
{
	sr_buf b = {0};
	sr_puts(&b, path);
	sr_putc(&b, '[');
	sr_quote_ascii(&b, k);
	sr_putc(&b, ']');
	sr_putc(&b, 0);
	return b.p;
}

static void line_start(dumper *d, const char *path)
{
	sr_puts(d->b, path);
	sr_puts(d->b, " = ");
}

static void line(dumper *d, const char *path, const char *v)
{
	if (d->collect)
		return;
	line_start(d, path);
	sr_puts(d->b, v);
	sr_putc(d->b, '\n');
}

static void l_str(dumper *d, const char *path, sr_str s)
{
	if (d->collect)
		return;
	line_start(d, path);
	sr_quote_ascii(d->b, s);
	sr_putc(d->b, '\n');
}

static void l_int(dumper *d, const char *path, int64_t v)
{
	if (d->collect)
		return;
	line_start(d, path);
	sr_printf(d->b, "%lld\n", (long long)v);
}

static void l_uint(dumper *d, const char *path, uint64_t v)
{
	if (d->collect)
		return;
	line_start(d, path);
	sr_printf(d->b, "%llu\n", (unsigned long long)v);
}

static void l_bool(dumper *d, const char *path, int v) { line(d, path, v ? "true" : "false"); }

static void l_len(dumper *d, const char *path, size_t n)
{
	if (d->collect)
		return;
	line_start(d, path);
	sr_printf(d->b, "#%zu\n", n);
}

static void fail(dumper *d, const char *path, const char *what)
{
	if (!d->err)
		d->err = cat(cat(path, ": "), what);
}

/* ---- scalars of the IR ---- */

static void d_pos(dumper *d, const char *path, fe_pos p)
{
	l_str(d, cat(path, ".File"), p.file);
	l_int(d, cat(path, ".Line"), p.line);
	l_int(d, cat(path, ".Col"), p.col);
}

static void d_big(dumper *d, const char *path, const bigint *x)
{
	if (!x) {
		line(d, path, "nil");
		return;
	}
	if (d->collect)
		return;
	char *s = bigint_string(x);
	line(d, path, s);
	free(s);
}

static void d_ival(dumper *d, const char *path, fe_ival v)
{
	if (!v.set) {
		line(d, path, "nil");
		return;
	}
	if (d->collect)
		return;
	char lo[64], hi[64];
	intv_string(v.lo, lo);
	intv_string(v.hi, hi);
	line_start(d, path);
	sr_printf(d->b, "[%s, %s]\n", lo, hi);
}

static void d_strs(dumper *d, const char *path, const sr_str *v, size_t n, int is_nil)
{
	if (is_nil) {
		line(d, path, "nil");
		return;
	}
	l_len(d, path, n);
	for (size_t i = 0; i < n; i++)
		l_str(d, idx(path, i), v[i]);
}

/* ---- the registry ---- */

static reg_entry *reg_find(dumper *d, int kind, sr_str name)
{
	for (size_t i = 0; i < d->n_reg; i++)
		if (d->reg[i].kind == kind && sr_eq(d->reg[i].name, name))
			return &d->reg[i];
	return NULL;
}

static const char *reg_id(int kind, sr_str name)
{
	sr_buf b = {0};
	sr_puts(&b, kind_name[kind]);
	sr_putc(&b, ':');
	sr_putstr(&b, name);
	sr_putc(&b, 0);
	return b.p;
}

typedef void (*print_fn)(dumper *d, const char *path, const void *p);

/* a pointer to a declaration (e178Dumper.walk's declaration branch) */
static void d_decl(dumper *d, const char *path, int kind, sr_str name, const void *p, print_fn pr)
{
	if (!p) {
		line(d, path, "nil");
		return;
	}
	if (name.n == 0) {
		line(d, path, cat("anon ", kind_name[kind]));
		pr(d, path, p);
		return;
	}
	const char *id = reg_id(kind, name);
	reg_entry *e = reg_find(d, kind, name);
	if (d->collect) {
		if (e) {
			if (e->p != p)
				fail(d, path, cat(cat("two objects have the id ", id), " (a duplicate or a detached same-name copy)"));
			return;
		}
		if (d->n_reg == d->cap_reg) {
			d->cap_reg = d->cap_reg ? 2 * d->cap_reg : 16;
			reg_entry *nv = sr_alloc(d->cap_reg * sizeof *nv);
			if (d->n_reg)
				memcpy(nv, d->reg, d->n_reg * sizeof *nv);
			d->reg = nv;
		}
		d->reg[d->n_reg++] = (reg_entry){kind, name, p};
		pr(d, path, p);
		return;
	}
	if (!e || e->p != p) {
		fail(d, path, cat(cat("the reference to ", id), " is not the registered object"));
		return;
	}
	if (p == d->self) {
		pr(d, path, p);
		return;
	}
	line(d, path, cat("&", id));
}

static void field_ref_add(dumper *d, const void *p, const char *ref)
{
	if (d->n_fields == d->cap_fields) {
		d->cap_fields = d->cap_fields ? 2 * d->cap_fields : 32;
		field_ref *nv = sr_alloc(d->cap_fields * sizeof *nv);
		if (d->n_fields)
			memcpy(nv, d->fields, d->n_fields * sizeof *nv);
		d->fields = nv;
	}
	d->fields[d->n_fields++] = (field_ref){p, ref};
}

static const char *field_ref_of(dumper *d, const void *p)
{
	for (size_t i = 0; i < d->n_fields; i++)
		if (d->fields[i].p == p)
			return d->fields[i].ref;
	return NULL;
}

/* ---- declarations ---- */

static void pr_record_field(dumper *d, const char *path, const fe_record_field *f)
{
	l_str(d, cat(path, ".Name"), f->name);
	l_int(d, cat(path, ".Bits"), f->bits);
	l_bool(d, cat(path, ".Signed"), f->is_signed);
	l_bool(d, cat(path, ".Pad"), f->pad);
	l_int(d, cat(path, ".Offset"), f->offset);
	l_int(d, cat(path, ".Count"), f->count);
}

static void pr_tp_field(dumper *d, const char *path, const fe_tp_field *f)
{
	l_str(d, cat(path, ".Name"), f->name);
	l_int(d, cat(path, ".Offset"), f->offset);
	l_str(d, cat(path, ".Type"), f->type);
	l_int(d, cat(path, ".N"), f->n);
}

static void pr_record(dumper *d, const char *path, const void *p)
{
	const fe_record_decl *r = p;
	l_str(d, cat(path, ".Const"), r->const_name);
	const char *fp = cat(path, ".Fields");
	if (r->fields_nil) {
		line(d, fp, "nil");
	} else {
		l_len(d, fp, r->n_fields);
		for (size_t i = 0; i < r->n_fields; i++)
			pr_record_field(d, idx(fp, i), &r->fields[i]);
	}
	l_int(d, cat(path, ".Size"), r->size);
	l_int(d, cat(path, ".Align"), r->align);
	d_pos(d, cat(path, ".Pos"), r->pos);
	d_pos(d, cat(path, ".StructPos"), r->struct_pos);
}

static void d_record(dumper *d, const char *path, const fe_record_decl *r)
{
	d_decl(d, path, K_RECORD, r ? r->const_name : (sr_str){0}, r, pr_record);
}

static void pr_map(dumper *d, const char *path, const void *p)
{
	const fe_map_decl *m = p;
	l_str(d, cat(path, ".Const"), m->const_name);
	l_str(d, cat(path, ".Name"), m->name);
	l_int(d, cat(path, ".ValueBits"), m->value_bits);
	l_bool(d, cat(path, ".Signed"), m->is_signed);
	l_uint(d, cat(path, ".MaxEntries"), m->max_entries);
	d_record(d, cat(path, ".Record"), m->record);
	l_str(d, cat(path, ".Kind"), m->kind);
	l_str(d, cat(path, ".Class"), m->class_name);
	l_int(d, cat(path, ".KeyBits"), m->key_bits);
	l_bool(d, cat(path, ".KeySigned"), m->key_signed);
	d_record(d, cat(path, ".KeyRecord"), m->key_record);
	d_pos(d, cat(path, ".Pos"), m->pos);
}

static void d_map(dumper *d, const char *path, const fe_map_decl *m)
{
	d_decl(d, path, K_MAP, m ? m->const_name : (sr_str){0}, m, pr_map);
}

static void pr_ring(dumper *d, const char *path, const void *p)
{
	const fe_ring_decl *r = p;
	l_str(d, cat(path, ".Const"), r->const_name);
	l_str(d, cat(path, ".Name"), r->name);
	d_record(d, cat(path, ".Record"), r->record);
	l_uint(d, cat(path, ".Size"), r->size);
	d_pos(d, cat(path, ".Pos"), r->pos);
}

static void d_ring(dumper *d, const char *path, const fe_ring_decl *r)
{
	d_decl(d, path, K_RING, r ? r->const_name : (sr_str){0}, r, pr_ring);
}

static void pr_global(dumper *d, const char *path, const void *p)
{
	const fe_global_decl *g = p;
	l_str(d, cat(path, ".Const"), g->const_name);
	l_str(d, cat(path, ".Name"), g->name);
	l_str(d, cat(path, ".Class"), g->class_name);
	l_str(d, cat(path, ".Section"), g->section);
	l_int(d, cat(path, ".Bits"), g->bits);
	l_bool(d, cat(path, ".Signed"), g->is_signed);
	l_bool(d, cat(path, ".Optional"), g->optional);
	d_pos(d, cat(path, ".Pos"), g->pos);
}

static void d_global(dumper *d, const char *path, const fe_global_decl *g)
{
	d_decl(d, path, K_GLOBAL, g ? g->const_name : (sr_str){0}, g, pr_global);
}

static void pr_ktype(dumper *d, const char *path, const void *p)
{
	const fe_kernel_type_decl *k = p;
	l_str(d, cat(path, ".Const"), k->const_name);
	l_str(d, cat(path, ".Name"), k->name);
	const char *fp = cat(path, ".Fields");
	if (k->fields_nil) {
		line(d, fp, "nil");
	} else {
		l_len(d, fp, k->n_fields);
		for (size_t i = 0; i < k->n_fields; i++) {
			const char *e = idx(fp, i);
			const fe_kernel_field *f = &k->fields[i];
			l_str(d, cat(e, ".Name"), f->name);
			l_str(d, cat(e, ".Kind"), f->kind);
			l_int(d, cat(e, ".Bits"), f->bits);
			l_bool(d, cat(e, ".Signed"), f->is_signed);
			l_str(d, cat(e, ".Ptr"), f->ptr);
			l_int(d, cat(e, ".Count"), f->count);
		}
	}
	d_pos(d, cat(path, ".Pos"), k->pos);
	d_pos(d, cat(path, ".StructPos"), k->struct_pos);
	const char *hp = cat(path, ".HandlePoss");
	if (k->handle_poss_nil) {
		line(d, hp, "nil");
	} else {
		l_len(d, hp, k->n_handle_poss);
		for (size_t i = 0; i < k->n_handle_poss; i++)
			d_pos(d, idx(hp, i), k->handle_poss[i]);
	}
}

static void d_ktype(dumper *d, const char *path, const fe_kernel_type_decl *k)
{
	d_decl(d, path, K_KTYPE, k ? k->const_name : (sr_str){0}, k, pr_ktype);
}

/* a *RecordField or *TpField outside a declaration */
static void d_field_ptr(dumper *d, const char *path, const void *p, int tp)
{
	if (!p) {
		line(d, path, "nil");
		return;
	}
	if (d->collect)
		return;
	const char *ref = field_ref_of(d, p);
	if (ref) {
		line(d, path, ref);
		return;
	}
	line(d, path, tp ? "own TpField" : "own RecordField");
	if (tp)
		pr_tp_field(d, path, p);
	else
		pr_record_field(d, path, p);
}

/* ---- Expr and Stmt ---- */

static void d_stmts(dumper *d, const char *path, const fe_stmts *ss);

static void d_expr(dumper *d, const char *path, const fe_expr *e)
{
	if (!e) {
		line(d, path, "nil");
		return;
	}
	l_str(d, cat(path, ".Kind"), e->kind);
	l_str(d, cat(path, ".Op"), e->op);
	const char *ap = cat(path, ".Args");
	if (e->args_nil) {
		line(d, ap, "nil");
	} else {
		l_len(d, ap, e->n_args);
		for (size_t i = 0; i < e->n_args; i++)
			d_expr(d, idx(ap, i), e->args[i]);
	}
	d_field_ptr(d, cat(path, ".TpCopy"), e->tp_copy, 1);
	d_big(d, cat(path, ".Lit"), e->lit);
	l_bool(d, cat(path, ".B"), e->b);
	l_str(d, cat(path, ".Var"), e->var);
	l_str(d, cat(path, ".Ref"), e->ref);
	d_map(d, cat(path, ".Map"), e->map);
	l_bool(d, cat(path, ".Bool"), e->bool_);
	d_ival(d, cat(path, ".Iv"), e->iv);
	l_bool(d, cat(path, ".Wide"), e->wide);
	l_str(d, cat(path, ".Div"), e->div);
	l_int(d, cat(path, ".Idx"), e->idx);
	d_field_ptr(d, cat(path, ".Field"), e->field, 0);
	d_ring(d, cat(path, ".Ring"), e->ring);
	l_int(d, cat(path, ".Len"), e->len);
	d_global(d, cat(path, ".Glob"), e->glob);
	l_str(d, cat(path, ".Path"), e->path);
	d_pos(d, cat(path, ".Pos"), e->pos);
}

static void d_stmt(dumper *d, const char *path, const fe_stmt *s)
{
	l_str(d, cat(path, ".Kind"), s->kind);
	d_field_ptr(d, cat(path, ".Field"), s->field, 0);
	l_str(d, cat(path, ".Op"), s->op);
	d_ring(d, cat(path, ".Ring"), s->ring);
	l_str(d, cat(path, ".Var"), s->var);
	d_global(d, cat(path, ".Glob"), s->glob);
	d_expr(d, cat(path, ".Off"), s->off);
	l_int(d, cat(path, ".Len"), s->len);
	d_expr(d, cat(path, ".Val"), s->val);
	d_expr(d, cat(path, ".Cond"), s->cond);
	d_stmts(d, cat(path, ".Then"), &s->then);
	d_stmts(d, cat(path, ".Else"), &s->else_);
	d_map(d, cat(path, ".Map"), s->map);
	d_expr(d, cat(path, ".Key"), s->key);
	d_expr(d, cat(path, ".Value"), s->value);
	d_pos(d, cat(path, ".Pos"), s->pos);
	d_pos(d, cat(path, ".IfPos"), s->if_pos);
	l_int(d, cat(path, ".Count"), s->count);
	d_expr(d, cat(path, ".Bound"), s->bound);
	l_str(d, cat(path, ".Path"), s->path);
	l_bool(d, cat(path, ".Clamp"), s->clamp);
	l_bool(d, cat(path, ".Incl"), s->incl);
	d_strs(d, cat(path, ".Carried"), s->carried, s->n_carried, s->carried_nil);
	d_ktype(d, cat(path, ".KT"), s->kt);
	l_str(d, cat(path, ".PtrOf"), s->ptr_of);
	d_ktype(d, cat(path, ".PtrOfKT"), s->ptr_of_kt);
	l_str(d, cat(path, ".KStr"), s->k_str);
	l_bool(d, cat(path, ".Comm"), s->comm);
	d_field_ptr(d, cat(path, ".TpCopy"), s->tp_copy, 1);
	d_field_ptr(d, cat(path, ".TpStr"), s->tp_str, 1);
	l_bool(d, cat(path, ".Argv"), s->argv);
	d_field_ptr(d, cat(path, ".Index"), s->index, 0);
	l_str(d, cat(path, ".StrSSA"), s->str_ssa);
	l_int(d, cat(path, ".IndexV"), s->index_v);
	l_bool(d, cat(path, ".Buf"), s->buf);
	d_expr(d, cat(path, ".BufLen"), s->buf_len);
	d_field_ptr(d, cat(path, ".CountF"), s->count_f, 0);
}

static void d_stmts(dumper *d, const char *path, const fe_stmts *ss)
{
	if (ss->nil) {
		line(d, path, "nil");
		return;
	}
	l_len(d, path, ss->n);
	for (size_t i = 0; i < ss->n; i++)
		d_stmt(d, idx(path, i), &ss->v[i]);
}

/* ---- Program and Result ---- */

static void d_program(dumper *d, const char *path, const fe_program *p)
{
	if (!p) {
		line(d, path, "nil");
		return;
	}
	l_str(d, cat(path, ".Name"), p->name);
	l_str(d, cat(path, ".Kind"), p->kind);
	l_str(d, cat(path, ".Target"), p->target);
	l_int(d, cat(path, ".Nargs"), p->nargs);
	l_str(d, cat(path, ".Ret"), p->ret);
	const char *x = cat(path, ".Params");
	if (p->params_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, p->n_params);
		for (size_t i = 0; i < p->n_params; i++) {
			l_int(d, cat(idx(x, i), ".N"), p->params[i].n);
			l_str(d, cat(idx(x, i), ".Type"), p->params[i].type);
		}
	}
	x = cat(path, ".TArgs");
	if (p->t_args_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, p->n_t_args);
		for (size_t i = 0; i < p->n_t_args; i++) {
			const char *e = idx(x, i);
			l_int(d, cat(e, ".Idx"), p->t_args[i].idx);
			d_ktype(d, cat(e, ".KT"), p->t_args[i].kt);
			l_str(d, cat(e, ".Type"), p->t_args[i].type);
			l_bool(d, cat(e, ".Null"), p->t_args[i].null);
		}
	}
	x = cat(path, ".TFields");
	if (p->t_fields_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, p->n_t_fields);
		for (size_t i = 0; i < p->n_t_fields; i++)
			pr_tp_field(d, idx(x, i), &p->t_fields[i]);
	}
	d_strs(d, cat(path, ".FParams"), p->f_params, p->n_f_params, p->f_params_nil);
	d_expr(d, cat(path, ".FRet"), p->f_ret);
	l_int(d, cat(path, ".FBorrow"), p->f_borrow);
	d_map(d, cat(path, ".FBorrowMap"), p->f_borrow_map);
	l_int(d, cat(path, ".FWin"), p->f_win);
	l_int(d, cat(path, ".FWinLen"), p->f_win_len);
	l_int(d, cat(path, ".FCtx"), p->f_ctx);
	l_str(d, cat(path, ".FCtxKind"), p->f_ctx_kind);
	l_str(d, cat(path, ".BinarySHA"), p->binary_sha);
	l_str(d, cat(path, ".BinaryPath"), p->binary_path);
	l_str(d, cat(path, ".SysTarget"), p->sys_target);
	x = cat(path, ".Globals");
	if (p->globals_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, p->n_globals);
		for (size_t i = 0; i < p->n_globals; i++)
			d_global(d, idx(x, i), p->globals[i]);
	}
	d_pos(d, cat(path, ".Pos"), p->pos);
	d_pos(d, cat(path, ".DeclPos"), p->decl_pos);
	d_stmts(d, cat(path, ".Body"), &p->body);
	l_str(d, cat(path, ".Verdict"), p->verdict);
	l_str(d, cat(path, ".VerdictConst"), p->verdict_const);
	d_map(d, cat(path, ".RedirMap"), p->redir_map);
	d_expr(d, cat(path, ".RedirKey"), p->redir_key);
	l_str(d, cat(path, ".GuardVerdict"), p->guard_verdict);
	d_expr(d, cat(path, ".FmodVal"), p->fmod_val);
	d_big(d, cat(path, ".FmodGuard"), p->fmod_guard);
	d_pos(d, cat(path, ".VerdictPos"), p->verdict_pos);
	l_int(d, cat(path, ".EndLine"), p->end_line);
	x = cat(path, ".Maps");
	if (p->maps_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, p->n_maps);
		for (size_t i = 0; i < p->n_maps; i++)
			d_map(d, idx(x, i), p->maps[i]);
	}
	x = cat(path, ".Rings");
	if (p->rings_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, p->n_rings);
		for (size_t i = 0; i < p->n_rings; i++)
			d_ring(d, idx(x, i), p->rings[i]);
	}
}

static void d_programs(dumper *d, const char *path, fe_program *const *v, size_t n, int is_nil)
{
	if (is_nil) {
		line(d, path, "nil");
		return;
	}
	l_len(d, path, n);
	for (size_t i = 0; i < n; i++)
		d_program(d, idx(path, i), v[i]);
}

static int str_less(sr_str a, sr_str b)
{
	size_t n = a.n < b.n ? a.n : b.n;
	int c = n ? memcmp(a.p, b.p, n) : 0;
	return c < 0 || (c == 0 && a.n < b.n);
}

/* the live keys of a name table, sorted as Go's sort.Strings */
static sr_str *sorted_keys(const fe_name_table *t, size_t *n)
{
	sr_str *k = sr_alloc((t->n + 1) * sizeof *k);
	size_t m = 0;
	for (size_t i = 0; i < t->n; i++)
		if (!t->e[i].removed)
			k[m++] = t->e[i].key;
	for (size_t i = 1; i < m; i++)
		for (size_t j = i; j > 0 && str_less(k[j], k[j - 1]); j--) {
			sr_str s = k[j];
			k[j] = k[j - 1];
			k[j - 1] = s;
		}
	*n = m;
	return k;
}

static void d_diags(dumper *d, const char *path, const fe_diags *ds)
{
	if (!ds->v) {
		line(d, path, "nil");
		return;
	}
	l_len(d, path, ds->n);
	for (size_t i = 0; i < ds->n; i++) {
		const char *e = idx(path, i);
		const fe_diag *g = &ds->v[i];
		l_int(d, cat(e, ".Verdict"), (int64_t)g->verdict);
		l_str(d, cat(e, ".Code"), sr_cstr(fe_code_text(g->code)));
		d_pos(d, cat(e, ".Pos"), g->pos);
		d_strs(d, cat(e, ".Path"), g->path, g->n_path, g->path == NULL);
		l_str(d, cat(e, ".Msg"), g->msg);
	}
}

static void d_result(dumper *d, const char *path, const fe_result *r)
{
	l_str(d, cat(path, ".Source"), r->source);
	d_programs(d, cat(path, ".Programs"), r->programs, r->n_programs, r->programs_nil);
	const char *x = cat(path, ".Maps");
	if (r->maps_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, r->n_maps);
		for (size_t i = 0; i < r->n_maps; i++)
			d_map(d, idx(x, i), r->maps[i]);
	}
	x = cat(path, ".Rings");
	if (r->rings_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, r->n_rings);
		for (size_t i = 0; i < r->n_rings; i++)
			d_ring(d, idx(x, i), r->rings[i]);
	}
	x = cat(path, ".Globals");
	if (r->globals_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, r->n_globals);
		for (size_t i = 0; i < r->n_globals; i++)
			d_global(d, idx(x, i), r->globals[i]);
	}
	x = cat(path, ".KernelTypes");
	if (r->kernel_types_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, r->n_kernel_types);
		for (size_t i = 0; i < r->n_kernel_types; i++)
			d_ktype(d, idx(x, i), r->kernel_types[i]);
	}
	d_programs(d, cat(path, ".Funcs"), r->funcs, r->n_funcs, r->funcs_nil);
	x = cat(path, ".Membership");
	if (r->membership_nil) {
		line(d, x, "nil");
	} else {
		size_t n;
		sr_str *keys = sorted_keys(&r->membership, &n);
		l_len(d, x, n);
		for (size_t i = 0; i < n; i++) {
			const fe_str_list *l = fe_name_get(&r->membership, keys[i]);
			d_strs(d, keyed(x, keys[i]), l ? l->v : NULL, l ? l->n : 0, l == NULL || l->v == NULL);
		}
	}
	x = cat(path, ".Edges");
	if (r->edges_nil) {
		line(d, x, "nil");
	} else {
		l_len(d, x, r->n_edges);
		for (size_t i = 0; i < r->n_edges; i++) {
			const char *e = idx(x, i);
			l_str(d, cat(e, ".From"), r->edges[i].from);
			l_str(d, cat(e, ".To"), r->edges[i].to);
			d_pos(d, cat(e, ".Pos"), r->edges[i].pos);
			l_str(d, cat(e, ".Dispatch"), r->edges[i].dispatch);
		}
	}
	d_diags(d, cat(path, ".Diags"), &r->diags);
}

/* ---- DomainGraph (schema.go) as json.MarshalIndent(doc, "", "  ") plus "\n" ---- */

/* encoding/json's string encoder with HTML escaping */
static void json_str(sr_buf *b, sr_str s)
{
	static const char hex[] = "0123456789abcdef";
	sr_putc(b, '"');
	for (size_t i = 0; i < s.n;) {
		unsigned char c = (unsigned char)s.p[i];
		if (c < 0x80) {
			if (c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&') {
				sr_putc(b, (char)c);
			} else {
				switch (c) {
				case '\\': sr_puts(b, "\\\\"); break;
				case '"': sr_puts(b, "\\\""); break;
				case '\b': sr_puts(b, "\\b"); break;
				case '\f': sr_puts(b, "\\f"); break;
				case '\n': sr_puts(b, "\\n"); break;
				case '\r': sr_puts(b, "\\r"); break;
				case '\t': sr_puts(b, "\\t"); break;
				default:
					sr_puts(b, "\\u00");
					sr_putc(b, hex[c >> 4]);
					sr_putc(b, hex[c & 0xf]);
				}
			}
			i++;
			continue;
		}
		size_t w;
		int32_t r = sr_decode_rune(s.p + i, s.n - i, &w);
		if (r == 0xFFFD && w == 1) {
			sr_puts(b, "\\ufffd");
		} else if (r == 0x2028 || r == 0x2029) {
			sr_puts(b, r == 0x2028 ? "\\u2028" : "\\u2029");
		} else {
			sr_put(b, s.p + i, w);
		}
		i += w;
	}
	sr_putc(b, '"');
}

static void ind(sr_buf *b, int depth)
{
	sr_putc(b, '\n');
	for (int i = 0; i < depth; i++)
		sr_puts(b, "  ");
}

static void j_key(sr_buf *b, int depth, const char *k, int first)
{
	if (!first)
		sr_putc(b, ',');
	ind(b, depth);
	json_str(b, sr_cstr(k));
	sr_puts(b, ": ");
}

static void j_pos(sr_buf *b, int depth, fe_pos p)
{
	sr_putc(b, '{');
	j_key(b, depth + 1, "file", 1);
	json_str(b, p.file);
	j_key(b, depth + 1, "line", 0);
	sr_printf(b, "%lld", (long long)p.line);
	j_key(b, depth + 1, "col", 0);
	sr_printf(b, "%lld", (long long)p.col);
	ind(b, depth);
	sr_putc(b, '}');
}

static void j_strs(sr_buf *b, int depth, const sr_str *v, size_t n, int is_nil)
{
	if (is_nil) {
		sr_puts(b, "null");
		return;
	}
	if (n == 0) {
		sr_puts(b, "[]");
		return;
	}
	sr_putc(b, '[');
	for (size_t i = 0; i < n; i++) {
		if (i)
			sr_putc(b, ',');
		ind(b, depth + 1);
		json_str(b, v[i]);
	}
	ind(b, depth);
	sr_putc(b, ']');
}

void fe_domain_graph(sr_buf *b, const fe_result *r)
{
	sr_putc(b, '{');
	j_key(b, 1, "source", 1);
	json_str(b, r->source);
	j_key(b, 1, "roots", 0);
	if (r->n_programs == 0) {
		sr_puts(b, "[]");
	} else {
		sr_putc(b, '[');
		for (size_t i = 0; i < r->n_programs; i++) {
			const fe_program *p = r->programs[i];
			if (i)
				sr_putc(b, ',');
			ind(b, 2);
			sr_putc(b, '{');
			j_key(b, 3, "name", 1);
			json_str(b, p->name);
			j_key(b, 3, "kind", 0);
			json_str(b, p->kind);
			j_key(b, 3, "decl", 0);
			j_pos(b, 3, p->decl_pos);
			j_key(b, 3, "def", 0);
			j_pos(b, 3, p->pos);
			ind(b, 2);
			sr_putc(b, '}');
		}
		ind(b, 1);
		sr_putc(b, ']');
	}
	j_key(b, 1, "functions", 0);
	size_t nk = 0;
	sr_str *keys = r->membership_nil ? NULL : sorted_keys(&r->membership, &nk);
	if (nk == 0) {
		sr_puts(b, "[]");
	} else {
		sr_putc(b, '[');
		for (size_t i = 0; i < nk; i++) {
			const fe_str_list *l = fe_name_get(&r->membership, keys[i]);
			if (i)
				sr_putc(b, ',');
			ind(b, 2);
			sr_putc(b, '{');
			j_key(b, 3, "name", 1);
			json_str(b, keys[i]);
			j_key(b, 3, "membership", 0);
			j_strs(b, 3, l ? l->v : NULL, l ? l->n : 0, l == NULL || l->v == NULL);
			ind(b, 2);
			sr_putc(b, '}');
		}
		ind(b, 1);
		sr_putc(b, ']');
	}
	j_key(b, 1, "edges", 0);
	if (r->n_edges == 0) {
		sr_puts(b, "[]");
	} else {
		sr_putc(b, '[');
		for (size_t i = 0; i < r->n_edges; i++) {
			const fe_edge *e = &r->edges[i];
			if (i)
				sr_putc(b, ',');
			ind(b, 2);
			sr_putc(b, '{');
			j_key(b, 3, "from", 1);
			json_str(b, e->from);
			j_key(b, 3, "to", 0);
			json_str(b, e->to);
			j_key(b, 3, "pos", 0);
			j_pos(b, 3, e->pos);
			j_key(b, 3, "dispatch", 0);
			json_str(b, e->dispatch);
			ind(b, 2);
			sr_putc(b, '}');
		}
		ind(b, 1);
		sr_putc(b, ']');
	}
	j_key(b, 1, "diagnostics", 0);
	fe_diags s = fe_diags_sorted(&r->diags);
	if (s.n == 0) {
		sr_puts(b, "[]");
	} else {
		sr_putc(b, '[');
		for (size_t i = 0; i < s.n; i++) {
			const fe_diag *g = &s.v[i];
			if (i)
				sr_putc(b, ',');
			ind(b, 2);
			sr_putc(b, '{');
			j_key(b, 3, "verdict", 1);
			json_str(b, sr_cstr(fe_verdict_string(g->verdict)));
			j_key(b, 3, "code", 0);
			json_str(b, sr_cstr(fe_code_text(g->code)));
			j_key(b, 3, "name", 0);
			json_str(b, sr_cstr(fe_code_name(g->code)));
			j_key(b, 3, "pos", 0);
			j_pos(b, 3, g->pos);
			if (g->n_path > 0) {
				j_key(b, 3, "path", 0);
				j_strs(b, 3, g->path, g->n_path, 0);
			}
			j_key(b, 3, "message", 0);
			json_str(b, g->msg);
			ind(b, 2);
			sr_putc(b, '}');
		}
		ind(b, 1);
		sr_putc(b, ']');
	}
	ind(b, 0);
	sr_puts(b, "}\n");
}

/* ---- the whole dump ---- */

static void pr_by_kind(dumper *d, const char *path, int kind, const void *p)
{
	static const print_fn fns[K_N] = {pr_map, pr_record, pr_ring, pr_global, pr_ktype};
	fns[kind](d, path, p);
}

static int reg_less(const reg_entry *a, const reg_entry *b)
{
	return a->kind != b->kind ? a->kind < b->kind : str_less(a->name, b->name);
}

const char *fe_result_dump(sr_buf *out, const fe_result *r)
{
	dumper d = {0};
	sr_buf scratch = {0};
	d.b = &scratch;
	d.collect = 1;
	d_result(&d, "result", r);
	if (d.err)
		return d.err;
	for (size_t i = 0; i < d.n_reg; i++) {
		if (d.reg[i].kind != K_RECORD)
			continue;
		const fe_record_decl *rec = d.reg[i].p;
		const char *id = reg_id(K_RECORD, rec->const_name);
		for (size_t j = 0; j < rec->n_fields; j++) {
			sr_buf rb = {0};
			sr_printf(&rb, "&%s.%zu", id, j);
			sr_putc(&rb, 0);
			field_ref_add(&d, &rec->fields[j], rb.p);
		}
	}
	for (int pass = 0; pass < 2; pass++) {
		fe_program *const *ps = pass ? r->funcs : r->programs;
		size_t n = pass ? r->n_funcs : r->n_programs;
		for (size_t i = 0; i < n; i++) {
			const fe_program *p = ps[i];
			if (!p)
				continue;
			for (size_t j = 0; j < p->n_t_fields; j++) {
				sr_buf rb = {0};
				sr_puts(&rb, "&tpfield:");
				sr_putstr(&rb, p->name);
				sr_printf(&rb, ".%zu", j);
				sr_putc(&rb, 0);
				field_ref_add(&d, &p->t_fields[j], rb.p);
			}
		}
	}
	d.collect = 0;
	d.b = out;
	sr_buf dom = {0};
	fe_domain_graph(&dom, r);
	sr_puts(out, "domain = ");
	sr_quote_ascii(out, sr_bufstr(&dom));
	sr_putc(out, '\n');
	/* the registry, ordered by kind, then name */
	for (size_t i = 1; i < d.n_reg; i++)
		for (size_t j = i; j > 0 && reg_less(&d.reg[j], &d.reg[j - 1]); j--) {
			reg_entry t = d.reg[j];
			d.reg[j] = d.reg[j - 1];
			d.reg[j - 1] = t;
		}
	for (size_t i = 0; i < d.n_reg; i++) {
		const char *id = reg_id(d.reg[i].kind, d.reg[i].name);
		sr_puts(out, "decl ");
		sr_puts(out, id);
		sr_putc(out, '\n');
		d.self = d.reg[i].p;
		pr_by_kind(&d, id, d.reg[i].kind, d.reg[i].p);
		d.self = NULL;
	}
	d_result(&d, "result", r);
	return d.err;
}

void fe_error_dump(sr_buf *out, sr_str err)
{
	sr_puts(out, "error = ");
	sr_quote_ascii(out, err);
	sr_putc(out, '\n');
}
