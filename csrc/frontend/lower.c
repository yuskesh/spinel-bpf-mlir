/* lower.c — Lower (internal/frontend/lower.go) in C, with the lowering methods of uprobe.go (outputStr), argv.go (outputArgv),
 * fmodret.go (lowerFmodReturn) and sklookup.go (skAssign) (the lowering to .mlir).
 *
 * The Go code stays the canon; each function names the Go it follows. The SSA environment (Go's map[string]ssaVal) is a table in
 * first-insertion order. Go reads it by key only, except in results(), which sorts its keys, so the table order is never seen.
 * A missing key reads as Go's zero ssaVal (name "", type ""). Go's mutation hooks are not ported (lower.h). */
#include "lower.h"
#include "core.h"
#include "../pin/pins.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* ---- ssaVal and the tables ---- */
typedef struct {
	sr_str name;
	const char *ty; /* "i64", "i1", "kptr" or "" (Go's zero value) */
} sv;

static int sv_eq(sv a, sv b) { return sr_eq(a.name, b.name) && strcmp(a.ty, b.ty) == 0; }

typedef struct {
	sr_str k;
	sv v;
} env_ent;
typedef struct {
	env_ent *e;
	size_t n, cap;
} env;

static env_ent *env_find(const env *m, sr_str k)
{
	for (size_t i = 0; i < m->n; i++)
		if (sr_eq(m->e[i].k, k))
			return &m->e[i];
	return NULL;
}
static sv env_get(const env *m, sr_str k, int *ok)
{
	env_ent *x = env_find(m, k);
	if (ok)
		*ok = x != NULL;
	return x ? x->v : (sv){{"", 0}, ""};
}
static void env_set(env *m, sr_str k, sv v)
{
	env_ent *x = env_find(m, k);
	if (x) {
		x->v = v;
		return;
	}
	if (m->n == m->cap) {
		size_t nc = m->cap ? m->cap * 2 : 8;
		m->e = sr_grow(m->e, m->cap * sizeof *m->e, nc * sizeof *m->e);
		m->cap = nc;
	}
	m->e[m->n++] = (env_ent){k, v};
}
static void env_del(env *m, sr_str k)
{
	for (size_t i = 0; i < m->n; i++)
		if (sr_eq(m->e[i].k, k)) {
			memmove(&m->e[i], &m->e[i + 1], (m->n - i - 1) * sizeof *m->e);
			m->n--;
			return;
		}
}
static env env_copy(const env *m)
{
	env o = {0};
	for (size_t i = 0; i < m->n; i++)
		env_set(&o, m->e[i].k, m->e[i].v);
	return o;
}

/* borrow {name, bits}: refs and wins (name -> borrow) */
typedef struct {
	sr_str name;
	int64_t bits;
} borrow;
typedef struct {
	sr_str k;
	borrow v;
} bor_ent;
typedef struct {
	bor_ent *e;
	size_t n, cap;
} bor_tab;

static int bor_get(const bor_tab *m, sr_str k, borrow *out)
{
	for (size_t i = 0; i < m->n; i++)
		if (sr_eq(m->e[i].k, k)) {
			*out = m->e[i].v;
			return 1;
		}
	*out = (borrow){{"", 0}, 0};
	return 0;
}
static void bor_set(bor_tab *m, sr_str k, borrow v)
{
	for (size_t i = 0; i < m->n; i++)
		if (sr_eq(m->e[i].k, k)) {
			m->e[i].v = v;
			return;
		}
	if (m->n == m->cap) {
		size_t nc = m->cap ? m->cap * 2 : 8;
		m->e = sr_grow(m->e, m->cap * sizeof *m->e, nc * sizeof *m->e);
		m->cap = nc;
	}
	m->e[m->n++] = (bor_ent){k, v};
}
static void bor_del(bor_tab *m, sr_str k)
{
	for (size_t i = 0; i < m->n; i++)
		if (sr_eq(m->e[i].k, k)) {
			memmove(&m->e[i], &m->e[i + 1], (m->n - i - 1) * sizeof *m->e);
			m->n--;
			return;
		}
}

/* ---- the lowerer (lower.go lowerer) ---- */
typedef struct {
	const fe_map_decl *m;
	sr_str name;
} map_ent;

typedef struct {
	sr_str *v;
	size_t n;
} names;

typedef struct {
	fe_z *z;
	sr_str kind;
	sr_buf *b;
	int64_t *n;
	map_ent *maps;
	size_t n_maps;
	sr_str indent;
	env env;
	bor_tab refs, wins;
	names *loops;
	size_t n_loops, cap_loops;
	sr_str fired;
	env narrow; /* i64 value -> its i32 (the name only) */
	sr_buf err;  /* Go's error text */
	int failed;
} lowerer;

static sr_str map_name(const lowerer *l, const fe_map_decl *m)
{
	for (size_t i = 0; i < l->n_maps; i++)
		if (l->maps[i].m == m)
			return l->maps[i].name;
	return (sr_str){"", 0};
}

/* Go's fmt for the lowering: %s (const char *), %S (sr_str), %q (sr_str, Go's %q), %d (int64_t), %L (fe_pos: loc()), %P (fe_pos:
 * Pos.String), %B (const bigint *, decimal), %%. */
static void vfmt(lowerer *l, sr_buf *b, const char *f, va_list ap)
{
	for (; *f; f++) {
		if (*f != '%') {
			sr_putc(b, *f);
			continue;
		}
		switch (*++f) {
		case 's':
			sr_puts(b, va_arg(ap, const char *));
			break;
		case 'S':
			sr_putstr(b, va_arg(ap, sr_str));
			break;
		case 'q':
			fe_fmt_q(l->z, b, va_arg(ap, sr_str));
			break;
		case 'd':
			sr_printf(b, "%lld", (long long)va_arg(ap, int64_t));
			break;
		case 'L': { /* loc(): loc(%q:%d:%d) */
			fe_pos p = va_arg(ap, fe_pos);
			sr_puts(b, "loc(");
			fe_fmt_q(l->z, b, p.file);
			sr_printf(b, ":%lld:%lld)", (long long)p.line, (long long)p.col);
			break;
		}
		case 'P':
			fe_pos_string(b, va_arg(ap, fe_pos));
			break;
		case 'B':
			fe_fmt_big(b, va_arg(ap, const bigint *));
			break;
		case '%':
			sr_putc(b, '%');
			break;
		default:
			abort();
		}
	}
}

static void wr(lowerer *l, sr_buf *b, const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	vfmt(l, b, f, ap);
	va_end(ap);
}

static sr_str S(lowerer *l, const char *f, ...)
{
	sr_buf b = {0};
	va_list ap;
	va_start(ap, f);
	vfmt(l, &b, f, ap);
	va_end(ap);
	return sr_bufstr(&b);
}

/* emit: indent, the line, "\n" */
static void emit(lowerer *l, const char *f, ...)
{
	sr_putstr(l->b, l->indent);
	va_list ap;
	va_start(ap, f);
	vfmt(l, l->b, f, ap);
	va_end(ap);
	sr_putc(l->b, '\n');
}

/* a Go error: the first one is kept (Go returns at once; every caller passes it up) */
static int fail(lowerer *l, const char *f, ...)
{
	if (!l->failed) {
		va_list ap;
		va_start(ap, f);
		vfmt(l, &l->err, f, ap);
		va_end(ap);
		l->failed = 1;
	}
	return -1;
}

static sr_str val(lowerer *l)
{
	sr_str v = S(l, "%%v%d", *l->n);
	(*l->n)++;
	return v;
}

static sr_str cat(sr_str a, const char *b)
{
	sr_buf o = {0};
	sr_putstr(&o, a);
	sr_puts(&o, b);
	return sr_bufstr(&o);
}

static int is(sr_str s, const char *c) { return sr_eqc(s, c); }

/* (*big.Int).Int64: the low 64 bits, negated for a negative value */
static int64_t big_int64(const bigint *x)
{
	if (!x || x->n == 0)
		return 0;
	uint64_t v = x->l[0];
	if (x->n > 1)
		v |= (uint64_t)x->l[1] << 32;
	if (x->neg)
		v = -v;
	return (int64_t)v;
}
static int big_sign(const bigint *x) { return !x || x->n == 0 ? 0 : x->neg ? -1 : 1; }

static const sv SV0 = {{"", 0}, ""};
static sv mk(sr_str name, const char *ty) { return (sv){name, ty}; }

/* ---- types (lower.go mapType, keyType, valueType) ---- */
static sr_str value_type(lowerer *l, const fe_map_decl *m)
{
	if (m->record)
		return fe_record_decl_mlir_type(m->record);
	return S(l, "i%d", m->value_bits);
}
static sr_str key_type(lowerer *l, const fe_map_decl *m)
{
	if (m->key_record)
		return fe_record_decl_mlir_type(m->key_record);
	if (fe_map_is_array(m) || fe_map_is_devmap(m) || is(m->kind, "sockmap"))
		return sr_cstr("i32");
	return S(l, "i%d", m->key_bits);
}
static sr_str map_type(lowerer *l, const fe_map_decl *m)
{
	return S(l, "!ebpf.map<%q, %S, %S>", fe_map_kind(m), key_type(l, m), value_type(l, m));
}

/* i32Text */
static sr_str i32_text(lowerer *l, int64_t v)
{
	if (v >= (int64_t)1 << 31)
		v = (int64_t)(int32_t)(uint32_t)v;
	return S(l, "%d", v);
}

static const char *ext_of(int is_signed) { return is_signed ? "arith.extsi" : "arith.extui"; }

static int expr(lowerer *l, const fe_expr *e, sv *out);
static int stmts(lowerer *l, const fe_stmts *ss);
static int output_str(lowerer *l, fe_stmt s);

/* ---- expressions (lower.go expr) ---- */

/* the i64 result of a read of the given width: as is at 64 bits, else extended (signed by the declaration) */
static int widen(lowerer *l, sr_str v, int64_t bits, int is_signed, fe_pos p, sv *out)
{
	if (bits == 64) {
		*out = mk(v, "i64");
		return 0;
	}
	sr_str x = val(l);
	emit(l, "%S = %s %S : i%d to i64 %L", x, ext_of(is_signed), v, bits, p);
	*out = mk(x, "i64");
	return 0;
}

static int load_raw(lowerer *l, const fe_expr *e, sr_str *raw, int64_t *bits)
{
	borrow br;
	if (!bor_get(&l->refs, e->ref, &br))
		return fail(l, "internal: p.load outside the present region at %P", e->pos);
	sr_str v = val(l);
	emit(l, "%S = ebpf.ref.load %S : !ebpf.borrowed<i%d> -> i%d %L", v, br.name, br.bits, br.bits, e->pos);
	*raw = v;
	*bits = br.bits;
	return 0;
}

static sr_str index32(lowerer *l, sr_str x, fe_pos p)
{
	int ok;
	sv n = env_get(&l->narrow, x, &ok);
	if (ok)
		return n.name;
	sr_str t = val(l);
	emit(l, "%S = arith.trunci %S : i64 to i32 %L", t, x, p);
	return t;
}

static int binary(lowerer *l, const fe_expr *e, sv *out)
{
	sv a, b;
	if (expr(l, e->args[0], &a) || expr(l, e->args[1], &b))
		return -1;
	fe_pos at = e->pos;
	static const char *const ops[][2] = {{"+", "arith.addi"}, {"-", "arith.subi"}, {"*", "arith.muli"}, {"&", "arith.andi"},
					     {"|", "arith.ori"},  {"^", "arith.xori"}, {"<<", "arith.shli"}, {">>", "arith.shrsi"}};
	const char *op = "";
	for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++)
		if (is(e->op, ops[i][0]))
			op = ops[i][1];
	if (is(e->op, ">>") && e->args[0]->wide)
		op = "arith.shrui";
	if (is(e->op, "/")) {
		op = is(e->div, "u") ? "arith.divui" : is(e->div, "floor") ? "arith.floordivsi" : "";
	} else if (is(e->op, "%")) {
		if (is(e->div, "u")) {
			op = "arith.remui";
		} else {
			const bigint *d = e->args[1]->lit;
			sr_str r = val(l), z = val(l), rnz = val(l), rbad = val(l), fix = val(l), rd = val(l), m = val(l);
			emit(l, "%S = arith.remsi %S, %S : i64 %L", r, a.name, b.name, at);
			emit(l, "%S = arith.constant 0 : i64 %L", z, at);
			emit(l, "%S = arith.cmpi ne, %S, %S : i64 %L", rnz, r, z, at);
			const char *pred = big_sign(d) < 0 ? "sgt" : "slt";
			emit(l, "%S = arith.cmpi %s, %S, %S : i64 %L", rbad, pred, r, z, at);
			emit(l, "%S = arith.andi %S, %S : i1 %L", fix, rnz, rbad, at);
			emit(l, "%S = arith.addi %S, %S : i64 %L", rd, r, b.name, at);
			emit(l, "%S = arith.select %S, %S, %S : i64 %L", m, fix, rd, r, at);
			*out = mk(m, "i64");
			return 0;
		}
	}
	if (!*op)
		return fail(l, "internal: operator %q", e->op);
	sr_str v = val(l);
	emit(l, "%S = %s %S, %S : i64 %L", v, op, a.name, b.name, at);
	*out = mk(v, "i64");
	return 0;
}

static int ring_output(lowerer *l, const fe_ring_decl *r, const fe_expr *mkx, fe_pos pos, int with_result, sv *out);
static int hash_status(lowerer *l, const fe_expr *e, sv *out);


/* ---- scx.go's lowering: the sched_ext ops, the SCX constants and the exit record ---- */

/* scxOperands: the Integer operands at the op's widths (an i32 operand is narrowed with one trunci); names and types in *vs / *tys */
static int scx_operands(lowerer *l, fe_expr *const *es, size_t n, const int *bits, fe_pos pos, sr_str *vs, const char **tys)
{
	for (size_t i = 0; i < n; i++) {
		sv x;
		if (expr(l, es[i], &x))
			return -1;
		sr_str v = x.name;
		if (bits[i] < 64) {
			v = val(l);
			emit(l, "%S = arith.trunci %S : i64 to i%d %L", v, x.name, (int64_t)bits[i], pos);
		}
		vs[i] = v;
		tys[i] = bits[i] == 32 ? "i32" : "i64";
	}
	return 0;
}

static sr_str scx_join(const sr_str *vs, size_t n)
{
	sr_buf b = {0};
	for (size_t i = 0; i < n; i++) {
		if (i)
			sr_puts(&b, ", ");
		sr_putstr(&b, vs[i]);
	}
	return sr_bufstr(&b);
}

static sr_str scx_join_c(const char *const *vs, size_t n)
{
	sr_buf b = {0};
	for (size_t i = 0; i < n; i++) {
		if (i)
			sr_puts(&b, ", ");
		sr_puts(&b, vs[i]);
	}
	return sr_bufstr(&b);
}

static void scx_bits(sr_str op, size_t n, int *bits)
{
	for (size_t i = 0; i < n; i++)
		bits[i] = sr_eqc(op, "error") ? 64 : fe_scx_op_bits(op, (int)i);
}

static int scx_stmt(lowerer *l, const fe_stmt *s)
{
	size_t n = s->n_scx_args;
	int bits[16];
	sr_str vs[16];
	const char *tys[16];
	scx_bits(s->op, n, bits);
	if (scx_operands(l, s->scx_args, n, bits, s->pos, vs, tys))
		return -1;
	if (sr_eqc(s->op, "error")) {
		if (n == 0)
			emit(l, "ebpf.scx.error %q () %L", s->path, s->pos);
		else
			emit(l, "ebpf.scx.error %q (%S) : %S %L", s->path, scx_join(vs, n), scx_join_c(tys, n), s->pos);
		return 0;
	}
	if (sr_eqc(s->op, "dsq_move_to_local")) { /* the Bool is dropped (whether a task was moved — not a status) */
		sr_str r = val(l);
		emit(l, "%S = ebpf.scx.dsq_move_to_local %S : i64 -> i1 %L", r, vs[0], s->pos);
		return 0;
	}
	emit(l, "ebpf.scx.%S %S, %S : !ebpf.kptr<%q>, %S %L", s->op, env_get(&l->env, s->var, NULL).name, scx_join(vs, n), s->kt->name,
	     scx_join_c(tys, n), s->pos);
	return 0;
}

static int scx_select(lowerer *l, const fe_stmt *s)
{
	int bits[2] = {32, 64};
	sr_str vs[2];
	const char *tys[2];
	if (scx_operands(l, s->scx_args, s->n_scx_args, bits, s->pos, vs, tys))
		return -1;
	sr_str r = val(l);
	emit(l, "%S:2 = ebpf.scx.select_cpu_dfl %S, %S, %S : !ebpf.kptr<%q>, i32, i64 -> i32, i1 %L", r, env_get(&l->env, s->var, NULL).name,
	     vs[0], vs[1], s->kt->name, s->pos);
	sr_str x = val(l);
	emit(l, "%S = arith.extsi %S#0 : i32 to i64 %L", x, r, s->pos);
	const char *comma = memchr(s->path.p, ',', s->path.n);
	sr_str cpu = {s->path.p, (size_t)(comma - s->path.p)}, idle = {comma + 1, s->path.n - (size_t)(comma - s->path.p) - 1};
	env_set(&l->env, cpu, mk(x, "i64"));
	env_set(&l->env, idle, mk(cat(r, "#1"), "i1"));
	return 0;
}

/* scxExit: the exit info argument, its check, and ebpf.scx.exit_info in the present region */
static void scx_exit(lowerer *l, const fe_stmt *s)
{
	sr_str n = val(l);
	emit(l, "%S = ebpf.ctx.arg %%ctx[0] : !ebpf.ctx<\"struct_ops\"> -> !ebpf.kptr_or_null<\"scx_exit_info\"> %L", n, s->pos);
	emit(l, "ebpf.kptr.check %S : !ebpf.kptr_or_null<\"scx_exit_info\"> present {", n);
	sr_str e = val(l);
	emit(l, "^present(%S: !ebpf.kptr<\"scx_exit_info\">):", e);
	emit(l, "  ebpf.scx.exit_info %S, @%S : !ebpf.kptr<\"scx_exit_info\"> %L", e, s->glob->name, s->pos);
	emit(l, "  ebpf.yield %L", s->pos);
	emit(l, "} absent {");
	emit(l, "  ebpf.yield %L", s->pos);
	emit(l, "} %L", s->pos);
}

static int scx_expr(lowerer *l, const fe_expr *e, sv *out)
{
	int bits[4];
	sr_str vs[4];
	const char *tys[4];
	scx_bits(e->op, e->n_args, bits);
	if (scx_operands(l, e->args, e->n_args, bits, e->pos, vs, tys))
		return -1;
	sr_str r = val(l);
	if (sr_eqc(e->op, "dsq_move_to_local")) {
		emit(l, "%S = ebpf.scx.dsq_move_to_local %S : i64 -> i1 %L", r, vs[0], e->pos);
		*out = mk(r, "i1");
		return 0;
	}
	emit(l, "%S = ebpf.scx.create_dsq %S : %S -> i32 %L", r, scx_join(vs, e->n_args), scx_join_c(tys, e->n_args), e->pos);
	sr_str x = val(l);
	emit(l, "%S = arith.extsi %S : i32 to i64 %L", x, r, e->pos);
	*out = mk(x, "i64");
	return 0;
}

static int expr(lowerer *l, const fe_expr *e, sv *out)
{
	sr_str k = e->kind;
	if (is(k, "lit")) {
		sr_str v = val(l);
		emit(l, "%S = arith.constant %B : i64 %L", v, e->lit, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "blit")) {
		sr_str v = val(l);
		emit(l, "%S = arith.constant %s %L", v, e->b ? "true" : "false", e->pos);
		*out = mk(v, "i1");
		return 0;
	}
	if (is(k, "var")) {
		int ok;
		sv s = env_get(&l->env, e->var, &ok);
		if (!ok)
			return fail(l, "internal: local %S has no value at %P", e->var, e->pos);
		*out = s;
		return 0;
	}
	if (is(k, "load")) {
		sr_str raw;
		int64_t bits;
		if (load_raw(l, e, &raw, &bits))
			return -1;
		if (bits == 64) {
			*out = mk(raw, "i64");
			return 0;
		}
		sr_str v = val(l);
		emit(l, "%S = %s %S : i32 to i64 %L", v, ext_of(e->map->is_signed), raw, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "ringout"))
		return ring_output(l, e->ring, e->args[0], e->pos, 1, out);
	if (is(k, "hstatus"))
		return hash_status(l, e, out);
	if (is(k, "ktime")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.ktime.ns : i64 %L", v, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "scx")) /* dsq_move_to_local / create_dsq as values */
		return scx_expr(l, e, out);
	if (is(k, "u64op")) { /* a u64 intrinsic (i64 operations without nsw / nuw / exact flags; u64ops.go u64Expr) */
		sv a, b;
		if (expr(l, e->args[0], &a) || expr(l, e->args[1], &b))
			return -1;
		sr_str v = val(l);
		if (is(e->op, "u64_add") || is(e->op, "u64_sub") || is(e->op, "u64_mul")) {
			const char *op = is(e->op, "u64_add") ? "arith.addi" : is(e->op, "u64_sub") ? "arith.subi" : "arith.muli";
			emit(l, "%S = %s %S, %S : i64 %L", v, op, a.name, b.name, e->pos);
			*out = mk(v, "i64");
			return 0;
		}
		if (is(e->op, "time_before")) { /* (s64)(a − b) < 0 */
			sr_str z = val(l);
			emit(l, "%S = arith.subi %S, %S : i64 %L", v, a.name, b.name, e->pos);
			emit(l, "%S = arith.constant 0 : i64 %L", z, e->pos);
			sr_str r = val(l);
			emit(l, "%S = arith.cmpi slt, %S, %S : i64 %L", r, v, z, e->pos);
			*out = mk(r, "i1");
			return 0;
		}
		if (is(e->op, "u64_div")) { /* maxui serves bpf-mlir's ArithLegality proof; the identity on the divisor the frontend proved >= 1 */
			emit(l, "%S = arith.constant 1 : i64 %L", v, e->pos);
			sr_str d = val(l);
			emit(l, "%S = arith.maxui %S, %S : i64 %L", d, b.name, v, e->pos);
			sr_str q = val(l);
			emit(l, "%S = arith.divui %S, %S : i64 %L", q, a.name, d, e->pos);
			*out = mk(q, "i64");
			return 0;
		}
		return fail(l, "u64 intrinsic %q has no lowering", e->op);
	}
	if (is(k, "scxconst")) { /* an SCX constant (its i64 bit pattern, resolved at load) */
		sr_str v = val(l);
		emit(l, "%S = ebpf.scx.const %q : i64 %L", v, e->path, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "gload")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.global.load @%S : i%d %L", v, e->glob->name, e->glob->bits, e->pos);
		return widen(l, v, e->glob->bits, e->glob->is_signed, e->pos, out);
	}
	if (is(k, "call")) {
		sr_buf as = {0}, tys = {0};
		for (size_t i = 0; i < e->n_args; i++) {
			const fe_expr *a = e->args[i];
			if (i) {
				sr_puts(&as, ", ");
				sr_puts(&tys, ", ");
			}
			if (is(a->kind, "winarg")) {
				borrow wb;
				if (!bor_get(&l->wins, a->ref, &wb))
					return fail(l, "internal: window %S outside its in_range region at %P", a->ref, a->pos);
				sr_putstr(&as, wb.name);
				wr(l, &tys, "!ebpf.pkt_window<%d>", a->len);
				continue;
			}
			if (is(a->kind, "ctxarg")) {
				sr_puts(&as, "%ctx");
				wr(l, &tys, "!ebpf.ctx<%q>", a->var);
				continue;
			}
			if (is(a->kind, "refarg")) {
				borrow br;
				if (!bor_get(&l->refs, a->ref, &br))
					return fail(l, "internal: borrowed %S outside its present region at %P", a->ref, a->pos);
				sr_putstr(&as, br.name);
				wr(l, &tys, "!ebpf.borrowed<%S>", value_type(l, a->map));
				continue;
			}
			sv x;
			if (expr(l, a, &x))
				return -1;
			sr_putstr(&as, x.name);
			sr_puts(&tys, "i64");
		}
		sr_str v = val(l);
		emit(l, "%S = ebpf.call @%S(%S) : (%S) -> i64 %L", v, e->var, sr_bufstr(&as), sr_bufstr(&tys), e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "pidtgid")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.task.pid_tgid : i64 %L", v, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "kaddr")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.kptr.addr %S : !ebpf.kptr<%q> -> i64 %L", v, env_get(&l->env, e->var, NULL).name, e->path, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "kfload")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.kfield.load %S %q : !ebpf.kptr<%q> -> i%d %L", v, env_get(&l->env, e->var, NULL).name, e->field->name,
		     e->path, e->field->bits, e->pos);
		return widen(l, v, e->field->bits, e->field->is_signed, e->pos, out);
	}
	if (is(k, "tpfield")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.tp.field %%ctx %q [%d] : !ebpf.ctx<%q> -> i%d %L", v, e->field->name, e->idx, l->kind, e->field->bits,
		     e->pos);
		return widen(l, v, e->field->bits, e->field->is_signed, e->pos, out);
	}
	if (is(k, "rawarg")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.ctx.field %%ctx \"args\"[%d] : !ebpf.ctx<%q> -> i64 %L", v, e->idx, l->kind, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "kretval")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.probe.retval %%ctx : !ebpf.ctx<%q> -> i%d %L", v, l->kind, e->field->bits, e->pos);
		return widen(l, v, e->field->bits, e->field->is_signed, e->pos, out);
	}
	if (is(k, "fkload")) {
		sr_str v = val(l);
		sr_str idx = {"", 0};
		if (e->idx >= 0)
			idx = S(l, "[%d]", e->idx);
		emit(l, "%S = ebpf.flow_keys.load %%ctx %q%S : !ebpf.ctx<\"flow_dissector\"> -> i%d %L", v, e->field->name, idx,
		     e->field->bits, e->pos);
		sr_str x = val(l);
		emit(l, "%S = arith.extui %S : i%d to i64 %L", x, v, e->field->bits, e->pos);
		*out = mk(x, "i64");
		return 0;
	}
	if (is(k, "adjt")) {
		sr_str c = val(l);
		emit(l, "%S = arith.constant %d : i32 %L", c, e->idx, e->pos);
		sr_str v = val(l);
		emit(l, "%S = ebpf.xdp.adjust_tail %%ctx, %S : !ebpf.ctx<\"xdp\"> -> i64 %L", v, c, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "adjh")) {
		sv d;
		if (expr(l, e->args[0], &d))
			return -1;
		sr_str t = val(l);
		emit(l, "%S = arith.trunci %S : i64 to i32 %L", t, d.name, e->pos);
		sr_str v = val(l);
		emit(l, "%S = ebpf.xdp.adjust_head %%ctx, %S : !ebpf.ctx<\"xdp\"> -> i64 %L", v, t, e->pos);
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "ctxfield")) {
		sr_str v = val(l);
		emit(l, "%S = ebpf.ctx.field %%ctx %q : !ebpf.ctx<%q> -> i%d %L", v, e->field->name, l->kind, e->field->bits, e->pos);
		sr_str x = val(l);
		emit(l, "%S = arith.extui %S : i%d to i64 %L", x, v, e->field->bits, e->pos);
		*out = mk(x, "i64");
		return 0;
	}
	if (is(k, "retval") || is(k, "kparg")) {
		sr_str v = val(l);
		if (is(k, "retval"))
			emit(l, "%S = ebpf.ctx.retval %%ctx after %d : !ebpf.ctx<\"fexit\"> -> i%d %L", v, e->idx, e->field->bits, e->pos);
		else if (is(l->kind, "tp_btf") || is(l->kind, "fentry") || is(l->kind, "fmod_ret") || is(l->kind, "struct_ops"))
			emit(l, "%S = ebpf.ctx.arg %%ctx[%d] : !ebpf.ctx<%q> -> i%d %L", v, e->idx, l->kind, e->field->bits, e->pos);
		else if (is(l->kind, "ksyscall"))
			emit(l, "%S = ebpf.ksyscall.arg %%ctx %d : !ebpf.ctx<\"ksyscall\"> -> i%d %L", v, e->idx, e->field->bits, e->pos);
		else if (is(l->kind, "uprobe"))
			emit(l, "%S = ebpf.uprobe.arg %%ctx %d : !ebpf.ctx<\"uprobe\"> -> i%d %L", v, e->idx, e->field->bits, e->pos);
		else
			emit(l, "%S = ebpf.kprobe.arg %%ctx %d : !ebpf.ctx<\"kprobe\"> -> i%d %L", v, e->idx, e->field->bits, e->pos);
		return widen(l, v, e->field->bits, e->field->is_signed, e->pos, out);
	}
	if (is(k, "fload")) {
		borrow br;
		if (!bor_get(&l->refs, e->ref, &br))
			return fail(l, "internal: %S.load.%S outside the present region at %P", e->ref, e->field->name, e->pos);
		sr_str v = val(l);
		sr_str path = e->field->name;
		if (e->path.n)
			path = e->path;
		emit(l, "%S = ebpf.ref.field.load %S %q : !ebpf.borrowed<%S> -> i%d %L", v, br.name, path,
		     fe_record_decl_mlir_type(e->map->record), e->field->bits, e->pos);
		return widen(l, v, e->field->bits, e->field->is_signed, e->pos, out);
	}
	if (is(k, "iload")) {
		borrow br;
		if (!bor_get(&l->refs, e->ref, &br))
			return fail(l, "internal: %S.load.%S[\xe2\x80\xa6] outside the present region at %P", e->ref, e->field->name, e->pos);
		sv ix;
		if (expr(l, e->args[0], &ix))
			return -1;
		sr_str t = index32(l, ix.name, e->pos);
		sr_str r = val(l), el = val(l), v = val(l), z = val(l);
		sr_str w = S(l, "i%d", e->field->bits);
		sr_str rt = fe_record_decl_mlir_type(e->map->record);
		emit(l, "%S = ebpf.ref.index %S %q [%S] : !ebpf.borrowed<%S>, i32 -> %S in_range {", r, br.name, e->field->name, t, rt, w);
		emit(l, "^bb0(%S: !ebpf.elem<%S>):", el, w);
		emit(l, "  %S = ebpf.elem.load %S : !ebpf.elem<%S> -> %S %L", v, el, w, w, e->pos);
		emit(l, "  ebpf.yield %S : %S %L", v, w, e->pos);
		emit(l, "} out_of_range {");
		emit(l, "  // unreachable \xe2\x80\x94 the index range is [0, %d] (proved by the frontend)", e->field->count - 1);
		emit(l, "  %S = arith.constant 0 : %S %L", z, w, e->pos);
		emit(l, "  ebpf.yield %S : %S %L", z, w, e->pos);
		emit(l, "} %L", e->pos);
		if (e->field->bits == 64) {
			*out = mk(r, "i64");
			return 0;
		}
		sr_str x = val(l);
		emit(l, "%S = %s %S : %S to i64 %L", x, ext_of(e->field->is_signed), r, w, e->pos);
		*out = mk(x, "i64");
		return 0;
	}
	if (is(k, "wload")) {
		borrow w;
		if (!bor_get(&l->wins, e->ref, &w))
			return fail(l, "internal: %S.%S outside the in-range region at %P", e->ref, e->op, e->pos);
		int64_t n = 0;
		fe_window_read_len(e->op, &n);
		int64_t bits = n * 8;
		sr_str v = val(l);
		emit(l, "%S = ebpf.packet.window_load %S[%d] : !ebpf.pkt_window<%d> -> i%d %L", v, w.name, e->idx, w.bits, bits, e->pos);
		if (bits > 8 && e->op.n >= 2 && memcmp(e->op.p, "be", 2) == 0) {
			sr_str b = val(l);
			emit(l, "%S = ebpf.byteorder.from_be %S : i%d %L", b, v, bits, e->pos);
			v = b;
		}
		sr_str x = val(l);
		emit(l, "%S = arith.extui %S : i%d to i64 %L", x, v, bits, e->pos);
		*out = mk(x, "i64");
		return 0;
	}
	if (is(k, "un")) {
		sv x;
		if (expr(l, e->args[0], &x))
			return -1;
		sr_str c = val(l), v = val(l);
		if (is(e->op, "-@")) {
			emit(l, "%S = arith.constant 0 : i64 %L", c, e->pos);
			emit(l, "%S = arith.subi %S, %S : i64 %L", v, c, x.name, e->pos);
		} else {
			emit(l, "%S = arith.constant -1 : i64 %L", c, e->pos);
			emit(l, "%S = arith.xori %S, %S : i64 %L", v, x.name, c, e->pos);
		}
		*out = mk(v, "i64");
		return 0;
	}
	if (is(k, "bin"))
		return binary(l, e, out);
	if (is(k, "cmp")) {
		sv a, b;
		if (expr(l, e->args[0], &a) || expr(l, e->args[1], &b))
			return -1;
		static const char *const preds[][2] = {{"==", "eq"}, {"!=", "ne"}, {"<", "slt"}, {"<=", "sle"}, {">", "sgt"}, {">=", "sge"}};
		const char *pred = "";
		for (size_t i = 0; i < sizeof preds / sizeof preds[0]; i++)
			if (is(e->op, preds[i][0]))
				pred = preds[i][1];
		sr_str v = val(l);
		emit(l, "%S = arith.cmpi %s, %S, %S : i64 %L", v, pred, a.name, b.name, e->pos);
		*out = mk(v, "i1");
		return 0;
	}
	if (is(k, "and") || is(k, "or")) {
		sv a, b;
		if (expr(l, e->args[0], &a) || expr(l, e->args[1], &b))
			return -1;
		sr_str v = val(l);
		emit(l, "%S = %s %S, %S : i1 %L", v, is(k, "and") ? "arith.andi" : "arith.ori", a.name, b.name, e->pos);
		*out = mk(v, "i1");
		return 0;
	}
	if (is(k, "not")) {
		sv a;
		if (expr(l, e->args[0], &a))
			return -1;
		sr_str t = val(l), v = val(l);
		emit(l, "%S = arith.constant true %L", t, e->pos);
		emit(l, "%S = arith.xori %S, %S : i1 %L", v, a.name, t, e->pos);
		*out = mk(v, "i1");
		return 0;
	}
	if (is(k, "sel")) {
		sv c, a, b;
		if (expr(l, e->args[0], &c) || expr(l, e->args[1], &a) || expr(l, e->args[2], &b))
			return -1;
		sr_str v = val(l);
		emit(l, "%S = arith.select %S, %S, %S : %s %L", v, c.name, a.name, b.name, a.ty, e->pos);
		*out = mk(v, a.ty);
		return 0;
	}
	return fail(l, "internal: expression kind %q", e->kind);
}

/* ---- operands (lower.go mapKey, keyOperand, valueOperand, fieldOperand) ---- */
static int key_operand(lowerer *l, const fe_expr *e, sr_str *out)
{
	if (is(e->kind, "lit")) {
		sr_str v = val(l);
		emit(l, "%S = arith.constant %S : i32 %L", v, i32_text(l, big_int64(e->lit)), e->pos);
		*out = v;
		return 0;
	}
	sv x;
	if (expr(l, e, &x))
		return -1;
	sr_str v = val(l);
	emit(l, "%S = arith.trunci %S : i64 to i32 %L", v, x.name, e->pos);
	*out = v;
	return 0;
}

static int value_operand(lowerer *l, const fe_expr *e, const fe_map_decl *m, sr_str *out);

static int map_key(lowerer *l, const fe_expr *e, const fe_map_decl *m, sr_str *out)
{
	if (fe_map_is_array(m) || (!m->key_record && m->key_bits == 32))
		return key_operand(l, e, out);
	if (m->key_record)
		return value_operand(l, e, e->map, out);
	if (is(e->kind, "lit")) {
		sr_str v = val(l);
		emit(l, "%S = arith.constant %B : i64 %L", v, e->lit, e->pos);
		*out = v;
		return 0;
	}
	sv x;
	int rc = expr(l, e, &x);
	*out = x.name;
	return rc;
}

static int field_operand(lowerer *l, const fe_expr *e, const fe_record_field *f, sr_str *out)
{
	if (is(e->kind, "lit")) {
		sr_str v = val(l);
		int64_t lit = big_int64(e->lit);
		if (!f->is_signed && f->bits < 64 && lit >= (int64_t)1 << (f->bits - 1))
			lit -= (int64_t)1 << f->bits;
		emit(l, "%S = arith.constant %d : i%d %L", v, lit, f->bits, e->pos);
		*out = v;
		return 0;
	}
	if (is(e->kind, "fload") && e->field->bits == f->bits) {
		borrow br;
		bor_get(&l->refs, e->ref, &br);
		sr_str v = val(l);
		emit(l, "%S = ebpf.ref.field.load %S %q : !ebpf.borrowed<%S> -> i%d %L", v, br.name, e->field->name,
		     fe_record_decl_mlir_type(e->map->record), e->field->bits, e->pos);
		*out = v;
		return 0;
	}
	if (is(e->kind, "load") && e->map->value_bits == f->bits) {
		int64_t bits;
		return load_raw(l, e, out, &bits);
	}
	sv x;
	if (expr(l, e, &x))
		return -1;
	if (f->bits == 64) {
		*out = x.name;
		return 0;
	}
	sr_str v = val(l);
	emit(l, "%S = arith.trunci %S : i64 to i%d %L", v, x.name, f->bits, e->pos);
	*out = v;
	return 0;
}

static int value_operand(lowerer *l, const fe_expr *e, const fe_map_decl *m, sr_str *out)
{
	if (is(e->kind, "rmake")) {
		sr_buf nm = {0}, vs = {0}, ts = {0};
		size_t cnt = 0;
#define SEP()                                                                                                                      \
	do {                                                                                                                       \
		if (cnt++) {                                                                                                       \
			sr_puts(&nm, ", ");                                                                                        \
			sr_puts(&vs, ", ");                                                                                        \
			sr_puts(&ts, ", ");                                                                                        \
		}                                                                                                                  \
	} while (0)
		const fe_record_decl *rec = m->record;
		for (size_t i = 0; i < rec->n_fields; i++) {
			const fe_record_field *f = &rec->fields[i];
			if (f->pad)
				continue;
			const fe_expr *a = e->args[i];
			if (is(a->kind, "zarr")) {
				sr_str z = val(l);
				emit(l, "%S = arith.constant 0 : i%d %L", z, f->bits, a->pos);
				for (int64_t k = 0; k < f->count; k++) {
					SEP();
					wr(l, &nm, "%q", S(l, "%S[%d]", f->name, k));
					sr_putstr(&vs, z);
					wr(l, &ts, "i%d", f->bits);
				}
				continue;
			}
			if (is(a->kind, "earr")) {
				fe_record_field el = {f->name, f->bits, f->is_signed, 0, 0, 0};
				for (size_t k = 0; k < a->n_args; k++) {
					sr_str v;
					if (field_operand(l, a->args[k], &el, &v))
						return -1;
					SEP();
					wr(l, &nm, "%q", S(l, "%S[%d]", f->name, (int64_t)k));
					sr_putstr(&vs, v);
					wr(l, &ts, "i%d", f->bits);
				}
				continue;
			}
			sr_str v;
			if (field_operand(l, a, f, &v))
				return -1;
			SEP();
			wr(l, &nm, "%q", f->name);
			sr_putstr(&vs, v);
			wr(l, &ts, "i%d", f->bits);
		}
#undef SEP
		sr_str r = val(l);
		emit(l, "%S = ebpf.record.make [%S] (%S) : (%S) -> %S %L", r, sr_bufstr(&nm), sr_bufstr(&vs), sr_bufstr(&ts),
		     fe_record_decl_mlir_type(rec), e->pos);
		*out = r;
		return 0;
	}
	if (is(e->kind, "lit")) {
		sr_str v = val(l);
		int64_t lit = big_int64(e->lit);
		sr_str txt = m->value_bits == 32 ? i32_text(l, lit) : S(l, "%d", lit);
		emit(l, "%S = arith.constant %S : i%d %L", v, txt, m->value_bits, e->pos);
		*out = v;
		return 0;
	}
	if (is(e->kind, "load") && e->map->value_bits == m->value_bits) {
		int64_t bits;
		return load_raw(l, e, out, &bits);
	}
	sv x;
	if (expr(l, e, &x))
		return -1;
	if (m->value_bits == 64) {
		*out = x.name;
		return 0;
	}
	sr_str v = val(l);
	emit(l, "%S = arith.trunci %S : i64 to i32 %L", v, x.name, e->pos);
	*out = v;
	return 0;
}

/* ---- ring output (lower.go ringOutput) ---- */
static int ring_output(lowerer *l, const fe_ring_decl *r, const fe_expr *mkx, fe_pos pos, int with_result, sv *out)
{
	sr_str rec = fe_record_decl_mlir_type(r->record);
	sr_str rv = val(l);
	emit(l, "%S = ebpf.ringbuf.reserve %q : !ebpf.maybe_reservation<%S> %L", rv, r->name, rec, pos);
	sr_str ok = {"", 0};
	if (with_result)
		ok = val(l);
	sr_str res = val(l);
	sr_buf b = {0};
	sr_buf *saved = l->b;
	sr_str saved_indent = l->indent;
	l->b = &b;
	l->indent = cat(l->indent, "  ");
	fe_map_decl tmp;
	memset(&tmp, 0, sizeof tmp);
	tmp.name = r->name;
	tmp.record = r->record;
	sr_str v;
	if (value_operand(l, mkx, &tmp, &v)) {
		l->b = saved;
		l->indent = saved_indent;
		return -1;
	}
	emit(l, "ebpf.ringbuf.store_record %S, %S : !ebpf.reservation<%S>, %S %L", res, v, rec, rec, pos);
	for (size_t i = 0; i < mkx->n_args; i++) {
		const fe_expr *a = mkx->args[i];
		if (is(a->kind, "zarr") && a->var.n)
			emit(l, "ebpf.kfield.copy %S %q, %S %q : !ebpf.kptr<%q>, !ebpf.reservation<%S> %L", env_get(&l->env, a->var, NULL).name,
			     a->path, res, a->field->name, a->op, rec, a->pos);
		if (is(a->kind, "zarr") && a->tp_copy)
			emit(l, "ebpf.tp.field.copy %S %q, %%ctx %q [%d] : !ebpf.reservation<%S>, !ebpf.ctx<\"tracepoint\"> %L", res,
			     a->field->name, a->tp_copy->name, a->tp_copy->offset, rec, a->pos);
	}
	emit(l, "ebpf.ringbuf.submit %S : !ebpf.reservation<%S> %L", res, rec, pos);
	if (with_result) {
		sr_str t = val(l);
		emit(l, "%S = arith.constant true %L", t, pos);
		emit(l, "ebpf.yield %S : i1 %L", t, pos);
	} else {
		emit(l, "ebpf.yield %L", pos);
	}
	sr_str present = sr_bufstr(&b);
	sr_buf ab = {0};
	l->b = &ab;
	if (with_result) {
		sr_str f = val(l);
		emit(l, "%S = arith.constant false %L", f, pos);
		emit(l, "ebpf.yield %S : i1 %L", f, pos);
	} else {
		emit(l, "ebpf.yield %L", pos);
	}
	sr_str absent = sr_bufstr(&ab);
	l->b = saved;
	l->indent = saved_indent;
	const char *decl = with_result ? " -> i1" : "";
	sr_str head = with_result ? cat(ok, " = ") : (sr_str){"", 0};
	emit(l, "%Sebpf.ringbuf.if_reserved %S : !ebpf.maybe_reservation<%S>%s present {", head, rv, rec, decl);
	emit(l, "^present(%S: !ebpf.reservation<%S>):", res, rec);
	sr_putstr(l->b, present);
	emit(l, "} absent {");
	sr_putstr(l->b, absent);
	emit(l, "} %L", pos);
	*out = mk(ok, "i1");
	return 0;
}

/* ---- regions (lower.go arm, results, regionTypes, yieldText, bindResults, resultDecl, armResults) ---- */
static int arm(lowerer *l, const fe_stmts *ss, const env *pre, sr_str indent, sr_str *text, env *after)
{
	sr_buf b = {0};
	sr_buf *saved = l->b;
	sr_str saved_indent = l->indent;
	l->b = &b;
	l->indent = indent;
	l->env = env_copy(pre);
	int rc = stmts(l, ss);
	*after = l->env;
	l->b = saved;
	l->indent = saved_indent;
	*text = sr_bufstr(&b);
	return rc;
}

static int cmp_names(const void *a, const void *b) { return sr_cmp(*(const sr_str *)a, *(const sr_str *)b); }

static names results(const env *pre, const env *a, const env *b)
{
	names o = {sr_alloc((a->n + 1) * sizeof(sr_str)), 0};
	for (size_t i = 0; i < a->n; i++) {
		sr_str k = a->e[i].k;
		sv va = a->e[i].v;
		int okb, okp;
		sv vb = env_get(b, k, &okb);
		if (!okb)
			continue;
		sv p = env_get(pre, k, &okp);
		if (okp && sv_eq(p, va) && sv_eq(p, vb))
			continue;
		o.v[o.n++] = k;
	}
	qsort(o.v, o.n, sizeof o.v[0], cmp_names);
	return o;
}

static names arm_results(const env *pre, const env *a, const env *b, int esc_a, int esc_b, const env **ty_env)
{
	if (esc_a && esc_b) {
		*ty_env = a;
		return (names){NULL, 0};
	}
	if (esc_a) {
		*ty_env = b;
		return results(pre, b, b);
	}
	if (esc_b) {
		*ty_env = a;
		return results(pre, a, a);
	}
	*ty_env = a;
	return results(pre, a, b);
}

/* regionTypes: the declaration text and the types */
static sr_str region_types(names vars, const env *e, const char ***tys)
{
	*tys = sr_alloc((vars.n + 1) * sizeof(char *));
	for (size_t i = 0; i < vars.n; i++)
		(*tys)[i] = env_get(e, vars.v[i], NULL).ty;
	if (vars.n == 0)
		return (sr_str){"", 0};
	sr_buf b = {0};
	sr_puts(&b, " -> ");
	for (size_t i = 0; i < vars.n; i++) {
		if (i)
			sr_puts(&b, ", ");
		sr_puts(&b, (*tys)[i]);
	}
	return sr_bufstr(&b);
}

static sr_str yield_text(const char *op, names vars, const env *e, const char **tys)
{
	if (vars.n == 0)
		return sr_cstr(op);
	sr_buf b = {0};
	sr_puts(&b, op);
	sr_putc(&b, ' ');
	for (size_t i = 0; i < vars.n; i++) {
		if (i)
			sr_puts(&b, ", ");
		sr_putstr(&b, env_get(e, vars.v[i], NULL).name);
	}
	sr_puts(&b, " : ");
	for (size_t i = 0; i < vars.n; i++) {
		if (i)
			sr_puts(&b, ", ");
		sr_puts(&b, tys[i]);
	}
	return sr_bufstr(&b);
}

static void bind_results(lowerer *l, sr_str res, names vars, const char **tys)
{
	for (size_t i = 0; i < vars.n; i++) {
		sr_str name = res;
		if (vars.n > 1)
			name = S(l, "%S#%d", res, (int64_t)i);
		env_set(&l->env, vars.v[i], mk(name, tys[i]));
	}
}

static sr_str result_decl(lowerer *l, sr_str res, size_t n)
{
	if (n == 0)
		return (sr_str){"", 0};
	if (n == 1)
		return cat(res, " = ");
	return S(l, "%S:%d = ", res, (int64_t)n);
}

/* the common shape of if, kptr.check and ref.check: two arms lowered, the results joined */
typedef struct {
	sr_str then_text, else_text;
	env then_env, else_env;
	int esc_t, esc_e;
	names vars;
	sr_str decl;
	const char **tys;
	sr_str res;
} region;

static void region_join(lowerer *l, region *g, const env *pre, const fe_stmt *s)
{
	l->env = *pre;
	g->esc_t = fe_escapes(&s->then);
	g->esc_e = fe_escapes(&s->else_);
	const env *ty_env;
	g->vars = arm_results(pre, &g->then_env, &g->else_env, g->esc_t, g->esc_e, &ty_env);
	g->decl = region_types(g->vars, ty_env, &g->tys);
	g->res = (sr_str){"", 0};
	if (g->vars.n > 0)
		g->res = val(l);
}

static void region_arms(lowerer *l, region *g, const char *yield, fe_pos ypos, fe_pos pos, const char *mid)
{
	sr_putstr(l->b, g->then_text);
	if (!g->esc_t)
		emit(l, "  %S %L", yield_text(yield, g->vars, &g->then_env, g->tys), ypos);
	emit(l, "%s", mid);
	sr_putstr(l->b, g->else_text);
	if (!g->esc_e)
		emit(l, "  %S %L", yield_text(yield, g->vars, &g->else_env, g->tys), ypos);
	emit(l, "} %L", pos);
	bind_results(l, g->res, g->vars, g->tys);
}

/* ---- loops (lower.go loop) ---- */
static int loop(lowerer *l, const fe_stmt *s)
{
	sr_str bnd = {"", 0};
	if (s->bound) {
		sv x;
		if (expr(l, s->bound, &x))
			return -1;
		sr_str v = x.name;
		if (s->incl) {
			sr_str one = val(l), sum = val(l);
			emit(l, "%S = arith.constant 1 : i64 %L", one, s->pos);
			emit(l, "%S = arith.addi %S, %S : i64 %L", sum, v, one, s->pos);
			v = sum;
		}
		if (s->clamp) {
			sr_str z = val(l), c = val(l), r = val(l);
			emit(l, "%S = arith.constant 0 : i64 %L", z, s->pos);
			emit(l, "%S = arith.cmpi slt, %S, %S : i64 %L", c, v, z, s->pos);
			emit(l, "%S = ebpf.if %S -> i64 {", r, c);
			emit(l, "  ebpf.if.yield %S : i64 %L", z, s->pos);
			emit(l, "} else {");
			emit(l, "  ebpf.if.yield %S : i64 %L", v, s->pos);
			emit(l, "} %L", s->pos);
			v = r;
		}
		sr_str t = val(l);
		emit(l, "%S = arith.trunci %S : i64 to i32 %L", t, v, s->pos);
		bnd = S(l, " bound(%S)", t);
	}
	env pre = env_copy(&l->env);
	names carried = {s->carried, s->n_carried};
	const char **tys = sr_alloc((carried.n + 1) * sizeof(char *));
	sr_buf inits = {0}, params = {0};
	for (size_t i = 0; i < carried.n; i++) {
		int ok;
		sv v = env_get(&pre, carried.v[i], &ok);
		if (!ok || strcmp(v.ty, "i64") != 0)
			return fail(l, "internal: loop value %S is not an i64 local at %P", carried.v[i], s->pos);
		if (i)
			sr_puts(&inits, ", ");
		sr_putstr(&inits, v.name);
		tys[i] = "i64";
	}
	sr_str iv = val(l);
	env body = env_copy(&pre);
	for (size_t i = 0; i < carried.n; i++) {
		sr_str a = val(l);
		sr_puts(&params, ", ");
		sr_putstr(&params, a);
		sr_puts(&params, ": i64");
		env_set(&body, carried.v[i], mk(a, "i64"));
	}
	sr_str res = {"", 0};
	if (carried.n > 0)
		res = val(l);
	sr_buf b = {0};
	sr_buf *saved = l->b;
	sr_str saved_indent = l->indent;
	l->b = &b;
	l->indent = cat(l->indent, "  ");
	l->env = body;
	if (s->var.n) {
		sr_str x = val(l);
		emit(l, "%S = arith.extui %S : i32 to i64 %L", x, iv, s->pos);
		env_set(&l->env, s->var, mk(x, "i64"));
		env_set(&l->narrow, x, mk(iv, ""));
	}
	if (l->n_loops == l->cap_loops) {
		size_t nc = l->cap_loops ? l->cap_loops * 2 : 4;
		l->loops = sr_grow(l->loops, l->cap_loops * sizeof *l->loops, nc * sizeof *l->loops);
		l->cap_loops = nc;
	}
	l->loops[l->n_loops++] = carried;
	int rc = stmts(l, &s->then);
	l->n_loops--;
	env end = l->env;
	l->b = saved;
	l->indent = saved_indent;
	if (rc)
		return rc;
	sr_str fn;
	if (carried.n == 0)
		fn = sr_cstr("() -> ()");
	else if (carried.n == 1)
		fn = sr_cstr("(i64) -> i64");
	else {
		sr_buf t = {0};
		for (size_t i = 0; i < carried.n; i++) {
			if (i)
				sr_puts(&t, ", ");
			sr_puts(&t, "i64");
		}
		fn = S(l, "(%S) -> (%S)", sr_bufstr(&t), sr_bufstr(&t));
	}
	emit(l, "%Sebpf.loop %d unroll%S (%S) : %S {", result_decl(l, res, carried.n), s->count, bnd, sr_bufstr(&inits), fn);
	emit(l, "^bb0(%S: i32%S):", iv, sr_bufstr(&params));
	sr_putstr(l->b, sr_bufstr(&b));
	emit(l, "  %S %L", yield_text("ebpf.loop.yield", carried, &end, tys), s->pos);
	emit(l, "} %L", s->pos);
	l->env = pre;
	bind_results(l, res, carried, tys);
	return 0;
}

/* ---- hash status (lower.go hashStatus) ---- */
static sr_str aoi_one(lowerer *l, const char *ind, sr_str mv, sr_str k, const fe_map_decl *m, sr_str kt, sr_str vt, sr_str v,
		      fe_pos at)
{
	sr_str r = val(l), res = val(l), b = val(l), z = val(l);
	emit(l, "%s%S = ebpf.map.lookup %S[%S] : %S, %S -> !ebpf.maybe_ref<%S> %L", ind, r, mv, k, map_type(l, m), kt, vt, at);
	emit(l, "%s%S = ebpf.ref.check %S : !ebpf.maybe_ref<%S> -> i64 present {", ind, res, r, vt);
	emit(l, "%s^present(%S: !ebpf.borrowed<%S>):", ind, b, vt);
	emit(l, "%s  ebpf.ref.atomic_add %S, %S : !ebpf.borrowed<%S>, %S %L", ind, b, v, vt, vt, at);
	emit(l, "%s  %S = arith.constant 0 : i64 %L", ind, z, at);
	emit(l, "%s  ebpf.yield %S : i64 %L", ind, z, at);
	emit(l, "%s} absent {", ind);
	return res;
}

static int hash_status(lowerer *l, const fe_expr *e, sv *out)
{
	const fe_map_decl *m = e->map;
	sr_str mv = map_name(l, m);
	sr_str k;
	if (map_key(l, e->args[0], m, &k))
		return -1;
	fe_pos at = e->pos;
	sr_str kt = key_type(l, m), vt = value_type(l, m);
	if (is(e->op, "delete")) {
		sr_str s = val(l);
		emit(l, "%S = ebpf.map.try_delete %S[%S] : %S, %S -> i64 %L", s, mv, k, map_type(l, m), kt, at);
		*out = mk(s, "i64");
		return 0;
	}
	sr_str v;
	if (value_operand(l, e->args[1], m, &v))
		return -1;
	if (!is(e->op, "add_or_init")) {
		sr_str s = val(l);
		emit(l, "%S = ebpf.map.try_update %S[%S], %S flags %q : %S, %S, %S -> i64 %L", s, mv, k, v, e->op, map_type(l, m), kt, vt, at);
		*out = mk(s, "i64");
		return 0;
	}
	sr_str res = aoi_one(l, "", mv, k, m, kt, vt, v, at);
	sr_str t = val(l), ee = val(l), c = val(l), u = val(l);
	emit(l, "  %S = ebpf.map.try_update %S[%S], %S flags \"noexist\" : %S, %S, %S -> i64 %L", t, mv, k, v, map_type(l, m), kt, vt, at);
	emit(l, "  %S = arith.constant -17 : i64 %L", ee, at);
	emit(l, "  %S = arith.cmpi eq, %S, %S : i64 %L", c, t, ee, at);
	emit(l, "  %S = ebpf.if %S -> i64 {", u, c);
	sr_str res2 = aoi_one(l, "    ", mv, k, m, kt, vt, v, at);
	sr_str n2 = val(l);
	emit(l, "      %S = arith.constant -2 : i64 %L", n2, at);
	emit(l, "      ebpf.yield %S : i64 %L", n2, at);
	emit(l, "    } %L", at);
	emit(l, "    ebpf.if.yield %S : i64 %L", res2, at);
	emit(l, "  } else {");
	emit(l, "    ebpf.if.yield %S : i64 %L", t, at);
	emit(l, "  } %L", at);
	emit(l, "  ebpf.yield %S : i64 %L", u, at);
	emit(l, "} %L", at);
	*out = mk(res, "i64");
	return 0;
}

/* ---- sklookup.go skAssign ---- */
#define SK_ASSIGN_ABSENT (-2) /* sklookup.go skAssignAbsent */
static int sk_assign(lowerer *l, const fe_stmt *s)
{
	sv k;
	if (expr(l, s->key, &k))
		return -1;
	sr_str k32 = val(l), sr = val(l), st = val(l), ab = val(l);
	emit(l, "%S = arith.trunci %S : i64 to i32 %L", k32, k.name, s->pos);
	emit(l, "%S = arith.constant %d : i64 %L", ab, (int64_t)SK_ASSIGN_ABSENT, s->pos);
	emit(l, "%S = ebpf.sock.map_lookup %S[%S] : %S, i32 -> !ebpf.sock_ref_or_null %L", sr, map_name(l, s->map), k32,
	     map_type(l, s->map), s->pos);
	sr_str p = val(l), a = val(l);
	emit(l, "%S = ebpf.sock.ref_check %S : !ebpf.sock_ref_or_null -> i64 present {", st, sr);
	emit(l, "^%S(%S: !ebpf.sock_ref):", (sr_str){p.p + 1, p.n - 1}, p);
	emit(l, "  %S = ebpf.sk.assign %%ctx, %S : !ebpf.ctx<\"sk_lookup\">, !ebpf.sock_ref -> i64 %L", a, p, s->pos);
	emit(l, "  ebpf.sock.release %S : !ebpf.sock_ref %L", p, s->pos);
	emit(l, "  ebpf.yield %S : i64 %L", a, s->pos);
	emit(l, "} absent {");
	emit(l, "  ebpf.yield %S : i64 %L", ab, s->pos);
	emit(l, "} %L", s->pos);
	env_set(&l->env, s->var, mk(st, "i64"));
	return 0;
}

/* ---- argv.go outputArgv ---- */
#define ARGV_SLOTS 20 /* argv.go argvSlots */
static int output_argv(lowerer *l, const fe_stmt *s)
{
	sr_str av = val(l);
	if (s->tp_str)
		emit(l, "%S = ebpf.tp.field %%ctx %q [%d] : !ebpf.ctx<\"tracepoint\"> -> !ebpf.user_str_array %L", av, s->tp_str->name,
		     s->tp_str->offset, s->pos);
	else
		emit(l, "%S = ebpf.ksyscall.arg %%ctx %d : !ebpf.ctx<\"ksyscall\"> -> !ebpf.user_str_array %L", av, s->len, s->pos);
	sr_str saved = l->indent;
	for (int64_t k = 0; k < ARGV_SLOTS; k++) {
		sr_str svv = val(l), stv = val(l), pv = val(l);
		emit(l, "%S, %S, %S = ebpf.user.str_at %S [%d] : !ebpf.user_str_array -> (!ebpf.user_str, i64, i1) %L", svv, stv, pv, av, k,
		     s->pos);
		emit(l, "ebpf.if %S {", pv);
		l->indent = cat(l->indent, "  ");
		fe_stmt sub = *s;
		sub.argv = 0;
		sub.tp_str = NULL;
		sub.str_ssa = svv;
		sub.index_v = k;
		if (output_str(l, sub)) {
			l->indent = saved;
			return -1;
		}
	}
	for (int64_t k = 0; k < ARGV_SLOTS; k++) {
		emit(l, "ebpf.if.yield %L", s->pos);
		l->indent.n -= 2;
		emit(l, "} else {");
		emit(l, "  ebpf.if.yield %L", s->pos);
		emit(l, "} %L", s->pos);
	}
	l->indent = saved;
	return 0;
}

/* ---- uprobe.go outputStr ---- */
static int output_str(lowerer *l, fe_stmt s)
{
	if (s.argv)
		return output_argv(l, &s);
	sr_str rec = fe_record_decl_mlir_type(s.ring->record);
	sr_str svv = {"", 0};
	sv lv = SV0;
	if (s.buf) {
		if (expr(l, s.buf_len, &lv))
			return -1;
		svv = val(l);
		emit(l, "%S = ebpf.uprobe.arg %%ctx %d : !ebpf.ctx<\"uprobe\"> -> !ebpf.user_buf %L", svv, s.len, s.pos);
	} else if (s.str_ssa.n) {
		svv = s.str_ssa;
	} else if (s.tp_str) {
		svv = val(l);
		emit(l, "%S = ebpf.tp.field %%ctx %q [%d] : !ebpf.ctx<\"tracepoint\"> -> !ebpf.user_str %L", svv, s.tp_str->name,
		     s.tp_str->offset, s.pos);
	} else if (s.k_str.n == 0 && !s.comm) {
		svv = val(l);
		if (is(l->kind, "ksyscall"))
			emit(l, "%S = ebpf.ksyscall.arg %%ctx %d : !ebpf.ctx<\"ksyscall\"> -> !ebpf.user_str %L", svv, s.len, s.pos);
		else
			emit(l, "%S = ebpf.uprobe.arg %%ctx %d : !ebpf.ctx<\"uprobe\"> -> !ebpf.user_str %L", svv, s.len, s.pos);
	}
	sr_str rv = val(l);
	emit(l, "%S = ebpf.ringbuf.reserve %q : !ebpf.maybe_reservation<%S> %L", rv, s.ring->name, rec, s.pos);
	sr_str ok = {"", 0}, st = {"", 0}, sn = {"", 0};
	int disc = is(s.op, "discard");
	if (s.var.n) {
		ok = val(l);
		st = val(l);
		if (disc)
			sn = val(l);
	}
	sr_str res = val(l);
	sr_buf b = {0};
	sr_buf *saved = l->b;
	sr_str saved_indent = l->indent;
	l->b = &b;
	l->indent = cat(l->indent, "  ");
	fe_map_decl tmp;
	memset(&tmp, 0, sizeof tmp);
	tmp.name = s.ring->name;
	tmp.record = s.ring->record;
	sr_str v;
	if (value_operand(l, s.value, &tmp, &v)) {
		l->b = saved;
		l->indent = saved_indent;
		return -1;
	}
	emit(l, "ebpf.ringbuf.store_record %S, %S : !ebpf.reservation<%S>, %S %L", res, v, rec, rec, s.pos);
	if (s.str_ssa.n && s.index) {
		sr_str iv = val(l);
		emit(l, "%S = arith.constant %d : i32 %L", iv, s.index_v, s.pos);
		emit(l, "ebpf.ringbuf.store_field %S[%d], %S : !ebpf.reservation<%S>, i32 %L", res, s.index->offset, iv, rec, s.pos);
	}
	sr_str rs = val(l);
	if (s.comm) {
		emit(l, "%S = ebpf.task.comm %S %q : !ebpf.reservation<%S> -> i64 %L", rs, res, s.path, rec, s.pos);
	} else if (s.k_str.n) {
		emit(l, "%S = ebpf.kernel.read_str %S %q, %S %q : !ebpf.reservation<%S>, !ebpf.kptr<%q> -> i64 %L", rs, res, s.path,
		     env_get(&l->env, s.ptr_of, NULL).name, s.k_str, rec, s.ptr_of_kt->name, s.pos);
	} else if (s.buf) {
		sr_str cv = val(l);
		emit(l, "%S, %S = ebpf.user.read %S %q, %S, %S : !ebpf.reservation<%S>, !ebpf.user_buf, %s -> i64, i32 %L", rs, cv, res, s.path,
		     svv, lv.name, rec, lv.ty, s.pos);
		emit(l, "ebpf.ringbuf.store_field %S[%d], %S : !ebpf.reservation<%S>, i32 %L", res, s.count_f->offset, cv, rec, s.pos);
	} else {
		emit(l, "%S = ebpf.user.read_str %S %q, %S : !ebpf.reservation<%S>, !ebpf.user_str -> i64 %L", rs, res, s.path, svv, rec,
		     s.pos);
	}
	emit(l, "ebpf.ringbuf.store_field %S[%d], %S : !ebpf.reservation<%S>, i64 %L", res, s.field->offset, rs, rec, s.pos);
	if (disc) {
		sr_str z = val(l), neg = val(l);
		emit(l, "%S = arith.constant 0 : i64 %L", z, s.pos);
		emit(l, "%S = arith.cmpi slt, %S, %S : i64 %L", neg, rs, z, s.pos);
		sr_str sent = {"", 0};
		if (s.var.n) {
			sent = val(l);
			emit(l, "%S = ebpf.if %S -> i1 {", sent, neg);
		} else {
			emit(l, "ebpf.if %S {", neg);
		}
		emit(l, "  ebpf.ringbuf.discard %S : !ebpf.reservation<%S> %L", res, rec, s.pos);
		if (s.var.n) {
			sr_str f = val(l);
			emit(l, "  %S = arith.constant false %L", f, s.pos);
			emit(l, "  ebpf.if.yield %S : i1 %L", f, s.pos);
		} else {
			emit(l, "  ebpf.if.yield %L", s.pos);
		}
		emit(l, "} else {");
		emit(l, "  ebpf.ringbuf.submit %S : !ebpf.reservation<%S> %L", res, rec, s.pos);
		if (s.var.n) {
			sr_str t = val(l);
			emit(l, "  %S = arith.constant true %L", t, s.pos);
			emit(l, "  ebpf.if.yield %S : i1 %L", t, s.pos);
		} else {
			emit(l, "  ebpf.if.yield %L", s.pos);
		}
		emit(l, "} %L", s.pos);
		if (s.var.n) {
			sr_str t = val(l);
			emit(l, "%S = arith.constant true %L", t, s.pos);
			emit(l, "ebpf.yield %S, %S, %S : i1, i64, i1 %L", t, rs, sent, s.pos);
		} else {
			emit(l, "ebpf.yield %L", s.pos);
		}
	} else {
		emit(l, "ebpf.ringbuf.submit %S : !ebpf.reservation<%S> %L", res, rec, s.pos);
	}
	if (disc) {
	} else if (s.var.n) {
		sr_str t = val(l);
		emit(l, "%S = arith.constant true %L", t, s.pos);
		emit(l, "ebpf.yield %S, %S : i1, i64 %L", t, rs, s.pos);
	} else {
		emit(l, "ebpf.yield %L", s.pos);
	}
	sr_str present = sr_bufstr(&b);
	sr_buf ab = {0};
	l->b = &ab;
	if (s.var.n && disc) {
		sr_str f = val(l), z = val(l);
		emit(l, "%S = arith.constant false %L", f, s.pos);
		emit(l, "%S = arith.constant 0 : i64 %L", z, s.pos);
		emit(l, "ebpf.yield %S, %S, %S : i1, i64, i1 %L", f, z, f, s.pos);
	} else if (s.var.n) {
		sr_str f = val(l), z = val(l);
		emit(l, "%S = arith.constant false %L", f, s.pos);
		emit(l, "%S = arith.constant 0 : i64 %L", z, s.pos);
		emit(l, "ebpf.yield %S, %S : i1, i64 %L", f, z, s.pos);
	} else {
		emit(l, "ebpf.yield %L", s.pos);
	}
	sr_str absent = sr_bufstr(&ab);
	l->b = saved;
	l->indent = saved_indent;
	sr_str decl = {"", 0}, head = {"", 0};
	if (s.var.n) {
		decl = sr_cstr(" -> i1, i64");
		head = S(l, "%S, %S = ", ok, st);
		if (disc) {
			decl = sr_cstr(" -> i1, i64, i1");
			head = S(l, "%S, %S, %S = ", ok, st, sn);
		}
	}
	emit(l, "%Sebpf.ringbuf.if_reserved %S : !ebpf.maybe_reservation<%S>%S present {", head, rv, rec, decl);
	emit(l, "^present(%S: !ebpf.reservation<%S>):", res, rec);
	sr_putstr(l->b, present);
	emit(l, "} absent {");
	sr_putstr(l->b, absent);
	emit(l, "} %L", s.pos);
	if (s.var.n) {
		env_set(&l->env, s.var, mk(ok, "i1"));
		env_set(&l->env, cat(s.var, "#status"), mk(st, "i64"));
		env_set(&l->env, cat(s.var, "#sent"), mk(ok, "i1"));
		if (disc)
			env_set(&l->env, cat(s.var, "#sent"), mk(sn, "i1"));
	}
	return 0;
}

/* ---- statements (lower.go stmts) ---- */

/* flow.go flowFields: the widths only (lower.go reads Bits; a missing name reads 0, as Go's zero flowField) */
static int64_t flow_bits(sr_str name)
{
	static const struct {
		const char *name;
		int64_t bits;
	} t[] = {{"nhoff", 16},	   {"thoff", 16},    {"addr_proto", 16}, {"is_frag", 8},   {"is_first_frag", 8}, {"is_encap", 8},
		 {"ip_proto", 8},  {"n_proto", 16},  {"sport", 16},	 {"dport", 16},    {"ipv4_src", 32},     {"ipv4_dst", 32},
		 {"ipv6_src", 32}, {"ipv6_dst", 32}, {"flags", 32},	 {"flow_label", 32}};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
		if (is(name, t[i].name))
			return t[i].bits;
	return 0;
}

static int stmt(lowerer *l, const fe_stmt *s)
{
	sr_str k = s->kind;
	if (is(k, "assign")) {
		sv x;
		if (expr(l, s->val, &x))
			return -1;
		env_set(&l->env, s->var, x);
		return 0;
	}
	if (is(k, "skassign"))
		return sk_assign(l, s);
	if (is(k, "kread")) {
		sr_str a = val(l);
		emit(l, "%S = ebpf.kprobe.arg %%ctx %d : !ebpf.ctx<\"kprobe\"> -> i64 %L", a, s->count, s->pos);
		sr_str r = val(l);
		emit(l, "%S:2 = ebpf.kernel.read_scalar %S offset %d : i64 -> i%d, i64 %L", r, a, s->len, s->field->bits, s->pos);
		sv v = mk(cat(r, "#0"), "i64");
		if (s->field->bits < 64) {
			sr_str x = val(l);
			emit(l, "%S = %s %S#0 : i%d to i64 %L", x, ext_of(s->field->is_signed), r, s->field->bits, s->pos);
			v = mk(x, "i64");
		}
		if (!is(s->var, "_"))
			env_set(&l->env, s->var, v);
		env_set(&l->env, s->path, mk(cat(r, "#1"), "i64"));
		return 0;
	}
	if (is(k, "fkstore")) {
		sv v;
		if (expr(l, s->val, &v))
			return -1;
		int64_t bits = flow_bits(s->path);
		sr_str t = val(l);
		emit(l, "%S = arith.trunci %S : i64 to i%d %L", t, v.name, bits, s->pos);
		sr_str idx = {"", 0};
		if (s->count >= 0)
			idx = S(l, "[%d]", s->count);
		emit(l, "ebpf.flow_keys.store %%ctx %q%S, %S : !ebpf.ctx<\"flow_dissector\">, i%d %L", s->path, idx, t, bits, s->pos);
		return 0;
	}
	if (is(k, "ctxstore")) {
		sv v;
		if (expr(l, s->val, &v))
			return -1;
		sr_str t = val(l);
		emit(l, "%S = arith.trunci %S : i64 to i32 %L", t, v.name, s->pos);
		emit(l, "ebpf.ctx.field.store %%ctx %q, %S : !ebpf.ctx<%q>, i32 %L", s->path, t, l->kind, s->pos);
		return 0;
	}
	if (is(k, "kptr")) {
		sr_str v = val(l);
		if (is(l->kind, "netfilter"))
			emit(l, "%S = ebpf.ctx.field %%ctx %q : !ebpf.ctx<\"netfilter\"> -> !ebpf.kptr<%q> %L", v, s->path, s->kt->name, s->pos);
		else
			emit(l, "%S = ebpf.ctx.arg %%ctx[%d] : !ebpf.ctx<\"tp_btf\"> -> !ebpf.kptr<%q> %L", v, s->len, s->kt->name, s->pos);
		env_set(&l->env, s->var, mk(v, "kptr"));
		return 0;
	}
	if (is(k, "kcheck")) {
		sr_str r = val(l);
		if (s->ptr_of.n == 0)
			emit(l, "%S = ebpf.ctx.arg %%ctx[%d] : !ebpf.ctx<%q> -> !ebpf.kptr_or_null<%q> %L", r, s->len, l->kind, s->kt->name,
			     s->pos);
		else
			emit(l, "%S = ebpf.kfield.ptr %S %q : !ebpf.kptr<%q> -> !ebpf.kptr_or_null<%q> %L", r,
			     env_get(&l->env, s->ptr_of, NULL).name, s->path, s->ptr_of_kt->name, s->kt->name, s->pos);
		env pre = env_copy(&l->env);
		sr_str q = val(l);
		env pin = env_copy(&pre);
		env_set(&pin, s->var, mk(q, "kptr"));
		region g;
		if (arm(l, &s->then, &pin, cat(l->indent, "  "), &g.then_text, &g.then_env))
			return -1;
		env_del(&g.then_env, s->var);
		if (arm(l, &s->else_, &pre, cat(l->indent, "  "), &g.else_text, &g.else_env))
			return -1;
		region_join(l, &g, &pre, s);
		emit(l, "%Sebpf.kptr.check %S : !ebpf.kptr_or_null<%q>%S present {", result_decl(l, g.res, g.vars.n), r, s->kt->name, g.decl);
		emit(l, "^present(%S: !ebpf.kptr<%q>):", q, s->kt->name);
		region_arms(l, &g, "ebpf.yield", s->if_pos, s->pos, "} absent {");
		return 0;
	}
	if (is(k, "scx")) /* a sched_ext op as a statement */
		return scx_stmt(l, s);
	if (is(k, "scxsel"))
		return scx_select(l, s);
	if (is(k, "scxexit")) {
		scx_exit(l, s);
		return 0;
	}
	if (is(k, "gset")) { /* a Global's write (ebpf.global.store — one trunci below 64 bits) */
		sv x;
		if (expr(l, s->val, &x))
			return -1;
		sr_str d = x.name;
		if (s->glob->bits < 64) {
			d = val(l);
			emit(l, "%S = arith.trunci %S : i64 to i%d %L", d, x.name, s->glob->bits, s->pos);
		}
		emit(l, "ebpf.global.store @%S, %S : i%d %L", s->glob->name, d, s->glob->bits, s->pos);
		return 0;
	}
	if (is(k, "kstore")) { /* the socket-write rule: write an integer field of the checked socket (ebpf.kfield.store) — the value is narrowed at the store */
		sv x;
		if (expr(l, s->val, &x))
			return -1;
		sr_str v = x.name;
		if (s->field->bits < 64) {
			v = val(l);
			emit(l, "%S = arith.trunci %S : i64 to i%d %L", v, x.name, s->field->bits, s->pos);
		}
		emit(l, "ebpf.kfield.store %S %q, %S : !ebpf.kptr<%q>, i%d %L", env_get(&l->env, s->var, NULL).name, s->field->name, v, s->kt->name,
		     s->field->bits, s->pos);
		return 0;
	}
	if (is(k, "kcopy")) {
		borrow br;
		if (!bor_get(&l->refs, s->var, &br))
			return fail(l, "internal: %S outside the present region at %P", s->var, s->pos);
		emit(l, "ebpf.kfield.copy %S %q, %S %q : !ebpf.kptr<%q>, !ebpf.borrowed<%S> %L", env_get(&l->env, s->ptr_of, NULL).name, s->path,
		     br.name, s->field->name, s->ptr_of_kt->name, fe_record_decl_mlir_type(s->map->record), s->pos);
		return 0;
	}
	if (is(k, "tpcopy")) {
		borrow br;
		if (!bor_get(&l->refs, s->var, &br))
			return fail(l, "internal: %S outside the present region at %P", s->var, s->pos);
		emit(l, "ebpf.tp.field.copy %S %q, %%ctx %q [%d] : !ebpf.borrowed<%S>, !ebpf.ctx<\"tracepoint\"> %L", br.name, s->field->name,
		     s->tp_copy->name, s->tp_copy->offset, fe_record_decl_mlir_type(s->map->record), s->pos);
		return 0;
	}
	if (is(k, "ostr"))
		return output_str(l, *s);
	if (is(k, "guard")) {
		sv c;
		if (expr(l, s->cond, &c))
			return -1;
		env pre = env_copy(&l->env);
		sr_buf b = {0};
		sr_buf *saved = l->b;
		sr_str saved_indent = l->indent, saved_fired = l->fired;
		l->b = &b;
		l->indent = cat(l->indent, "  ");
		l->env = env_copy(&pre);
		l->fired = (sr_str){"", 0};
		int rc = stmts(l, &s->else_);
		sr_str inner = l->fired;
		if (inner.n == 0) {
			inner = val(l);
			emit(l, "%S = arith.constant false %L", inner, s->pos);
		}
		l->b = saved;
		l->indent = saved_indent;
		l->fired = saved_fired;
		if (rc)
			return rc;
		l->env = pre;
		sr_str f = val(l), t = val(l);
		emit(l, "%S = ebpf.if %S -> i1 {", f, c.name);
		emit(l, "  %S = arith.constant true %L", t, s->pos);
		emit(l, "  ebpf.if.yield %S : i1 %L", t, s->pos);
		emit(l, "} else {");
		sr_putstr(l->b, sr_bufstr(&b));
		emit(l, "  ebpf.if.yield %S : i1 %L", inner, s->pos);
		emit(l, "} %L", s->pos);
		l->fired = f;
		return 0;
	}
	if (is(k, "loop"))
		return loop(l, s);
	if (is(k, "break") || is(k, "next")) {
		const char *op = is(k, "break") ? "ebpf.break" : "ebpf.continue";
		names carried = l->loops[l->n_loops - 1];
		const char **tys;
		region_types(carried, &l->env, &tys);
		emit(l, "%S %L", yield_text(op, carried, &l->env, tys), s->pos);
		return 0;
	}
	if (is(k, "gadd")) {
		sv x;
		if (expr(l, s->val, &x))
			return -1;
		sr_str d = x.name;
		if (s->glob->bits == 32) {
			d = val(l);
			emit(l, "%S = arith.trunci %S : i64 to i32 %L", d, x.name, s->pos);
		}
		emit(l, "ebpf.global.atomic_add @%S, %S : i%d %L", s->glob->name, d, s->glob->bits, s->pos);
		return 0;
	}
	if (is(k, "atomic_add") || is(k, "update")) {
		sr_str m = map_name(l, s->map), kk, v;
		if (key_operand(l, s->key, &kk) || value_operand(l, s->value, s->map, &v))
			return -1;
		emit(l, "ebpf.map.%S %S[%S], %S : %S, i32, %S %L", s->kind, m, kk, v, map_type(l, s->map), value_type(l, s->map), s->pos);
		return 0;
	}
	if (is(k, "if")) {
		sv c;
		if (expr(l, s->cond, &c))
			return -1;
		env pre = env_copy(&l->env);
		region g;
		if (arm(l, &s->then, &pre, cat(l->indent, "  "), &g.then_text, &g.then_env))
			return -1;
		if (arm(l, &s->else_, &pre, cat(l->indent, "  "), &g.else_text, &g.else_env))
			return -1;
		region_join(l, &g, &pre, s);
		emit(l, "%Sebpf.if %S%S {", result_decl(l, g.res, g.vars.n), c.name, g.decl);
		region_arms(l, &g, "ebpf.if.yield", s->pos, s->pos, "} else {");
		return 0;
	}
	if (is(k, "lookup_check")) {
		sr_str m = map_name(l, s->map);
		int64_t vb = s->map->value_bits;
		sr_str vt = value_type(l, s->map);
		sr_str kk;
		if (map_key(l, s->key, s->map, &kk))
			return -1;
		sr_str r = val(l);
		emit(l, "%S = ebpf.map.lookup %S[%S] : %S, %S -> !ebpf.maybe_ref<%S> %L", r, m, kk, map_type(l, s->map), key_type(l, s->map), vt,
		     s->pos);
		env pre = env_copy(&l->env);
		sr_str bor = val(l);
		bor_set(&l->refs, s->var, (borrow){bor, vb});
		region g;
		if (arm(l, &s->then, &pre, cat(l->indent, "  "), &g.then_text, &g.then_env))
			return -1;
		if (arm(l, &s->else_, &pre, cat(l->indent, "  "), &g.else_text, &g.else_env))
			return -1;
		bor_del(&l->refs, s->var);
		region_join(l, &g, &pre, s);
		emit(l, "%Sebpf.ref.check %S : !ebpf.maybe_ref<%S>%S present {", result_decl(l, g.res, g.vars.n), r, vt, g.decl);
		emit(l, "^present(%S: !ebpf.borrowed<%S>):", bor, vt);
		region_arms(l, &g, "ebpf.yield", s->if_pos, s->pos, "} absent {");
		return 0;
	}
	if (is(k, "fadd")) {
		borrow br;
		if (!bor_get(&l->refs, s->var, &br))
			return fail(l, "internal: %S outside the present region at %P", s->var, s->pos);
		sr_str rt = fe_record_decl_mlir_type(s->map->record);
		int64_t bits = s->field->bits;
		sr_str x = val(l);
		emit(l, "%S = ebpf.ref.field.load %S %q : !ebpf.borrowed<%S> -> i%d %L", x, br.name, s->field->name, rt, bits, s->pos);
		sr_str d;
		if (field_operand(l, s->value, s->field, &d))
			return -1;
		sr_str y = val(l);
		const char *op = is(s->op, "+") ? "arith.addi" : is(s->op, "-") ? "arith.subi" : "";
		emit(l, "%S = %s %S, %S : i%d %L", y, op, x, d, bits, s->pos);
		emit(l, "ebpf.ref.field.store %S %q, %S : !ebpf.borrowed<%S>, i%d %L", br.name, s->field->name, y, rt, bits, s->pos);
		return 0;
	}
	if (is(k, "drop")) {
		sv x;
		return expr(l, s->val, &x);
	}
	if (is(k, "ratomic")) {
		borrow br;
		if (!bor_get(&l->refs, s->var, &br))
			return fail(l, "internal: %S outside the present region at %P", s->var, s->pos);
		sr_str v;
		if (value_operand(l, s->value, s->map, &v))
			return -1;
		sr_str vt = value_type(l, s->map);
		emit(l, "ebpf.ref.atomic_add %S, %S : !ebpf.borrowed<%S>, %S %L", br.name, v, vt, vt, s->pos);
		return 0;
	}
	if (is(k, "ringout")) {
		sv x;
		return ring_output(l, s->ring, s->value, s->pos, 0, &x);
	}
	if (is(k, "fstore") || is(k, "fatomic")) {
		borrow br;
		if (!bor_get(&l->refs, s->var, &br))
			return fail(l, "internal: %S outside the present region at %P", s->var, s->pos);
		sr_str v;
		if (field_operand(l, s->value, s->field, &v))
			return -1;
		const char *op = is(k, "fstore") ? "ebpf.ref.field.store" : "ebpf.ref.field.atomic_add";
		sr_str path = s->field->name;
		if (s->path.n)
			path = s->path;
		emit(l, "%s %S %q, %S : !ebpf.borrowed<%S>, i%d %L", op, br.name, path, v, fe_record_decl_mlir_type(s->map->record),
		     s->field->bits, s->pos);
		return 0;
	}
	if (is(k, "istore")) {
		borrow br;
		if (!bor_get(&l->refs, s->var, &br))
			return fail(l, "internal: %S outside the present region at %P", s->var, s->pos);
		sv ix;
		if (expr(l, s->key, &ix))
			return -1;
		sr_str v;
		if (field_operand(l, s->value, s->field, &v))
			return -1;
		sr_str t = index32(l, ix.name, s->pos);
		sr_str el = val(l);
		sr_str w = S(l, "i%d", s->field->bits);
		emit(l, "ebpf.ref.index %S %q [%S] : !ebpf.borrowed<%S>, i32 in_range {", br.name, s->field->name, t,
		     fe_record_decl_mlir_type(s->map->record));
		emit(l, "^bb0(%S: !ebpf.elem<%S>):", el, w);
		emit(l, "  ebpf.elem.store %S, %S : !ebpf.elem<%S>, %S %L", el, v, w, w, s->pos);
		emit(l, "  ebpf.yield %L", s->pos);
		emit(l, "} out_of_range {");
		emit(l, "  // unreachable \xe2\x80\x94 the index range is [0, %d] (proved by the frontend)", s->field->count - 1);
		emit(l, "  ebpf.yield %L", s->pos);
		emit(l, "} %L", s->pos);
		return 0;
	}
	if (is(k, "window_check")) {
		sv off;
		if (expr(l, s->off, &off))
			return -1;
		env pre = env_copy(&l->env);
		sr_str w = val(l);
		bor_set(&l->wins, s->var, (borrow){w, s->len});
		sr_str then_text, else_text;
		env then_env, else_env;
		if (arm(l, &s->then, &pre, cat(l->indent, "  "), &then_text, &then_env))
			return -1;
		bor_del(&l->wins, s->var);
		if (arm(l, &s->else_, &pre, cat(l->indent, "  "), &else_text, &else_env))
			return -1;
		l->env = pre;
		names vars = results(&pre, &then_env, &else_env);
		const char **tys;
		sr_str decl = region_types(vars, &then_env, &tys);
		sr_str res = {"", 0};
		if (vars.n > 0)
			res = val(l);
		emit(l, "%Sebpf.packet.check %%ctx[%S] len %d : !ebpf.ctx<%q>, i64%S in_range {", result_decl(l, res, vars.n), off.name, s->len,
		     l->kind, decl);
		emit(l, "^in_range(%S: !ebpf.pkt_window<%d>):", w, s->len);
		sr_putstr(l->b, then_text);
		emit(l, "  %S %L", yield_text("ebpf.yield", vars, &then_env, tys), s->if_pos);
		emit(l, "} out_of_range {");
		sr_putstr(l->b, else_text);
		emit(l, "  %S %L", yield_text("ebpf.yield", vars, &else_env, tys), s->if_pos);
		emit(l, "} %L", s->pos);
		bind_results(l, res, vars, tys);
		return 0;
	}
	return fail(l, "internal: statement kind %q", s->kind);
}

static int stmts(lowerer *l, const fe_stmts *ss)
{
	for (size_t i = 0; i < ss->n; i++)
		if (stmt(l, &ss->v[i]))
			return -1;
	return 0;
}

/* ---- programs and functions (lower.go lowerProgram, lowerFunc; fmodret.go fmodUses, lowerFmodReturn) ---- */
static void lowerer_init(lowerer *l, fe_z *z, sr_buf *b, int64_t *n, sr_str kind)
{
	memset(l, 0, sizeof *l);
	l->z = z;
	l->b = b;
	l->n = n;
	l->indent = sr_cstr("  ");
	l->kind = kind;
}

static void add_map(lowerer *l, const fe_map_decl *m, sr_str name)
{
	l->maps = sr_grow(l->maps, l->n_maps * sizeof *l->maps, (l->n_maps + 1) * sizeof *l->maps);
	l->maps[l->n_maps++] = (map_ent){m, name};
}

static int fmod_uses(const fe_program *p) { return is(p->kind, "fmod_ret") && (p->fmod_val || p->fmod_guard); }

static int lower_fmod_return(lowerer *l, const fe_program *p)
{
	sr_str last = val(l);
	if (p->fmod_val) {
		sv x;
		if (expr(l, p->fmod_val, &x))
			return -1;
		emit(l, "%S = arith.trunci %S : i64 to i32 %L", last, x.name, p->verdict_pos);
	} else {
		emit(l, "%S = arith.constant 0 : i32 %L", last, p->verdict_pos);
	}
	sr_str r = last;
	if (p->guard_verdict.n) {
		sr_str g = val(l);
		bigint zero = {0};
		emit(l, "%S = arith.constant %B : i32 %L", g, p->fmod_guard ? p->fmod_guard : &zero, p->verdict_pos);
		r = val(l);
		emit(l, "%S = arith.select %S, %S, %S : i32 %L", r, l->fired, g, last, p->verdict_pos);
	}
	emit(l, "ebpf.return %S : i32 %L", r, p->verdict_pos);
	return 0;
}

static int lower_program(fe_z *z, sr_buf *b, const fe_program *p, sr_buf *err)
{
	lowerer L, *l = &L;
	if (p->verdict.n == 0) {
		lowerer_init(l, z, b, &(int64_t){0}, p->kind);
		fail(l, "internal: program %S has no verdict", p->name);
		sr_putstr(err, sr_bufstr(&l->err));
		return -1;
	}
	int64_t n = 0;
	lowerer_init(l, z, b, &n, p->kind);
	sr_buf syms = {0}, params = {0};
	for (size_t i = 0; i < p->n_maps; i++) {
		if (i)
			sr_puts(&syms, ", ");
		sr_putc(&syms, '@');
		sr_putstr(&syms, p->maps[i]->name);
		sr_str mn = S(l, "%%m%d", (int64_t)i);
		add_map(l, p->maps[i], mn);
		wr(l, &params, ", %S: %S", mn, map_type(l, p->maps[i]));
	}
	wr(l, b, "ebpf.program @%S %q", p->name, p->kind);
	if (p->target.n)
		wr(l, b, " attach %q", p->target);
	if (is(p->kind, "kprobe") || is(p->kind, "uprobe") || is(p->kind, "kretprobe") || is(p->kind, "uretprobe") ||
	    is(p->kind, "ksyscall"))
		sr_puts(b, " arch \"x86_64\"");
	if (p->n_maps > 0)
		wr(l, b, " maps [%S]", sr_bufstr(&syms));
	sr_puts(b, " {\n");
	wr(l, b, "^bb0(%%ctx: !ebpf.ctx<%q>%S):\n", p->kind, sr_bufstr(&params));
	int rc = stmts(l, &p->body);
	if (!rc) {
		if (p->so_val) { /* a struct_ops integer member's return value (u32 — ebpf.return … : i32) */
			sv x;
			rc = expr(l, p->so_val, &x);
			if (!rc) {
				sr_str r = val(l);
				emit(l, "%S = arith.trunci %S : i64 to i32 %L", r, x.name, p->verdict_pos);
				wr(l, b, "  ebpf.return %S : i32 %L\n", r, p->verdict_pos);
			}
		} else if (fmod_uses(p)) {
			rc = lower_fmod_return(l, p);
		} else if (p->guard_verdict.n) {
			wr(l, b, "  ebpf.verdict.if %S %q else %q %L\n", l->fired, p->guard_verdict, p->verdict, p->verdict_pos);
		} else if (p->redir_map) {
			sv k;
			rc = expr(l, p->redir_key, &k);
			if (!rc) {
				sr_str k32 = val(l);
				emit(l, "%S = arith.trunci %S : i64 to i32 %L", k32, k.name, p->verdict_pos);
				wr(l, b, "  ebpf.redirect_map %S[%S] : %S, i32 fallback %q %L\n", map_name(l, p->redir_map), k32,
				   map_type(l, p->redir_map), p->verdict, p->verdict_pos);
			}
		} else {
			wr(l, b, "  ebpf.verdict %q %L\n", p->verdict, p->verdict_pos);
		}
	}
	if (rc) {
		sr_putstr(err, sr_bufstr(&l->err));
		return -1;
	}
	wr(l, b, "} %L\n", p->pos);
	return 0;
}

static int lower_func(fe_z *z, sr_buf *b, const fe_program *p, sr_buf *err)
{
	lowerer L, *l = &L;
	int64_t n = 0;
	lowerer_init(l, z, b, &n, p->kind);
	if (!p->f_ret) {
		fail(l, "internal: function %S has no value", p->name);
		sr_putstr(err, sr_bufstr(&l->err));
		return -1;
	}
	sr_buf syms = {0}, params = {0}, tys = {0};
	size_t np = 0;
#define PSEP()                                                                                                                     \
	do {                                                                                                                       \
		if (np++) {                                                                                                        \
			sr_puts(&params, ", ");                                                                                    \
			sr_puts(&tys, ", ");                                                                                       \
		}                                                                                                                  \
	} while (0)
	for (size_t i = 0; i < p->n_f_params; i++) {
		sr_str a = p->f_params[i];
		sr_str v = S(l, "%%a%d", (int64_t)i);
		if ((int64_t)i == p->f_win) {
			sr_str t = S(l, "!ebpf.pkt_window<%d>", p->f_win_len);
			bor_set(&l->wins, a, (borrow){v, p->f_win_len});
			PSEP();
			wr(l, &params, "%S: %S", v, t);
			sr_putstr(&tys, t);
			continue;
		}
		if ((int64_t)i == p->f_ctx) {
			sr_str t = S(l, "!ebpf.ctx<%q>", p->f_ctx_kind);
			l->kind = p->f_ctx_kind;
			PSEP();
			wr(l, &params, "%%ctx: %S", t);
			sr_putstr(&tys, t);
			continue;
		}
		if ((int64_t)i == p->f_borrow) {
			sr_str t = S(l, "!ebpf.borrowed<%S>", value_type(l, p->f_borrow_map));
			bor_set(&l->refs, a, (borrow){v, p->f_borrow_map->value_bits});
			PSEP();
			wr(l, &params, "%S: %S", v, t);
			sr_putstr(&tys, t);
			continue;
		}
		env_set(&l->env, a, mk(v, "i64"));
		PSEP();
		wr(l, &params, "%S: i64", v);
		sr_puts(&tys, "i64");
	}
	for (size_t i = 0; i < p->n_maps; i++) {
		if (i)
			sr_puts(&syms, ", ");
		sr_putc(&syms, '@');
		sr_putstr(&syms, p->maps[i]->name);
		sr_str mn = S(l, "%%m%d", (int64_t)i);
		add_map(l, p->maps[i], mn);
		if (np++)
			sr_puts(&params, ", ");
		wr(l, &params, "%S: %S", mn, map_type(l, p->maps[i]));
	}
#undef PSEP
	wr(l, b, "ebpf.func @%S \"static\" (%S) -> i64", p->name, sr_bufstr(&tys));
	if (p->n_maps > 0)
		wr(l, b, " maps [%S]", sr_bufstr(&syms));
	sr_puts(b, " {\n");
	wr(l, b, "^bb0(%S):\n", sr_bufstr(&params));
	sv r;
	if (stmts(l, &p->body) || expr(l, p->f_ret, &r)) {
		sr_putstr(err, sr_bufstr(&l->err));
		return -1;
	}
	wr(l, b, "  ebpf.return %S : i64 %L\n", r.name, p->verdict_pos);
	wr(l, b, "} %L\n", p->pos);
	return 0;
}

sr_result fe_lower(fe_z *z, const fe_result *r, sr_buf *out)
{
	sr_buf b = {0}, err = {0};
	sr_puts(&b, "// Code generated by spinelbpf. DO NOT EDIT.\n");
	sr_puts(&b, "// spinel-bpf-mlir " PIN_VERSION "\n"); /* version.MLIRLine */
	int rc = 0;
	for (size_t i = 0; !rc && i < r->n_funcs; i++)
		rc = lower_func(z, &b, r->funcs[i], &err);
	for (size_t i = 0; !rc && i < r->n_programs; i++)
		rc = lower_program(z, &b, r->programs[i], &err);
	if (z->np.kind != SR_OK)
		return z->np;
	if (rc)
		return sr_err_str(sr_bufstr(&err));
	int scx = 0;
	for (size_t i = 0; i < r->n_programs; i++)
		scx = scx || r->programs[i]->scx;
	if (scx) { /* the sched_ext op forms (bpf-mlir's insert set) — the module attribute wraps every op after the two comment lines */
		sr_str t = sr_bufstr(&b);
		const char *p1 = memchr(t.p, '\n', t.n);
		const char *p2 = p1 ? memchr(p1 + 1, '\n', t.n - (size_t)(p1 + 1 - t.p)) : NULL;
		if (p2) {
			size_t k = (size_t)(p2 + 1 - t.p);
			sr_buf w = {0};
			sr_putstr(&w, (sr_str){t.p, k});
			sr_puts(&w, "module attributes {ebpf.scx_kfuncs = \"insert\"} {\n");
			sr_putstr(&w, (sr_str){t.p + k, t.n - k});
			sr_puts(&w, "}\n");
			b = w;
		}
	}
	if (!fe_verify_world(sr_bufstr(&b), &err))
		return sr_err_str(sr_bufstr(&err));
	sr_putstr(out, sr_bufstr(&b));
	return sr_ok;
}
