/* body_ring — ring.go of G1: the ring buffer output and the record.make walk (`S.new(…)`) that the ring output, map updates and
 * lpm keys share. Each function names the Go it follows (internal/frontend/ring.go at main c204310). Walker state is only read through
 * the core's functions of body.h. */
#include "body.h"
#include "body_priv.h"

#include <string.h>

static const sr_node *recv_of(fe_prog_ctx *c, const sr_node *n) { return fe_ast_ref(c->a, n, "receiver"); }

static sr_str nstr(const sr_node *n, const char *k)
{
	int ok;
	return fe_node_str(n, k, &ok);
}

static int is_type(const sr_node *n, const char *t) { return n && sr_eqc(n->type, t); }

static fe_expr *new_expr(fe_prog_ctx *c, const char *kind, const sr_node *at)
{
	fe_expr *e = sr_alloc(sizeof *e);
	e->args_nil = 1;
	e->kind = sr_cstr(kind);
	e->pos = fe_pos_of(c->z->z, c->a, at);
	return e;
}

static void expr_push(fe_expr *e, fe_expr *a)
{
	e->args = sr_grow(e->args, e->n_args * sizeof *e->args, (e->n_args + 1) * sizeof *e->args);
	e->args[e->n_args++] = a;
	e->args_nil = 0;
}

static void reject(fe_prog_ctx *c, fe_code code, const sr_node *n, sr_buf *b)
{
	fe_ctx_add(c, FE_REJECTED, code, n, sr_bufstr(b));
}

/* ring.go ringOf */
fe_ring_decl *fe_ring_of(fe_prog_ctx *c, const sr_node *recv)
{
	if (!recv || !is_type(recv, "ConstantReadNode")) return NULL;
	return fe_name_get(&c->z->top->rings, nstr(recv, "name"));
}

/* ring.go isOutput */
int fe_is_output(fe_prog_ctx *c, const sr_node *n)
{
	return n && is_type(n, "CallNode") && sr_eqc(nstr(n, "name"), "output") && fe_ring_of(c, recv_of(c, n)) != NULL;
}

/* ring.go outputOfBadRing */
int fe_output_of_bad_ring(fe_prog_ctx *c, const sr_node *n)
{
	const sr_node *recv = recv_of(c, n);
	if (!n || !is_type(n, "CallNode")) return 0;
	sr_str name = nstr(n, "name");
	if (!(sr_eqc(name, "output") || sr_eqc(name, "output_str"))) return 0;
	return recv && is_type(recv, "ConstantReadNode") && fe_name_get(&c->z->top->bad_rings, nstr(recv, "name")) != NULL;
}

/* ring.go ringOutput */
fe_expr *fe_ring_output(fe_prog_ctx *c, const sr_node *n, sr_str ref_var)
{
	fe_ring_decl *r = fe_ring_of(c, recv_of(c, n));
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok) return NULL;
	if (!sr_eqc(callee, "RingBuf#output")) {
		sr_buf b = {0};
		sr_puts(&b, "`output` resolves to ");
		fe_fmt_s(&b, callee);
		sr_puts(&b, ", not BPF::RingBuf#output");
		reject(c, FE_SB011, n, &b);
		return NULL;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, n, &n_as);
	if (n_as != 1) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, r->const_name);
		sr_puts(&b, ".output` takes one event (`");
		fe_fmt_s(&b, r->record->const_name);
		sr_puts(&b, ".new(…)`)");
		reject(c, FE_SB002, n, &b);
		return NULL;
	}
	c->ring_make = 1; /* ring.go: only the ring output's record.make takes `t.copy(:m)` for an array member */
	fe_map_decl probe = {0};
	probe.name = r->name;
	probe.record = r->record;
	fe_map_decl *pm = sr_alloc(sizeof *pm);
	*pm = probe;
	fe_expr *mk = fe_record_make(c, as[0], r->record, pm, ref_var);
	c->ring_make = 0;
	if (!mk) return NULL;
	fe_ptr_set_add(&c->used_rings, r);
	fe_expr *e = new_expr(c, "ringout", n);
	e->ring = r;
	expr_push(e, mk);
	e->bool_ = 1;
	return e;
}

/* ring.go ringCopy: `t.copy(:m)` of an array member of the ring output's record.make. Returns Go's second result (handled);
 * *out is Go's first (NULL with handled set is Go's `nil, true`, a rejection already added). */
static int ring_copy(fe_prog_ctx *c, const sr_node *x, fe_record_field *f, fe_record_decl *rec, fe_expr **out)
{
	*out = NULL;
	if (!c->ring_make || !is_type(x, "CallNode") || !sr_eqc(nstr(x, "name"), "copy")) return 0;
	const sr_node *recv = recv_of(c, x);
	if (!recv || !is_type(recv, "LocalVariableReadNode") || !fe_name_get(&c->kptrs, nstr(recv, "name"))) return 0;
	sr_str t = nstr(recv, "name");
	fe_kernel_type_decl *d = fe_name_get(&c->kptrs, t);
	int ok;
	sr_str cs = fe_callee(c, x, &ok);
	if (!ok || !sr_eqc(cs, "KPtr#copy")) {
		if (ok) {
			sr_buf b = {0};
			sr_puts(&b, "`copy` resolves to ");
			fe_fmt_s(&b, cs);
			sr_puts(&b, ", not BPF::KPtr#copy");
			reject(c, FE_SB011, x, &b);
		}
		return 1;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, x, &n_as);
	if (n_as != 1 || !is_type(as[0], "SymbolNode")) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, t);
		sr_puts(&b, ".copy(:m)` takes one member Symbol");
		reject(c, FE_SB033, x, &b);
		return 1;
	}
	sr_str mname = nstr(as[0], "value");
	fe_kernel_field *kf = fe_kernel_type_decl_field(d, mname);
	if (!kf) {
		sr_buf b = {0};
		fe_fmt_s(&b, d->const_name);
		sr_puts(&b, " (");
		fe_fmt_s(&b, d->name);
		sr_puts(&b, ") declares no member `");
		fe_fmt_s(&b, mname);
		sr_puts(&b, "`");
		reject(c, FE_SB033, as[0], &b);
		return 1;
	}
	if (!sr_eqc(kf->kind, "array")) {
		sr_buf b = {0};
		sr_puts(&b, "member ");
		fe_fmt_s(&b, kf->name);
		sr_puts(&b, " is not a byte array (`[:u8, N]`) — read it with `");
		fe_fmt_s(&b, t);
		sr_puts(&b, ".load.");
		fe_fmt_s(&b, kf->name);
		sr_puts(&b, "`");
		reject(c, FE_SB033, as[0], &b);
		return 1;
	}
	if (f->bits != 8 || f->count != kf->count) {
		sr_buf b = {0};
		sr_puts(&b, "event member ");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, " of ");
		fe_fmt_s(&b, rec->const_name);
		sr_puts(&b, " has ");
		fe_fmt_d(&b, f->count);
		sr_puts(&b, " elements but ");
		fe_fmt_s(&b, d->const_name);
		sr_puts(&b, ".");
		fe_fmt_s(&b, kf->name);
		sr_puts(&b, " has ");
		fe_fmt_d(&b, kf->count);
		sr_puts(&b, " — the copy is a fixed N bytes into a `[:u8, N]` member, declare the same N");
		reject(c, FE_SB033, x, &b);
		return 1;
	}
	fe_expr *e = new_expr(c, "zarr", x);
	e->var = t;
	e->op = d->name;
	e->path = kf->name;
	e->field = f;
	*out = e;
	return 1;
}

/* ring.go recordMake */
fe_expr *fe_record_make(fe_prog_ctx *c, const sr_node *mk, fe_record_decl *rec, fe_map_decl *m, sr_str ref_var)
{
	if (!is_type(mk, "CallNode") || !sr_eqc(nstr(mk, "name"), "new") || !sr_eq(fe_const_name(c->a, recv_of(c, mk)), rec->const_name)) {
		sr_buf b = {0};
		sr_puts(&b, "the value is `");
		fe_fmt_s(&b, rec->const_name);
		sr_puts(&b, ".new(…)` with every member");
		reject(c, FE_SB024, mk, &b);
		return NULL;
	}
	size_t n_vs;
	const sr_node **vs = fe_args(c->a, mk, &n_vs);
	for (size_t i = 0; i < n_vs; i++) {
		if (is_type(vs[i], "KeywordHashNode") || is_type(vs[i], "SplatNode")) {
			sr_buf b = {0};
			fe_fmt_s(&b, rec->const_name);
			sr_puts(&b, ".new takes positional arguments only");
			reject(c, FE_SB024, vs[i], &b);
			return NULL;
		}
	}
	if (n_vs != rec->n_fields) {
		sr_buf b = {0};
		fe_fmt_s(&b, rec->const_name);
		sr_puts(&b, ".new must give all ");
		fe_fmt_d(&b, (int64_t)rec->n_fields);
		sr_puts(&b, " members explicitly, got ");
		fe_fmt_d(&b, (int64_t)n_vs);
		sr_puts(&b, " (an omitted member is nil, which Spinel types as Integer — upstream_suspects S5)");
		reject(c, FE_SB024, mk, &b);
		return NULL;
	}
	fe_expr *e = new_expr(c, "rmake", mk);
	e->map = m;
	for (size_t i = 0; i < n_vs; i++) {
		const sr_node *x = vs[i];
		fe_record_field *f = &rec->fields[i];
		if (f->pad) {
			bigint lit = {0};
			int ok = is_type(x, "IntegerNode");
			if (ok) ok = fe_literal(c->z->z, c->a, x, &lit);
			int zero = ok && lit.n == 0;
			bigint_free(&lit);
			if (!zero) {
				sr_buf b = {0};
				sr_puts(&b, "padding member ");
				fe_fmt_s(&b, f->name);
				sr_puts(&b, " must be the literal 0");
				reject(c, FE_SB024, x, &b);
				return NULL;
			}
			fe_expr *z = new_expr(c, "lit", x);
			z->lit = sr_alloc(sizeof *z->lit);
			z->iv = fe_point(intv_from_i64(0));
			expr_push(e, z);
			continue;
		}
		if (f->count > 0) { /* an array member is `Array.new(N, 0)` only (every element 0 in record.make) */
			if (fe_ctx_copy_other_kind(c, x)) return NULL;
			if (fe_is_tp_copy(c, x)) { /* the ring output's `ctx.copy(:f)`: 0 here, written into the reservation after store_record */
				if (!c->ring_make) {
					sr_buf b = {0};
					sr_puts(&b, "`");
					fe_fmt_s(&b, c->param);
					sr_puts(&b, ".copy(:f)` is accepted only as an array member's argument of `R.output(S.new(…))` or as `r.load.<member> = ");
					fe_fmt_s(&b, c->param);
					sr_puts(&b, ".copy(:f)`");
					reject(c, FE_SB028, x, &b);
					return NULL;
				}
				int ok;
				fe_tp_field *tf = fe_tp_copy_field(c, x, x, f, rec->const_name, &ok);
				if (!ok) return NULL;
				fe_expr *z = new_expr(c, "zarr", x);
				z->tp_copy = tf;
				z->field = f;
				expr_push(e, z);
				continue;
			}
			fe_expr *cp;
			if (ring_copy(c, x, f, rec, &cp)) {
				if (!cp) return NULL;
				expr_push(e, cp);
				continue;
			}
			if (!fe_zero_array(c, x, f->count)) {
				sr_buf b = {0};
				sr_puts(&b, "the array member ");
				fe_fmt_s(&b, f->name);
				sr_puts(&b, " is given as `Array.new(");
				fe_fmt_d(&b, f->count);
				sr_puts(&b, ", 0)` in ");
				fe_fmt_s(&b, rec->const_name);
				sr_puts(&b, ".new — its elements are not values on the eBPF side");
				reject(c, FE_SB024, x, &b);
				return NULL;
			}
			expr_push(e, new_expr(c, "zarr", x));
			continue;
		}
		fe_expr *v = fe_field_value(c, x, f, m, ref_var);
		if (!v) return NULL;
		expr_push(e, v);
	}
	return e;
}

/* the value of a bigint that fits an int64 (Go: IsInt64 then Int64) */
int fe_big_is_i64(const bigint *x, int64_t *v)
{
	if (x->n == 0) {
		*v = 0;
		return 1;
	}
	if (x->n > 2) return 0;
	uint64_t m = x->l[0] | (x->n == 2 ? (uint64_t)x->l[1] << 32 : 0);
	if (!x->neg) {
		if (m > (uint64_t)INT64_MAX) return 0;
		*v = (int64_t)m;
	} else {
		if (m > (uint64_t)INT64_MAX + 1) return 0;
		*v = (int64_t)(0 - m);
	}
	return 1;
}

/* ring.go zeroArray: x is `Array.new(n, 0)` (literals) */
int fe_zero_array(fe_prog_ctx *c, const sr_node *x, int64_t n)
{
	if (!x || !is_type(x, "CallNode") || !sr_eqc(nstr(x, "name"), "new") || !sr_eqc(fe_const_name(c->a, recv_of(c, x)), "Array")) return 0;
	size_t n_as;
	const sr_node **as = fe_args(c->a, x, &n_as);
	if (n_as != 2 || !is_type(as[0], "IntegerNode") || !is_type(as[1], "IntegerNode")) return 0;
	bigint a = {0}, b = {0};
	int ok1 = fe_literal(c->z->z, c->a, as[0], &a);
	int ok2 = fe_literal(c->z->z, c->a, as[1], &b);
	int64_t av = 0;
	int res = ok1 && ok2 && fe_big_is_i64(&a, &av) && av == n && b.n == 0;
	bigint_free(&a);
	bigint_free(&b);
	return res;
}

/* ring.go outputIsCondition: the output call is the whole condition of an if / unless (one `!` may sit between) */
int fe_output_is_condition(fe_prog_ctx *c, const sr_node *n)
{
	int64_t *pid = sr_imap_get(&c->a->parent, n->id);
	const sr_node *p = pid ? fe_ast_node(c->a, *pid) : NULL;
	if (p && is_type(p, "CallNode") && sr_eqc(nstr(p, "name"), "!") && recv_of(c, p) == n) {
		n = p;
		int64_t *gid = sr_imap_get(&c->a->parent, p->id);
		p = gid ? fe_ast_node(c->a, *gid) : NULL;
	}
	return p && (is_type(p, "IfNode") || is_type(p, "UnlessNode")) && fe_ast_ref(c->a, p, "predicate") == n;
}
