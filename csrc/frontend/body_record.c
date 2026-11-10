/* body_record — record.go of G1: member reads and writes of a borrowed record entry, the record `update`, element access of array
 * members, and oneReasonEach. Each function names the Go it follows (internal/frontend/record.go at main c204310). The Go mutation hooks
 * (no-rmw) are not ported (the user path). */
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

static void reject(fe_prog_ctx *c, fe_code code, const sr_node *n, sr_buf *b) { fe_ctx_add(c, FE_REJECTED, code, n, sr_bufstr(b)); }

static void expr_push(fe_expr *e, fe_expr *a)
{
	e->args = sr_grow(e->args, e->n_args * sizeof *e->args, (e->n_args + 1) * sizeof *e->args);
	e->args[e->n_args++] = a;
	e->args_nil = 0;
}

static fe_expr *new_expr(fe_prog_ctx *c, const char *kind, const sr_node *at)
{
	fe_expr *e = sr_alloc(sizeof *e);
	e->args_nil = 1;
	e->kind = sr_cstr(kind);
	e->pos = fe_pos_of(c->z->z, c->a, at);
	return e;
}

static fe_ival full_i64(void) { return fe_iv(intv_from_i64(INT64_MIN), intv_from_i64(INT64_MAX)); }

static int ends_with_eq(sr_str s) { return s.n > 0 && s.p[s.n - 1] == '='; }

/* name != "==" && name != "!=" */
static int is_setter(sr_str name) { return ends_with_eq(name) && !sr_eqc(name, "==") && !sr_eqc(name, "!="); }

static void member_missing(fe_prog_ctx *c, const sr_node *n, const fe_map_decl *m, sr_str name)
{
	sr_buf b = {0};
	sr_puts(&b, "record ");
	fe_fmt_s(&b, m->record->const_name);
	sr_puts(&b, " has no member `");
	fe_fmt_s(&b, name);
	sr_puts(&b, "`");
	reject(c, FE_SB002, n, &b);
}

static void member_padding(fe_prog_ctx *c, const sr_node *n, const fe_record_field *f)
{
	sr_buf b = {0};
	sr_puts(&b, "`");
	fe_fmt_s(&b, f->name);
	sr_puts(&b, "` is padding — it is neither read nor written on the eBPF side");
	reject(c, FE_SB024, n, &b);
}

/* record.go loadCallee */
int fe_load_callee(fe_prog_ctx *c, const sr_node *load)
{
	int ok;
	sr_str callee = fe_callee(c, load, &ok);
	if (!ok) return 0;
	if (!sr_eqc(callee, "RecordRef#load")) {
		sr_buf b = {0};
		sr_puts(&b, "`load` resolves to ");
		fe_fmt_s(&b, callee);
		sr_puts(&b, ", not BPF::RecordRef#load");
		reject(c, FE_SB011, load, &b);
		return 0;
	}
	return 1;
}

/* the value of a Go readsRef walk: does the node read the local `ref` */
typedef struct {
	sr_str ref;
	int found;
} reads_ref;

static int reads_ref_walk(void *u, const sr_node *x)
{
	reads_ref *r = u;
	if (is_type(x, "LocalVariableReadNode") && sr_eq(nstr(x, "name"), r->ref)) r->found = 1;
	return !r->found;
}

/* record.go readsRef */
static int reads_ref_syntax(fe_prog_ctx *c, const sr_node *n, sr_str ref)
{
	reads_ref r = {ref, 0};
	fe_walk(c->a, n, reads_ref_walk, &r);
	return r.found;
}

/* the `exempt` and RMW test shared by the member writes: the value reads the same entry (a per-CPU map is exempt) */
static int rmw_entry(fe_prog_ctx *c, const fe_map_decl *m, const sr_node *val, sr_str ref) { return !fe_exempt(c, m) && fe_reads_ref_via(c, val, ref); }

/* record.go fieldValue */
fe_expr *fe_field_value(fe_prog_ctx *c, const sr_node *n, fe_record_field *f, fe_map_decl *m, sr_str ref_var)
{
	fe_expr *e = fe_ctx_expr(c, n, ref_var);
	if (!e) return NULL;
	if (e->bool_) {
		fe_ctx_add(c, FE_REJECTED, FE_SB001, n, sr_cstr("a bool cannot be stored in a record member"));
		return NULL;
	}
	if (e->wide) {
		static const char *const ok_kinds[] = {"u64op", "load", "fload", "ktime", "pidtgid", "retval", "kparg", "rawarg", "tpfield", "gload", "kfload"};
		int pass = 0;
		if (f->bits == 64 && !f->is_signed) {
			if (sr_eqc(e->kind, "var") && e->wide) pass = 1;
			for (size_t i = 0; i < sizeof ok_kinds / sizeof *ok_kinds; i++)
				if (sr_eqc(e->kind, ok_kinds[i])) pass = 1;
		}
		if (pass) return e;
		fe_value_ok(c, e, n);
		return NULL;
	}
	fe_ival r = fe_record_field_range(f);
	if (!fe_ival_within(e->iv, r.lo, r.hi)) {
		sr_buf b = {0};
		sr_puts(&b, "the value's range ");
		fe_fmt_s(&b, fe_ival_text(e->iv));
		sr_puts(&b, " does not fit member ");
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, ".");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, " (");
		fe_fmt_s(&b, fe_record_field_type_name(f));
		sr_puts(&b, " ");
		fe_fmt_s(&b, fe_ival_text(r));
		sr_puts(&b, ") — the store would truncate silently; narrow it (e.g. `& 0xFF`)");
		reject(c, FE_SB014, n, &b);
		return NULL;
	}
	return e;
}

/* the interval of a loaded member (fieldRead, elemRead): u64 is Wide, 64-bit signed the full i64, else the member's range */
static void load_range(fe_expr *e, const fe_record_field *f)
{
	if (f->bits == 64 && !f->is_signed) {
		e->iv = fe_iv(intv_from_i64(0), intv_from_u64(UINT64_MAX));
		e->wide = 1;
	} else {
		e->iv = fe_record_field_range(f);
		if (f->bits == 64) e->iv = full_i64();
	}
}

/* record.go fieldRead: `p.load.m` */
fe_expr *fe_field_read(fe_prog_ctx *c, const sr_node *n, const sr_node *load, sr_str ref_var)
{
	fe_map_decl *m = fe_name_get(&c->ref_map, ref_var);
	sr_str name = nstr(n, "name");
	fe_record_field *f = fe_record_decl_field(m->record, name);
	if (!f && !fe_member_like(name)) return NULL; /* p.load.dup / == …: lookupCheck's walk stops it (SB005) */
	if (f && !f->pad && !fe_load_callee(c, load)) return NULL;
	size_t n_as;
	fe_args(c->a, n, &n_as);
	if (!f) {
		member_missing(c, n, m, name);
		return NULL;
	}
	if (f->pad) {
		member_padding(c, n, f);
		return NULL;
	}
	if (n_as != 0 || fe_ast_ref(c->a, n, "block") != NULL) {
		fe_ctx_add(c, FE_REJECTED, FE_SB002, n, sr_cstr("a member read takes no arguments"));
		return NULL;
	}
	if (f->count > 0) {
		sr_buf b = {0};
		sr_puts(&b, "the array member ");
		fe_fmt_s(&b, name);
		sr_puts(&b, " is read by element (`");
		fe_fmt_s(&b, ref_var);
		sr_puts(&b, ".load.");
		fe_fmt_s(&b, name);
		sr_puts(&b, "[k]`) — the array itself is not a value on the eBPF side");
		reject(c, FE_SB024, n, &b);
		return NULL;
	}
	fe_expr *e = new_expr(c, "fload", n);
	e->ref = ref_var;
	e->map = m;
	e->field = f;
	load_range(e, f);
	return e;
}

/* record.go arrayIndex: the literal index of an array member, -2 for a variable index, -1 for an error (SB031 added) */
static int64_t array_index(fe_prog_ctx *c, const sr_node *x, const fe_record_field *f, sr_str ref)
{
	if (!is_type(x, "IntegerNode")) return -2; /* a variable index: the caller proves it by interval */
	bigint v = {0};
	if (!fe_literal(c->z->z, c->a, x, &v)) return -1;
	int64_t iv64 = 0;
	int bad = (v.neg && v.n > 0) || !fe_big_is_i64(&v, &iv64) || iv64 >= f->count;
	if (bad) {
		sr_buf b = {0};
		sr_puts(&b, "the index ");
		fe_fmt_big(&b, &v);
		sr_puts(&b, " is outside [0, ");
		fe_fmt_d(&b, f->count - 1);
		sr_puts(&b, "] of ");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".load.");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, " (Ruby reads nil past the end and counts a negative index from the end; BPF has neither)");
		reject(c, FE_SB031, x, &b);
		bigint_free(&v);
		return -1;
	}
	bigint_free(&v);
	return iv64;
}

/* record.go varIndex: a variable index whose interval is inside [0, N-1] is the index Expr, else SB031 and NULL */
static fe_expr *var_index(fe_prog_ctx *c, const sr_node *x, const fe_record_field *f, sr_str ref, sr_str ref_var)
{
	fe_expr *e = fe_ctx_expr(c, x, ref_var);
	if (!e) return NULL;
	if (e->bool_ || e->wide) {
		sr_buf b = {0};
		sr_puts(&b, "the index of ");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".load.");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, " must be an Integer (not a bool, not an unnarrowed u64 value)");
		reject(c, FE_SB031, x, &b);
		return NULL;
	}
	if (!fe_ival_within(e->iv, intv_from_i64(0), intv_from_i64(f->count - 1))) {
		sr_buf b = {0};
		sr_puts(&b, "the index of ");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".load.");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, " has range ");
		fe_fmt_s(&b, fe_ival_text(e->iv));
		sr_puts(&b, ", not inside [0, ");
		fe_fmt_d(&b, f->count - 1);
		sr_puts(&b, "]");
		if (intv_sign(e->iv.lo) < 0) sr_puts(&b, " — a negative index counts from the end in Ruby, BPF has no such index");
		sr_puts(&b, "; ");
		fe_fmt_s(&b, fe_index_hint(f->count));
		reject(c, FE_SB031, x, &b);
		return NULL;
	}
	return e;
}

/* record.go elemRead: `p.load.m[k]` */
fe_expr *fe_elem_read(fe_prog_ctx *c, const sr_node *n, const sr_node *mem, const sr_node *load, sr_str ref_var)
{
	fe_map_decl *m = fe_name_get(&c->ref_map, ref_var);
	fe_record_field *f = fe_record_decl_field(m->record, nstr(mem, "name"));
	if (!f || f->pad) return fe_field_read(c, mem, load, ref_var); /* a wrong name and padding are the member read's messages */
	size_t n_mem, n_n;
	fe_args(c->a, mem, &n_mem);
	const sr_node **nas = fe_args(c->a, n, &n_n);
	if (f->count == 0) {
		sr_buf b = {0};
		sr_puts(&b, "member ");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, " of record ");
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, " is not an array — `[]` is for array members");
		reject(c, FE_SB002, n, &b);
		return NULL;
	}
	if (n_mem != 0 || n_n != 1 || fe_ast_ref(c->a, n, "block") != NULL) {
		sr_buf b = {0};
		sr_puts(&b, "an element read is `");
		fe_fmt_s(&b, ref_var);
		sr_puts(&b, ".load.");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, "[k]` with one index");
		reject(c, FE_SB002, n, &b);
		return NULL;
	}
	if (!fe_load_callee(c, load)) return NULL;
	int64_t k = array_index(c, nas[0], f, ref_var);
	fe_expr *e;
	if (k == -2) { /* a variable index: prove it by interval, then ebpf.ref.index */
		fe_expr *ix = var_index(c, nas[0], f, ref_var, ref_var);
		if (!ix) return NULL;
		e = new_expr(c, "iload", n);
		e->ref = ref_var;
		e->map = m;
		e->field = f;
		expr_push(e, ix);
	} else if (k < 0) {
		return NULL;
	} else {
		e = new_expr(c, "fload", n);
		e->ref = ref_var;
		e->map = m;
		e->field = f;
		sr_buf b = {0};
		sr_putstr(&b, f->name);
		sr_printf(&b, "[%lld]", (long long)k);
		e->path = sr_bufstr(&b);
	}
	load_range(e, f);
	return e;
}

/* record.go recordCall: returns Go's first bool (a statement was made), *ok2 the second (the record's form); *out the Stmt */
static int record_call_impl(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2)
{
	*ok2 = 0;
	*out = fe_stmt_new("");
	const sr_node *recv = recv_of(c, n);
	sr_str name = nstr(n, "name");
	/* p.load.m[k] = e */
	if (sr_eqc(name, "[]=") && recv && is_type(recv, "CallNode")) {
		const sr_node *ld = recv_of(c, recv);
		if (ld && is_type(ld, "CallNode") && sr_eqc(nstr(ld, "name"), "load")) {
			const sr_node *pv = recv_of(c, ld);
			if (pv && is_type(pv, "LocalVariableReadNode") && fe_name_get(&c->refs, nstr(pv, "name")) &&
			    ((fe_map_decl *)fe_name_get(&c->ref_map, nstr(pv, "name")))->record) {
				sr_str ref = nstr(pv, "name");
				if (!sr_eq(ref, ref_var)) return 0; /* outside the arm: lookupCheck's walk stops it */
				fe_map_decl *m = fe_name_get(&c->ref_map, ref);
				if (!fe_load_callee(c, ld)) {
					*ok2 = 1;
					return 0;
				}
				fe_record_field *f = fe_record_decl_field(m->record, nstr(recv, "name"));
				size_t n_as;
				const sr_node **as = fe_args(c->a, n, &n_as);
				if (!f) {
					member_missing(c, n, m, nstr(recv, "name"));
					*ok2 = 1;
					return 0;
				}
				if (f->count == 0) {
					sr_buf b = {0};
					sr_puts(&b, "member ");
					fe_fmt_s(&b, f->name);
					sr_puts(&b, " of record ");
					fe_fmt_s(&b, m->record->const_name);
					sr_puts(&b, " is not an array — `[]=` is for array members");
					reject(c, FE_SB002, n, &b);
					*ok2 = 1;
					return 0;
				}
				if (n_as != 2) {
					sr_buf b = {0};
					sr_puts(&b, "an element write is `");
					fe_fmt_s(&b, ref);
					sr_puts(&b, ".load.");
					fe_fmt_s(&b, f->name);
					sr_puts(&b, "[k] = v`");
					reject(c, FE_SB002, n, &b);
					*ok2 = 1;
					return 0;
				}
				fe_note_flow(c, as[1], m, n);
				if (rmw_entry(c, m, as[1], ref)) { /* a read-modify-write of the same entry */
					sr_buf b = {0};
					sr_puts(&b, "`");
					fe_fmt_s(&b, ref);
					sr_puts(&b, ".load.");
					fe_fmt_s(&b, f->name);
					sr_puts(&b, "[…] = …` stores a value read from the same map entry — concurrent CPUs lose updates; use `");
					fe_fmt_s(&b, ref);
					sr_puts(&b, ".atomic_add(:");
					fe_fmt_s(&b, f->name);
					sr_puts(&b, ", k, d)`");
					reject(c, FE_SB019, n, &b);
					*ok2 = 1;
					return 0;
				}
				int64_t k = array_index(c, as[0], f, ref);
				fe_expr *ix = NULL;
				if (k == -2) { /* a variable index: prove it by interval, then ebpf.ref.index */
					ix = var_index(c, as[0], f, ref, ref_var);
					if (!ix) {
						*ok2 = 1;
						return 0;
					}
				} else if (k < 0) {
					*ok2 = 1;
					return 0;
				}
				fe_expr *v = fe_field_value(c, as[1], f, m, ref_var);
				*ok2 = 1;
				if (!v) return 0;
				out->var = ref;
				out->map = m;
				out->field = f;
				out->value = v;
				out->pos = fe_pos_of(c->z->z, c->a, n);
				if (ix) {
					out->kind = sr_cstr("istore");
					out->key = ix;
				} else {
					out->kind = sr_cstr("fstore");
					sr_buf b = {0};
					sr_putstr(&b, f->name);
					sr_printf(&b, "[%lld]", (long long)k);
					out->path = sr_bufstr(&b);
				}
				return 1;
			}
		}
	}
	/* a write through a kernel struct member path (`t.load.a.m = v`) is refused by name: a path is read only */
	if (is_setter(name) && fe_kptr_path_recv(c, recv)) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, name);
		sr_puts(&b, " v` writes a kernel struct member through a member path — a member path is read only");
		reject(c, FE_SB033, n, &b);
		*ok2 = 1;
		return 0;
	}
	/* p.load.m = e */
	if (recv && is_type(recv, "CallNode") && sr_eqc(nstr(recv, "name"), "load") && is_setter(name)) {
		const sr_node *pv = recv_of(c, recv);
		if (!pv || !is_type(pv, "LocalVariableReadNode") || !fe_name_get(&c->refs, nstr(pv, "name")) ||
		    !((fe_map_decl *)fe_name_get(&c->ref_map, nstr(pv, "name")))->record)
			return 0;
		sr_str ref = nstr(pv, "name");
		if (!sr_eq(ref, ref_var)) return 0; /* outside the arm: lookupCheck's walk stops it */
		fe_map_decl *m = fe_name_get(&c->ref_map, ref);
		if (!fe_load_callee(c, recv)) {
			*ok2 = 1;
			return 0;
		}
		sr_str fname = {name.p, name.n - 1}; /* TrimSuffix(name, "=") */
		fe_record_field *f = fe_record_decl_field(m->record, fname);
		size_t n_as;
		const sr_node **as = fe_args(c->a, n, &n_as);
		*ok2 = 1;
		if (!f) {
			member_missing(c, n, m, fname);
			return 0;
		}
		if (f->pad) {
			member_padding(c, n, f);
			return 0;
		}
		if (n_as != 1) {
			fe_ctx_add(c, FE_REJECTED, FE_SB002, n, sr_cstr("a member write takes one value"));
			return 0;
		}
		if (is_type(as[0], "CallNode") && sr_eqc(nstr(as[0], "name"), "copy") && fe_is_kptr_read(c, recv_of(c, as[0]))) /* r.load.m = t.copy(:f) */
			return fe_kcopy_stmt(c, n, as[0], ref, m, f, out);
		if (fe_ctx_copy_other_kind(c, as[0])) return 0; /* a copy of a ctx that is not a tracepoint's */
		if (fe_is_tp_copy(c, as[0])) /* r.load.m = ctx.copy(:f) */
			return fe_tpcopy_stmt(c, n, as[0], ref, m, f, out);
		if (f->count > 0) {
			sr_buf b = {0};
			sr_puts(&b, "the array member ");
			fe_fmt_s(&b, f->name);
			sr_puts(&b, " is written by element (`");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".load.");
			fe_fmt_s(&b, f->name);
			sr_puts(&b, "[k] = v`) — not as a whole");
			reject(c, FE_SB024, n, &b);
			return 0;
		}
		fe_note_flow(c, as[0], m, n);
		if (rmw_entry(c, m, as[0], ref)) { /* the local's origin too; a per-CPU map is exempt */
			sr_buf b = {0};
			sr_puts(&b, "`");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".load.");
			fe_fmt_s(&b, f->name);
			sr_puts(&b, " = …` stores a value read from the same map entry — concurrent CPUs lose updates; use `");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".atomic_add(:");
			fe_fmt_s(&b, f->name);
			sr_puts(&b, ", d)`");
			reject(c, FE_SB019, n, &b);
			return 0;
		}
		fe_expr *v = fe_field_value(c, as[0], f, m, ref_var);
		if (!v) return 0;
		out->kind = sr_cstr("fstore");
		out->var = ref;
		out->map = m;
		out->field = f;
		out->value = v;
		out->pos = fe_pos_of(c->z->z, c->a, n);
		return 1;
	}
	/* p.atomic_add(:m, d) */
	if (sr_eqc(name, "atomic_add") && recv && is_type(recv, "LocalVariableReadNode") && fe_name_get(&c->refs, nstr(recv, "name")) &&
	    ((fe_map_decl *)fe_name_get(&c->ref_map, nstr(recv, "name")))->record) {
		sr_str ref = nstr(recv, "name");
		if (!sr_eq(ref, ref_var)) return 0;
		fe_map_decl *m = fe_name_get(&c->ref_map, ref);
		*ok2 = 1;
		int ok;
		sr_str callee = fe_callee(c, n, &ok);
		if (!ok) return 0;
		if (!sr_eqc(callee, "RecordRef#atomic_add")) {
			sr_buf b = {0};
			sr_puts(&b, "`atomic_add` resolves to ");
			fe_fmt_s(&b, callee);
			sr_puts(&b, ", not BPF::RecordRef#atomic_add");
			reject(c, FE_SB011, n, &b);
			return 0;
		}
		size_t n_as;
		const sr_node **as = fe_args(c->a, n, &n_as);
		if ((n_as != 2 && n_as != 3) || !is_type(as[0], "SymbolNode")) {
			sr_buf b = {0};
			sr_puts(&b, "`");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".atomic_add` takes a member Symbol literal and a delta (`");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".atomic_add(:member, d)` — an array member also takes the index: `");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".atomic_add(:member, k, d)`)");
			reject(c, FE_SB002, n, &b);
			return 0;
		}
		sr_str mname = nstr(as[0], "value");
		fe_record_field *f = fe_record_decl_field(m->record, mname);
		if (!f || f->pad) {
			sr_buf b = {0};
			sr_puts(&b, "record ");
			fe_fmt_s(&b, m->record->const_name);
			sr_puts(&b, " has no member `");
			fe_fmt_s(&b, mname);
			sr_puts(&b, "` to add to");
			reject(c, FE_SB002, as[0], &b);
			return 0;
		}
		if (f->bits != 32 && f->bits != 64) {
			sr_buf b = {0};
			sr_puts(&b, "member ");
			fe_fmt_s(&b, f->name);
			sr_puts(&b, " is ");
			fe_fmt_s(&b, fe_record_field_type_name(f));
			sr_puts(&b, " — atomic_add needs a 32- or 64-bit member (BPF has no narrower atomic add)");
			reject(c, FE_SB024, as[0], &b);
			return 0;
		}
		if ((f->count > 0) != (n_as == 3)) {
			sr_buf b = {0};
			sr_puts(&b, "`");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".atomic_add(:");
			fe_fmt_s(&b, f->name);
			sr_puts(&b, ", …)` takes ");
			sr_puts(&b, f->count > 0 ? "the index and the delta — `atomic_add(:m, k, d)` for an array member"
						 : "only the delta — the member is not an array");
			reject(c, FE_SB002, n, &b);
			return 0;
		}
		sr_str path = {0};
		if (f->count > 0) { /* a constant index only: bpf-mlir has no atomic add on a variable-index element */
			if (!is_type(as[1], "IntegerNode")) {
				sr_buf b = {0};
				sr_puts(&b, "`");
				fe_fmt_s(&b, ref);
				sr_puts(&b, ".atomic_add(:");
				fe_fmt_s(&b, f->name);
				sr_puts(&b, ", k, d)` needs a literal index — bpf-mlir has no atomic add on a variable-index element; use a per-CPU record map (`BPF::PerCpuRecordMap`, then `");
				fe_fmt_s(&b, ref);
				sr_puts(&b, ".load.");
				fe_fmt_s(&b, f->name);
				sr_puts(&b, "[i] += …` is not shared) or a literal index");
				reject(c, FE_SB031, as[1], &b);
				return 0;
			}
			int64_t k = array_index(c, as[1], f, ref);
			if (k < 0) return 0;
			sr_buf b = {0};
			sr_putstr(&b, f->name);
			sr_printf(&b, "[%lld]", (long long)k);
			path = sr_bufstr(&b);
			as++; /* as[1] is the delta */
		}
		fe_note_flow(c, as[1], m, n);
		if (rmw_entry(c, m, as[1], ref)) { /* the delta reads the same entry (directly or by origin) */
			sr_buf b = {0};
			sr_puts(&b, "`");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".atomic_add(:");
			fe_fmt_s(&b, f->name);
			sr_puts(&b, ", …)` adds a value read from the same entry — concurrent CPUs interleave the read and the add; use a delta that does not read `");
			fe_fmt_s(&b, ref);
			sr_puts(&b, "`");
			reject(c, FE_SB019, n, &b);
			return 0;
		}
		fe_expr *d = fe_field_value(c, as[1], f, m, ref_var);
		if (!d) return 0;
		out->kind = sr_cstr("fatomic");
		out->var = ref;
		out->map = m;
		out->field = f;
		out->path = path;
		out->value = d;
		out->pos = fe_pos_of(c->z->z, c->a, n);
		return 1;
	}
	return 0;
}

/* the message of recordUpdate's rmwFirst callback */
typedef struct {
	fe_map_decl *m;
} upd_ctx;

static sr_str upd_msg(void *u, sr_str ref)
{
	upd_ctx *uc = u;
	sr_buf b = {0};
	sr_puts(&b, "`");
	fe_fmt_s(&b, uc->m->name);
	sr_puts(&b, ".update` stores a value read from the same map (`");
	fe_fmt_s(&b, ref);
	sr_puts(&b, ".load`) — concurrent CPUs lose updates (keys must be different literals to accept this form)");
	return sr_bufstr(&b);
}

/* record.go recordUpdate: returns Go's bool, *out the Stmt */
int fe_record_update(fe_prog_ctx *c, const sr_node *n, sr_str name, fe_map_decl *m, const sr_node *const *as, size_t n_as, sr_str ref_var,
		     fe_stmt *out)
{
	*out = fe_stmt_new("");
	if (!sr_eqc(name, "update")) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".");
		fe_fmt_s(&b, name);
		sr_puts(&b, "` is not accepted on a record map — add to a member with `p = ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".lookup(k)`, `if p`, `p.atomic_add(:member, d)`");
		reject(c, FE_SB002, n, &b);
		return 0;
	}
	if (n_as != 2 || fe_ast_ref(c->a, n, "block") != NULL) {
		sr_buf b = {0};
		sr_puts(&b, "`update` takes exactly two arguments (key, ");
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, ".new(…))");
		reject(c, FE_SB002, n, &b);
		return 0;
	}
	fe_expr *k = fe_ctx_key(c, as[0], m, ref_var);
	const sr_node *mk = as[1];
	for (size_t i = 0; i < c->refs.n; i++) {
		fe_name_entry *en = &c->refs.e[i];
		if (en->removed || !en->val) continue;
		fe_map_decl *rm = fe_name_get(&c->ref_map, en->key);
		if (rm && rm->record && is_type(mk, "CallNode") && !sr_eqc(nstr(mk, "name"), "new") && reads_ref_syntax(c, mk, en->key))
			return 0; /* p.load / p.load.dup: lookupCheck's walk stops it (SB005) */
	}
	if (!is_type(mk, "CallNode") || !sr_eqc(nstr(mk, "name"), "new") || !sr_eq(fe_const_name(c->a, recv_of(c, mk)), m->record->const_name)) {
		sr_buf b = {0};
		sr_puts(&b, "the value of ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".update is `");
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, ".new(…)` with every member");
		reject(c, FE_SB024, mk, &b);
		return 0;
	}
	if (fe_record_decl_has_array(m->record)) { /* a record with an array member is not built by record.make yet: write its elements by member */
		sr_buf b = {0};
		sr_puts(&b, "record ");
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, " has an array member — `");
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, ".new(…)` is not built on the eBPF side yet; write its members with `p = ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".lookup(k)`, `if p`, `p.load.m[k] = v`");
		reject(c, FE_SB024, mk, &b);
		return 0;
	}
	size_t n_vs;
	const sr_node **vs = fe_args(c->a, mk, &n_vs);
	for (size_t i = 0; i < n_vs; i++) {
		if (is_type(vs[i], "KeywordHashNode") || is_type(vs[i], "SplatNode")) {
			sr_buf b = {0};
			fe_fmt_s(&b, m->record->const_name);
			sr_puts(&b, ".new takes positional arguments only");
			reject(c, FE_SB024, vs[i], &b);
			return 0;
		}
	}
	if (n_vs != m->record->n_fields) {
		sr_buf b = {0};
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, ".new must give all ");
		fe_fmt_d(&b, (int64_t)m->record->n_fields);
		sr_puts(&b, " members explicitly, got ");
		fe_fmt_d(&b, (int64_t)n_vs);
		sr_puts(&b, " (an omitted member is nil, which Spinel types as Integer — upstream_suspects S5)");
		reject(c, FE_SB024, mk, &b);
		return 0;
	}
	upd_ctx uc = {m};
	if (fe_rmw_first(c, n, mk, m, k, upd_msg, &uc)) return 0; /* the RMW check comes before the value's interval (after the shape's SB024) */
	fe_expr *e = new_expr(c, "rmake", mk);
	e->map = m;
	for (size_t i = 0; i < n_vs; i++) {
		const sr_node *x = vs[i];
		fe_record_field *f = &m->record->fields[i];
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
				return 0;
			}
			fe_expr *z = new_expr(c, "lit", x);
			z->lit = sr_alloc(sizeof *z->lit);
			z->iv = fe_point(intv_from_i64(0));
			expr_push(e, z);
			continue;
		}
		fe_expr *v = fe_field_value(c, x, f, m, ref_var);
		if (!v) return 0;
		expr_push(e, v);
	}
	if (!k) return 0;
	int rok = 0;
	sr_str ref = fe_reads_map(e, m, &rok);
	if (rok && !fe_exempt(c, m)) { /* per-CPU is exempt */
		fe_expr *lk = fe_name_get(&c->ref_key, ref);
		if (!lk || !sr_eqc(lk->kind, "lit") || !sr_eqc(k->kind, "lit") || bigint_cmp(lk->lit, k->lit) == 0) {
			fe_ctx_add(c, FE_REJECTED, FE_SB019, n, upd_msg(&uc, ref));
			return 0;
		}
	}
	out->kind = sr_cstr("update");
	out->map = m;
	out->key = k;
	out->value = e;
	out->pos = fe_pos_of(c->z->z, c->a, n);
	return 1;
}


/* recordCall returns (Stmt, ok, handled); the core reads the return value as `handled` and *ok2 as `ok` (see body_hash.c) */
int fe_record_call(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2)
{
	int handled;
	*ok2 = record_call_impl(c, n, ref_var, out, &handled);
	return handled;
}
