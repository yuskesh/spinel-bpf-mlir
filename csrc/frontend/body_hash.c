/* body_hash — hash.go of G1: the walk of the hash maps' status operations, record keys, the integer `atomic_add` of a borrowed
 * entry, and the per-CPU record member add. Each function names the Go it follows (internal/frontend/hash.go at main c204310).
 * The declaration side (hashMapDecl, sampleRecord) is in the steps 1-2 code. The Go mutation hooks are not ported (the user path). */
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

static const sr_node *parent_of(fe_prog_ctx *c, const sr_node *n)
{
	int64_t *pid = sr_imap_get(&c->a->parent, n->id);
	return pid ? fe_ast_node(c->a, *pid) : NULL;
}

static void expr_push(fe_expr *e, fe_expr *a)
{
	e->args = sr_grow(e->args, e->n_args * sizeof *e->args, (e->n_args + 1) * sizeof *e->args);
	e->args[e->n_args++] = a;
	e->args_nil = 0;
}

/* hash.go exempt: perCPUExempt over the program kinds of the whole file */
int fe_exempt(fe_prog_ctx *c, const fe_map_decl *m)
{
	return fe_per_cpu_exempt(m, c->z->top->root_kinds, c->z->top->n_root_kinds);
}

/* hash.go statusOps: update/insert/replace/delete/add_or_init -> the try_update flags (or "delete" / "add_or_init") */
static int status_op(sr_str name, const char **flags)
{
	static const struct {
		const char *op, *flags;
	} t[] = {{"update", "any"}, {"insert", "noexist"}, {"replace", "exist"}, {"delete", "delete"}, {"add_or_init", "add_or_init"}};
	for (size_t i = 0; i < sizeof t / sizeof *t; i++)
		if (sr_eqc(name, t[i].op)) {
			if (flags) *flags = t[i].flags;
			return 1;
		}
	return 0;
}

static int cmp_op(sr_str name)
{
	static const char *const ops[] = {"==", "!=", "<", "<=", ">", ">="};
	for (size_t i = 0; i < sizeof ops / sizeof *ops; i++)
		if (sr_eqc(name, ops[i])) return 1;
	return 0;
}

/* hash.go statusCall: *ok is Go's third result, *bad the second */
fe_map_decl *fe_status_call(fe_prog_ctx *c, const sr_node *n, int *bad, int *ok)
{
	*bad = 0;
	*ok = 0;
	if (!n || !is_type(n, "CallNode")) return NULL;
	if (!status_op(nstr(n, "name"), NULL)) return NULL;
	const sr_node *recv = recv_of(c, n);
	if (!recv || !is_type(recv, "ConstantReadNode")) return NULL;
	if (fe_name_get(&c->z->top->bad_hash, nstr(recv, "name"))) {
		*bad = 1;
		*ok = 1;
		return NULL;
	}
	fe_map_decl *m = fe_name_get(&c->z->top->maps, nstr(recv, "name"));
	if (!m || !fe_g1_map_is_hash(m)) return NULL;
	*ok = 1;
	return m;
}

/* hash.go statusParentOK: the call sits in a local assignment or as an operand of a comparison */
int fe_status_parent_ok(fe_prog_ctx *c, const sr_node *n)
{
	const sr_node *p = parent_of(c, n);
	if (p && is_type(p, "LocalVariableWriteNode") && fe_ast_ref(c->a, p, "value") == n) return 1;
	if (p && is_type(p, "ArgumentsNode")) p = parent_of(c, p);
	return p && is_type(p, "CallNode") && cmp_op(nstr(p, "name"));
}

/* the walk of statusLocalOK: how often the local is written and read below the program's def */
typedef struct {
	sr_str name;
	int64_t writes, reads;
} local_count;

static int count_local(void *u, const sr_node *x)
{
	local_count *lc = u;
	if (!sr_eq(nstr(x, "name"), lc->name)) return 1;
	if (sr_eqc(x->type, "LocalVariableWriteNode") || sr_eqc(x->type, "LocalVariableOperatorWriteNode") ||
	    sr_eqc(x->type, "LocalVariableOrWriteNode") || sr_eqc(x->type, "LocalVariableAndWriteNode"))
		lc->writes++;
	else if (sr_eqc(x->type, "LocalVariableReadNode"))
		lc->reads++;
	return 1;
}

/* hash.go statusLocalOK */
int fe_status_local_ok(fe_prog_ctx *c, const sr_node *w, fe_map_decl *m, sr_str op)
{
	sr_str name = nstr(w, "name");
	local_count lc = {name, 0, 0};
	fe_walk(c->a, c->def, count_local, &lc);
	if (lc.writes != 1 && fe_name_get(&c->status_reported, name)) return 0; /* said once at the first assignment */
	if (lc.writes != 1) {
		fe_name_set(&c->status_reported, name, (void *)1);
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, name);
		sr_puts(&b, "` holds the status of `");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".");
		fe_fmt_s(&b, op);
		sr_puts(&b, "` but is assigned ");
		fe_fmt_d(&b, lc.writes);
		sr_puts(&b, " times — a status local is assigned once (give each status its own name, so none is overwritten before it is read)");
		reject(c, FE_SB026, w, &b);
		return 0;
	}
	if (lc.reads == 0) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, name);
		sr_puts(&b, "` holds the status of `");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".");
		fe_fmt_s(&b, op);
		sr_puts(&b, "` but is never read — check it (e.g. `if ");
		fe_fmt_s(&b, name);
		sr_puts(&b, " != 0`) or drop it explicitly with `_ = ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".");
		fe_fmt_s(&b, op);
		sr_puts(&b, "(…)`");
		reject(c, FE_SB026, w, &b);
		return 0;
	}
	return 1;
}

/* the two texts of rmwFirst's callback in statusExpr */
typedef struct {
	fe_map_decl *m;
	sr_str name;
} rmw_ctx;

static sr_str rmw_msg(void *u, sr_str ref)
{
	rmw_ctx *r = u;
	sr_buf b = {0};
	if (sr_eqc(r->name, "add_or_init")) {
		sr_puts(&b, "`");
		fe_fmt_s(&b, r->m->name);
		sr_puts(&b, ".add_or_init` adds a value read from the same map (`");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".load`) — concurrent CPUs interleave the read and the add; use a delta that does not read ");
		fe_fmt_s(&b, r->m->const_name);
		return sr_bufstr(&b);
	}
	sr_puts(&b, "`");
	fe_fmt_s(&b, r->m->name);
	sr_puts(&b, ".");
	fe_fmt_s(&b, r->name);
	sr_puts(&b, "` stores a value read from the same map (`");
	fe_fmt_s(&b, ref);
	sr_puts(&b, ".load`) — concurrent CPUs lose updates; use `");
	fe_fmt_s(&b, r->m->const_name);
	sr_puts(&b, ".add_or_init` or `");
	fe_fmt_s(&b, ref);
	sr_puts(&b, ".atomic_add` inside `if ");
	fe_fmt_s(&b, ref);
	sr_puts(&b, "`");
	return sr_bufstr(&b);
}

static fe_ival full_i64(void) { return fe_iv(intv_from_i64(INT64_MIN), intv_from_i64(INT64_MAX)); }

/* hash.go statusExpr */
fe_expr *fe_status_expr(fe_prog_ctx *c, const sr_node *n, fe_map_decl *m, sr_str ref_var)
{
	sr_str name = nstr(n, "name");
	if (sr_eqc(name, "add_or_init") && m->record) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".add_or_init` takes integer values only — for a record value, `p = ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".lookup(k)`, `if p`, `p.atomic_add(:member, d)`, with `");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".insert(k, ");
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, ".new(…))` for a new key");
		reject(c, FE_SB002, n, &b);
		return NULL;
	}
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok) return NULL;
	sr_buf want_callee = {0};
	sr_putstr(&want_callee, fe_g1_map_class_name(m));
	sr_putc(&want_callee, '#');
	sr_putstr(&want_callee, name);
	if (!sr_eq(callee, sr_bufstr(&want_callee))) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, name);
		sr_puts(&b, "` resolves to ");
		fe_fmt_s(&b, callee);
		sr_puts(&b, ", not BPF::");
		fe_fmt_s(&b, fe_g1_map_class_name(m));
		sr_puts(&b, "#");
		fe_fmt_s(&b, name);
		reject(c, FE_SB011, n, &b);
		return NULL;
	}
	if (!fe_map_of(c, recv_of(c, n), n)) return NULL;
	size_t n_as;
	const sr_node **as = fe_args(c->a, n, &n_as);
	size_t want = sr_eqc(name, "delete") ? 1 : 2;
	if (n_as != want || fe_ast_ref(c->a, n, "block") != NULL) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".");
		fe_fmt_s(&b, name);
		sr_puts(&b, "` takes exactly ");
		fe_fmt_d(&b, (int64_t)want);
		sr_puts(&b, " argument(s)");
		reject(c, FE_SB002, n, &b);
		return NULL;
	}
	fe_expr *k = fe_ctx_key(c, as[0], m, ref_var);
	rmw_ctx rc = {m, name};
	if (want == 2 && fe_rmw_first(c, n, as[1], m, k, rmw_msg, &rc)) return NULL; /* the RMW check comes before the value's interval */
	fe_expr *v = NULL;
	if (want == 2) {
		if (m->record)
			v = fe_record_make(c, as[1], m->record, m, ref_var);
		else if (sr_eqc(name, "add_or_init"))
			v = fe_ctx_value(c, as[1], m, ref_var, sr_cstr("delta"));
		else
			v = fe_ctx_value(c, as[1], m, ref_var, sr_cstr("value"));
		if (!v) return NULL;
	}
	if (!k) return NULL;
	int rok = 0;
	sr_str ref = v ? fe_reads_map(v, m, &rok) : (sr_str){0};
	if (v && rok && !fe_exempt(c, m)) { /* a per-CPU map is exempt when every program kind is xdp */
		fe_expr *lk = fe_name_get(&c->ref_key, ref);
		if (!lk || !sr_eqc(lk->kind, "lit") || !sr_eqc(k->kind, "lit") || bigint_cmp(lk->lit, k->lit) == 0) {
			sr_buf b = {0};
			sr_puts(&b, "`");
			fe_fmt_s(&b, m->name);
			sr_puts(&b, ".");
			fe_fmt_s(&b, name);
			sr_puts(&b, "` stores a value read from the same map (`");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".load`) — concurrent CPUs lose updates; use `");
			fe_fmt_s(&b, m->const_name);
			sr_puts(&b, ".add_or_init` or `");
			fe_fmt_s(&b, ref);
			sr_puts(&b, ".atomic_add` inside `if ");
			fe_fmt_s(&b, ref);
			sr_puts(&b, "`");
			reject(c, FE_SB019, n, &b);
			return NULL;
		}
	}
	fe_expr *e = sr_alloc(sizeof *e);
	e->args_nil = 1;
	e->kind = sr_cstr("hstatus");
	const char *flags = "";
	status_op(name, &flags);
	e->op = sr_cstr(flags);
	e->map = m;
	expr_push(e, k);
	expr_push(e, v); /* v is nil for delete: Go's []*Expr{k, v} keeps the nil element */
	e->iv = full_i64();
	e->pos = fe_pos_of(c->z->z, c->a, n);
	return e;
}

/* hash.go hashKey */
fe_expr *fe_hash_key(fe_prog_ctx *c, const sr_node *n, fe_map_decl *m, sr_str ref_var)
{
	if (m->key_record) {
		if (is_type(n, "CallNode") && sr_eqc(nstr(n, "name"), "new") && sr_eq(fe_const_name(c->a, recv_of(c, n)), m->key_record->const_name)) {
			fe_map_decl *km = sr_alloc(sizeof *km);
			km->name = m->name;
			km->record = m->key_record;
			return fe_record_make(c, n, m->key_record, km, ref_var);
		}
		sr_buf b = {0};
		sr_puts(&b, "the key of ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, " is `");
		fe_fmt_s(&b, m->key_record->const_name);
		sr_puts(&b, ".new(…)` written in the call itself — a record key is not kept in a local or built elsewhere (bpf-mlir: a record.make result does not cross blocks)");
		reject(c, FE_SB024, n, &b);
		return NULL;
	}
	fe_expr *e = fe_ctx_expr(c, n, ref_var);
	if (!e) return NULL;
	if (e->bool_ || e->wide) {
		fe_ctx_add(c, FE_REJECTED, FE_SB001, n, sr_cstr("a map key must be an Integer (not a bool, not an unnarrowed u64 value)"));
		return NULL;
	}
	fe_map_decl kr = {0};
	kr.value_bits = m->key_bits;
	kr.is_signed = m->key_signed;
	fe_ival tr = fe_type_range(&kr);
	if (!fe_ival_within(e->iv, tr.lo, tr.hi)) {
		sr_buf b = {0};
		if (sr_eqc(e->kind, "lit")) {
			sr_puts(&b, "the key literal ");
			fe_fmt_big(&b, e->lit);
			sr_puts(&b, " is outside ");
			fe_fmt_s(&b, fe_ival_text(tr));
			sr_puts(&b, " (the ");
			fe_fmt_s(&b, fe_g1_map_key_type_name(m));
			sr_puts(&b, " key of ");
			fe_fmt_s(&b, m->name);
			sr_puts(&b, "; Ruby would not wrap it)");
		} else {
			sr_puts(&b, "the key's range ");
			fe_fmt_s(&b, fe_ival_text(e->iv));
			sr_puts(&b, " does not fit the ");
			fe_fmt_s(&b, fe_g1_map_key_type_name(m));
			sr_puts(&b, " key of ");
			fe_fmt_s(&b, m->name);
			sr_puts(&b, " ");
			fe_fmt_s(&b, fe_ival_text(tr));
			sr_puts(&b, " — the key would be truncated silently; narrow it (e.g. `& 0xFFFF_FFFF`)");
		}
		reject(c, FE_SB014, n, &b);
		return NULL;
	}
	return e;
}

/* hash.go refAtomic: returns Go's first bool, *ok2 the second (handled) */
static int ref_atomic_impl(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2)
{
	*ok2 = 0;
	*out = fe_stmt_new("");
	const sr_node *recv = recv_of(c, n);
	if (!sr_eqc(nstr(n, "name"), "atomic_add") || !recv || !is_type(recv, "LocalVariableReadNode")) return 0;
	sr_str ref = nstr(recv, "name");
	if (!fe_name_get(&c->refs, ref)) return 0;
	fe_map_decl *m = fe_name_get(&c->ref_map, ref);
	if (m->record) return 0;
	if (!sr_eq(ref, ref_var)) return 0; /* outside the arm: lookupCheck's walk stops it */
	if (fe_map_is_lpm(m)) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".atomic_add` is not accepted on lpm_trie ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, " — an lpm_trie is read-only on the eBPF side (read the value with `");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".load`; user space writes it with `obj.lpm_put`)");
		reject(c, FE_SB002, n, &b);
		*ok2 = 1;
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok) {
		*ok2 = 1;
		return 0;
	}
	if (!sr_eqc(callee, "MapRef#atomic_add")) {
		sr_buf b = {0};
		sr_puts(&b, "`atomic_add` resolves to ");
		fe_fmt_s(&b, callee);
		sr_puts(&b, ", not BPF::MapRef#atomic_add");
		reject(c, FE_SB011, n, &b);
		*ok2 = 1;
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, n, &n_as);
	if (n_as != 1) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".atomic_add` takes one delta (`");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".atomic_add(d)`)");
		reject(c, FE_SB002, n, &b);
		*ok2 = 1;
		return 0;
	}
	fe_note_flow(c, as[0], m, n);
	if (fe_reads_ref_via(c, as[0], ref)) { /* the local's origin too */
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".atomic_add` adds a value read from the same entry — use a delta that does not read `");
		fe_fmt_s(&b, ref);
		sr_puts(&b, "`");
		reject(c, FE_SB019, n, &b);
		*ok2 = 1;
		return 0;
	}
	fe_expr *d = fe_ctx_value(c, as[0], m, ref_var, sr_cstr("delta"));
	*ok2 = 1;
	if (!d) return 0;
	out->kind = sr_cstr("ratomic");
	out->var = ref;
	out->map = m;
	out->value = d;
	out->pos = fe_pos_of(c->z->z, c->a, n);
	return 1;
}

/* hash.go perCPUAdd: returns Go's first bool, *ok2 the second (handled) */
static int per_cpu_add_impl(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2)
{
	*ok2 = 0;
	*out = fe_stmt_new("");
	const sr_node *recv = recv_of(c, n);
	if (!is_type(n, "CallOperatorWriteNode") || !recv || !is_type(recv, "CallNode") || !sr_eqc(nstr(recv, "name"), "load")) return 0;
	const sr_node *pv = fe_ast_ref(c->a, recv, "receiver");
	if (!pv || !is_type(pv, "LocalVariableReadNode") || !fe_name_get(&c->refs, nstr(pv, "name"))) return 0;
	sr_str ref = nstr(pv, "name");
	fe_map_decl *m = fe_name_get(&c->ref_map, ref);
	if (!m->record || !fe_exempt(c, m)) return 0;
	if (!sr_eq(ref, ref_var)) return 0; /* outside the arm: lookupCheck's walk stops it */
	sr_str op = nstr(n, "binary_operator");
	if (!sr_eqc(op, "+") && !sr_eqc(op, "-")) {
		sr_buf b = {0};
		sr_puts(&b, "`.");
		fe_fmt_s(&b, nstr(n, "name"));
		sr_puts(&b, " ");
		fe_fmt_s(&b, op);
		sr_puts(&b, "= …` is not accepted on a per-CPU record member — only `+=` and `-=`");
		reject(c, FE_SB001, n, &b);
		*ok2 = 1;
		return 0;
	}
	if (!fe_load_callee(c, recv)) {
		*ok2 = 1;
		return 0;
	}
	sr_str fname = nstr(n, "name");
	fe_record_field *f = fe_record_decl_field(m->record, fname);
	if (!f) {
		sr_buf b = {0};
		sr_puts(&b, "record ");
		fe_fmt_s(&b, m->record->const_name);
		sr_puts(&b, " has no member `");
		fe_fmt_s(&b, fname);
		sr_puts(&b, "`");
		reject(c, FE_SB002, n, &b);
		*ok2 = 1;
		return 0;
	}
	if (f->pad) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, "` is padding — it is neither read nor written on the eBPF side");
		reject(c, FE_SB024, n, &b);
		*ok2 = 1;
		return 0;
	}
	const sr_node *vn = fe_ast_ref(c->a, n, "value");
	fe_note_flow(c, vn, m, n);
	if (fe_reads_ref_via(c, vn, ref)) { /* the local's origin too */
		sr_buf b = {0};
		sr_puts(&b, "the delta of `");
		fe_fmt_s(&b, ref);
		sr_puts(&b, ".load.");
		fe_fmt_s(&b, f->name);
		sr_puts(&b, " ");
		fe_fmt_s(&b, op);
		sr_puts(&b, "= …` reads the same entry — use a delta that does not read `");
		fe_fmt_s(&b, ref);
		sr_puts(&b, "`");
		reject(c, FE_SB019, n, &b);
		*ok2 = 1;
		return 0;
	}
	fe_expr *d = fe_field_value(c, vn, f, m, ref_var);
	*ok2 = 1;
	if (!d) return 0;
	out->kind = sr_cstr("fadd");
	out->var = ref;
	out->map = m;
	out->field = f;
	out->value = d;
	out->op = op;
	out->pos = fe_pos_of(c->z->z, c->a, n);
	return 1;
}

/* The Go functions return (Stmt, ok, handled). The core's call sites read the return value as `handled` and *ok2 as `ok`
 * (prog.c: `if (fe_ref_atomic(…)) { if (ok) push; continue; }`), so the public functions swap the two. */
int fe_ref_atomic(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2)
{
	int handled;
	*ok2 = ref_atomic_impl(c, n, ref_var, out, &handled);
	return handled;
}

int fe_per_cpu_add(fe_prog_ctx *c, const sr_node *n, sr_str ref_var, fe_stmt *out, int *ok2)
{
	int handled;
	*ok2 = per_cpu_add_impl(c, n, ref_var, out, &handled);
	return handled;
}
