/* body_globals — globals.go of G1: reads and adds of the library's Config / OptionalConfig / Counter globals, and the small
 * functions around them. Each function names the Go it follows (internal/frontend/globals.go at main c204310). */
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

/* globals.go globalValueCallees */
static sr_str value_callee(sr_str cls)
{
	if (sr_eqc(cls, "Config")) return sr_cstr("Config#value");
	if (sr_eqc(cls, "OptionalConfig")) return sr_cstr("OptionalConfig#value");
	if (sr_eqc(cls, "Counter")) return sr_cstr("Counter#value");
	return (sr_str){0};
}

static void no_add_msg(fe_prog_ctx *c, const sr_node *n, const fe_global_decl *g)
{
	sr_buf b = {0};
	fe_fmt_s(&b, g->const_name);
	sr_puts(&b, " is a ");
	fe_fmt_s(&b, g->class_name);
	sr_puts(&b, " (.rodata — set at load) and has no `add` — only a Counter (.bss) adds");
	reject(c, FE_SB029, n, &b);
}

/* globals.go globalRead */
fe_expr *fe_global_read(fe_prog_ctx *c, const sr_node *n, fe_global_decl *g, sr_str name, const sr_node *const *as, size_t n_as, fe_pos p)
{
	(void)as;
	if (sr_eqc(name, "add")) {
		if (!fe_global_counter(g)) {
			no_add_msg(c, n, g);
		} else {
			sr_buf b = {0};
			sr_puts(&b, "`");
			fe_fmt_s(&b, g->const_name);
			sr_puts(&b, ".add(d)` is a statement, not a value (ebpf.global.atomic_add returns nothing)");
			reject(c, FE_SB029, n, &b);
		}
		return NULL;
	}
	if (!sr_eqc(name, "value") || n_as != 0) {
		sr_buf b = {0};
		sr_puts(&b, "a global is read as `");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, ".value` (and a Counter adds with `");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, ".add(d)`), not `");
		fe_fmt_s(&b, name);
		sr_puts(&b, "`");
		reject(c, FE_SB029, n, &b);
		return NULL;
	}
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok) return NULL;
	sr_str want = value_callee(g->class_name);
	if (!sr_eq(callee, want)) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, ".value` resolves to ");
		if (!fe_fmt_q(c->z->z, &b, callee)) return NULL;
		sr_puts(&b, ", not BPF::");
		fe_fmt_s(&b, want);
		reject(c, FE_SB011, n, &b);
		return NULL;
	}
	fe_ptr_set_add(&c->used_globals, g);
	fe_expr *e = sr_alloc(sizeof *e);
	e->args_nil = 1;
	e->kind = sr_cstr("gload");
	e->glob = g;
	e->pos = p;
	if (g->bits == 64 && !g->is_signed) {
		e->iv = fe_iv(intv_from_i64(0), intv_from_u64(UINT64_MAX));
		e->wide = 1;
	} else {
		e->iv = fe_width_range(g->bits, g->is_signed);
	}
	return e;
}

/* globals.go globalAdd: returns Go's bool; *out is the Stmt */
int fe_global_add(fe_prog_ctx *c, const sr_node *n, fe_global_decl *g, const sr_node *const *as, size_t n_as, sr_str ref_var, fe_stmt *out)
{
	if (!fe_global_counter(g)) {
		no_add_msg(c, n, g);
		return 0;
	}
	if (n_as != 1) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, ".add(d)` takes one Integer");
		reject(c, FE_SB029, n, &b);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, n, &ok);
	if (!ok) return 0;
	if (!sr_eqc(callee, "Counter#add")) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, ".add` resolves to ");
		if (!fe_fmt_q(c->z->z, &b, callee)) return 0;
		sr_puts(&b, ", not BPF::Counter#add");
		reject(c, FE_SB011, n, &b);
		return 0;
	}
	/* the delta is a read of the same Counter (direct or through a local): the same kind as a map atomic_add's delta reading the same
	 * entry; a read across functions is the summary's */
	sr_buf key = {0};
	sr_puts(&key, "g:");
	sr_putstr(&key, g->const_name);
	fe_note_flow_key(c, as[0], sr_bufstr(&key), n);
	sr_buf dk = {0};
	sr_puts(&dk, "@g");
	sr_putstr(&dk, g->const_name);
	fe_name_table derived = fe_derived_refs(c, as[0]);
	if (fe_name_get(&derived, sr_bufstr(&dk))) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, ".add` adds a value read from ");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, " itself (`");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, ".value`) — concurrent CPUs read the same old value and lose updates; use a delta that does not read ");
		fe_fmt_s(&b, g->const_name);
		reject(c, FE_SB019, n, &b);
		return 0;
	}
	fe_expr *e = fe_ctx_expr(c, as[0], ref_var);
	if (!e) return 0;
	if (e->bool_) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, g->const_name);
		sr_puts(&b, ".add` takes an Integer, not a boolean");
		reject(c, FE_SB001, as[0], &b);
		return 0;
	}
	if (e->wide && !(g->bits == 64 && !g->is_signed)) {
		fe_ctx_add(c, FE_REJECTED, FE_SB014, as[0],
			   sr_cstr("a u64 value does not fit Ruby's Integer — add it only to a :u64 Counter, or narrow it first (`x & M` or `x >> K`)"));
		return 0;
	}
	fe_ptr_set_add(&c->used_globals, g);
	*out = fe_stmt_new("");
	out->kind = sr_cstr("gadd");
	out->glob = g;
	out->val = e;
	out->pos = fe_pos_of(c->z->z, c->a, n);
	return 1;
}

/* globals.go counterRead: n is a Counter's `G.value` */
fe_global_decl *fe_counter_read(fe_prog_ctx *c, const sr_node *n)
{
	if (!n || !is_type(n, "CallNode") || !sr_eqc(nstr(n, "name"), "value")) return NULL;
	const sr_node *r = recv_of(c, n);
	if (!r || !is_type(r, "ConstantReadNode")) return NULL;
	fe_global_decl *g = fe_name_get(&c->z->top->globals, nstr(r, "name"));
	if (g && fe_global_counter(g)) return g;
	return NULL;
}
