/* body_sklookup — sklookup.go of G1: `st = M.assign(ctx, k)` of an sk_lookup program. Follows internal/frontend/sklookup.go
 * at main c204310 (the lowering `skAssign` is the lowerer's). The Go mutation hook skassign-absent-zero is not ported. */
#include "body.h"
#include "body_priv.h"

#include <string.h>

#define SK_ASSIGN_ABSENT (-2) /* sklookup.go skAssignAbsent: the status of an empty slot (the helper is not called) */

static int is_type(const sr_node *n, const char *t) { return n && sr_eqc(n->type, t); }

static sr_str nstr(const sr_node *n, const char *k)
{
	int ok;
	return fe_node_str(n, k, &ok);
}

static void reject(fe_prog_ctx *c, fe_code code, const sr_node *n, sr_buf *b) { fe_ctx_add(c, FE_REJECTED, code, n, sr_bufstr(b)); }

/* sklookup.go isSkAssign */
int fe_is_sk_assign(fe_prog_ctx *c, const sr_node *v)
{
	const sr_node *r = v ? fe_ast_ref(c->a, v, "receiver") : NULL;
	return v && is_type(v, "CallNode") && sr_eqc(nstr(v, "name"), "assign") && r && is_type(r, "ConstantReadNode");
}

/* sklookup.go skAssignStmt: w is a LocalVariableWriteNode; returns Go's bool, *out the Stmt */
int fe_sk_assign_stmt(fe_prog_ctx *c, const sr_node *w, fe_stmt *out)
{
	sr_str name = nstr(w, "name");
	const sr_node *v = fe_ast_ref(c->a, w, "value");
	if (!sr_eqc(c->prog->kind, "sk_lookup")) {
		sr_buf b = {0};
		sr_puts(&b, "`assign` (bpf_sk_assign) is accepted only in an sk_lookup program — a ");
		fe_fmt_s(&b, c->prog->kind);
		sr_puts(&b, " program has no socket lookup");
		reject(c, FE_SB028, v, &b);
		return 0;
	}
	fe_map_decl *m = fe_map_of(c, fe_ast_ref(c->a, v, "receiver"), v);
	if (!m) return 0;
	if (!sr_eqc(m->kind, "sockmap")) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".assign` needs a sockmap (`BPF::SockMap.new`) — ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, " is a ");
		fe_fmt_s(&b, m->kind.n ? m->kind : sr_cstr("array")); /* MapKind */
		reject(c, FE_SB002, v, &b);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, v, &ok);
	if (!ok || !sr_eqc(callee, "SockMap#assign")) {
		if (ok) {
			sr_buf b = {0};
			sr_puts(&b, "`assign` resolves to ");
			fe_fmt_s(&b, callee);
			sr_puts(&b, ", not BPF::SockMap#assign");
			reject(c, FE_SB011, v, &b);
		}
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, v, &n_as);
	if (n_as != 2 || !fe_is_var_read(c, as[0], c->param)) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".assign(");
		fe_fmt_s(&b, c->param);
		sr_puts(&b, ", k)` takes the program's context and a slot key");
		reject(c, FE_SB028, v, &b);
		return 0;
	}
	if (sr_eqc(name, "_")) {
		sr_buf b = {0};
		sr_puts(&b, "the status of `");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".assign` is dropped — receive it as `st = ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".assign(");
		fe_fmt_s(&b, c->param);
		sr_puts(&b, ", k)` and read `st` (0 is assigned, a negative errno or ");
		fe_fmt_d(&b, SK_ASSIGN_ABSENT);
		sr_puts(&b, " (no socket in the slot) is not)");
		reject(c, FE_SB026, w, &b);
		return 0;
	}
	if (fe_name_has(&c->env, name) || sr_eq(name, c->param) || fe_name_get(&c->refs, name) || fe_name_get(&c->wins, name)) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, name);
		sr_puts(&b, "` is already bound — the status of `");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".assign` takes a fresh local");
		reject(c, FE_SB026, w, &b);
		return 0;
	}
	sr_buf what = {0};
	sr_putstr(&what, m->const_name);
	sr_puts(&what, ".assign");
	if (!fe_kread_status_ok(c, w, name, sr_bufstr(&what), sr_cstr("an empty slot or a refused socket is not an assigned one"))) return 0;
	fe_expr *k = fe_ctx_expr(c, as[1], sr_cstr(""));
	if (!k) return 0;
	if (k->bool_) {
		sr_buf b = {0};
		sr_puts(&b, "the key of `");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".assign` is an Integer (a sockmap slot), not a bool");
		reject(c, FE_SB001, as[1], &b);
		return 0;
	}
	if (!fe_value_ok(c, k, as[1])) return 0;
	fe_var_info *vi = sr_alloc(sizeof *vi); /* Go: &varInfo{Iv: [-2^63, 0]} — 0 or negative */
	vi->iv = fe_iv(intv_from_i64(INT64_MIN), intv_from_i64(0));
	vi->from_nil = 1;
	fe_name_set(&c->env, name, vi);
	*out = fe_stmt_new("");
	out->kind = sr_cstr("skassign");
	out->var = name;
	out->map = m;
	out->key = k;
	out->pos = fe_pos_of(c->z->z, c->a, w);
	return 1;
}
