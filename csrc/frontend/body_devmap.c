/* body_devmap — devmap.go of G1: the XDP program's ending `M.redirect(k, BPF::XDP_*)`. Follows internal/frontend/devmap.go
 * at main c204310. */
#include "body.h"
#include "body_priv.h"

#include <string.h>

static const sr_node *recv_of(fe_prog_ctx *c, const sr_node *n) { return fe_ast_ref(c->a, n, "receiver"); }

static int is_type(const sr_node *n, const char *t) { return n && sr_eqc(n->type, t); }

static void reject(fe_prog_ctx *c, fe_code code, const sr_node *n, sr_buf *b) { fe_ctx_add(c, FE_REJECTED, code, n, sr_bufstr(b)); }

/* devmap.go redirectVerdict: n is the program's last statement, v the redirect call */
void fe_redirect_verdict(fe_prog_ctx *c, const sr_node *n, const sr_node *v)
{
	if (!sr_eqc(c->prog->kind, "xdp")) {
		sr_buf b = {0};
		sr_puts(&b, "`redirect` (bpf_redirect_map) ends only an XDP program — a ");
		fe_fmt_s(&b, c->prog->kind);
		sr_puts(&b, " program returns its own verdict");
		reject(c, FE_SB028, v, &b);
		return;
	}
	if (c->guard_returns.n > 0) {
		fe_ctx_add(c, FE_REJECTED, FE_SB008, v,
			   sr_cstr("a program that ends with `M.redirect(k, …)` takes no top-level `return … if cond` guard yet — compute the key on every path instead"));
		return;
	}
	fe_map_decl *m = fe_map_of(c, recv_of(c, v), v);
	if (!m) return;
	if (!fe_map_is_devmap(m)) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".redirect` needs a devmap (`BPF::DevMap.new`) — ");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, " is a ");
		fe_fmt_s(&b, m->kind.n ? m->kind : sr_cstr("array")); /* MapKind */
		reject(c, FE_SB002, v, &b);
		return;
	}
	int ok;
	sr_str callee = fe_callee(c, v, &ok);
	if (!ok || !sr_eqc(callee, "DevMap#redirect")) {
		if (ok) {
			sr_buf b = {0};
			sr_puts(&b, "`redirect` resolves to ");
			fe_fmt_s(&b, callee);
			sr_puts(&b, ", not BPF::DevMap#redirect");
			reject(c, FE_SB011, v, &b);
		}
		return;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, v, &n_as);
	if (n_as != 2) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".redirect(k, BPF::XDP_PASS)` takes the key and the fallback verdict");
		reject(c, FE_SB008, v, &b);
		return;
	}
	sr_str cn = fe_const_name(c->a, as[1]);
	fe_name_table table = fe_verdicts_of(sr_cstr("xdp"));
	sr_str *entry = cn.n >= 5 ? fe_name_get(&table, (sr_str){cn.p + 5, cn.n - 5}) : NULL;
	if (!is_type(as[1], "ConstantPathNode") || cn.n < 5 || memcmp(cn.p, "BPF::", 5) != 0 || !entry || entry->n == 0) {
		sr_buf b = {0};
		sr_puts(&b, "the fallback of `");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".redirect` is an XDP verdict constant (BPF::XDP_ABORTED / XDP_DROP / XDP_PASS / XDP_TX)");
		reject(c, FE_SB008, as[1], &b);
		return;
	}
	fe_expr *k = fe_ctx_expr(c, as[0], sr_cstr(""));
	if (!k) return;
	if (k->bool_) {
		sr_buf b = {0};
		sr_puts(&b, "the key of `");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".redirect` is an Integer (a devmap index), not a bool");
		reject(c, FE_SB001, as[0], &b);
		return;
	}
	if (!fe_value_ok(c, k, as[0])) return;
	c->prog->verdict = *entry;
	c->prog->verdict_const = (sr_str){cn.p + 5, cn.n - 5};
	c->prog->verdict_pos = fe_pos_of(c->z->z, c->a, n);
	c->prog->redir_map = m;
	c->prog->redir_key = k;
}
