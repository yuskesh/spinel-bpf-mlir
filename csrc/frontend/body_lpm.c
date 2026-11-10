/* body_lpm — the walk side of lpm.go in G1: the key of an lpm_trie lookup. Follows internal/frontend/lpm.go at main c204310
 * (the harness text builders of that file are not part of the C frontend). The Go mutation hook lpm-plen24 is not ported. */
#include "body.h"
#include "body_priv.h"

static void expr_push(fe_expr *e, fe_expr *a)
{
	e->args = sr_grow(e->args, e->n_args * sizeof *e->args, (e->n_args + 1) * sizeof *e->args);
	e->args[e->n_args++] = a;
	e->args_nil = 0;
}

/* lpm.go lpmKey: `R.lookup(a0, a1, a2, a3)` is a record.make of prefixlen 32 and the four address bytes (each in the u8 range) */
fe_expr *fe_lpm_key(fe_prog_ctx *c, const sr_node *call, fe_map_decl *m, const sr_node *const *as, size_t n_as, sr_str ref_var)
{
	if (n_as != 4) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".lookup` takes the 4 bytes of an IPv4 address (`");
		fe_fmt_s(&b, m->const_name);
		sr_puts(&b, ".lookup(a0, a1, a2, a3)` — e.g. `w.u8(30)` … `w.u8(33)`)");
		fe_ctx_add(c, FE_REJECTED, FE_SB002, call, sr_bufstr(&b));
		return NULL;
	}
	fe_map_decl *km = sr_alloc(sizeof *km);
	km->name = m->name;
	km->record = &fe_lpm_key4;
	fe_pos pos = fe_pos_of(c->z->z, c->a, call);
	fe_expr *bs = sr_alloc(sizeof *bs);
	bs->args_nil = 1;
	bs->kind = sr_cstr("earr");
	bs->pos = pos;
	fe_record_field *addr = sr_alloc(sizeof *addr); /* Go: lpmAddrByte = RecordField{Name: "addr", Bits: 8} */
	addr->name = sr_cstr("addr");
	addr->bits = 8;
	for (size_t i = 0; i < n_as; i++) {
		fe_expr *e = fe_field_value(c, as[i], addr, km, ref_var);
		if (!e) return NULL;
		expr_push(bs, e);
	}
	fe_expr *plen = sr_alloc(sizeof *plen);
	plen->args_nil = 1;
	plen->kind = sr_cstr("lit");
	plen->lit = sr_alloc(sizeof *plen->lit);
	bigint_set_string(plen->lit, "32", 2, 10);
	plen->iv = fe_point(intv_from_i64(32));
	plen->pos = pos;
	fe_expr *e = sr_alloc(sizeof *e);
	e->args_nil = 1;
	e->kind = sr_cstr("rmake");
	e->map = km;
	e->pos = pos;
	expr_push(e, plen);
	expr_push(e, bs);
	return e;
}
