/* body_g2_util — G2's shared helpers, declared in body_g2.h. */
#include "body_g2.h"

#include <stdarg.h>
#include <string.h>

static int one_ = 1;
void *const g2_true = &one_;

sr_str g2_str(const sr_node *n, const char *k)
{
	int ok;
	return fe_node_str(n, k, &ok);
}

int g2_is(const sr_node *n, const char *type) { return n && sr_eqc(n->type, type); }

const sr_node *g2_parent(const sr_ast *a, const sr_node *n)
{
	const int64_t *v = sr_imap_get(&a->parent, n->id);
	return fe_ast_node(a, v ? *v : 0);
}

fe_expr *g2_expr(const char *kind, fe_pos p)
{
	fe_expr *e = sr_alloc(sizeof *e);
	e->kind = sr_cstr(kind);
	e->args_nil = 1;
	e->pos = p;
	return e;
}

fe_pos g2_pos(fe_prog_ctx *c, const sr_node *n) { return fe_pos_of(c->z->z, c->a, n); }

void g2_reject(fe_prog_ctx *c, fe_code code, const sr_node *n, const char *fmt, ...)
{
	sr_buf b = {0};
	va_list ap;
	va_start(ap, fmt);
	for (const char *p = fmt; *p; p++) {
		if (*p != '%') {
			sr_putc(&b, *p);
			continue;
		}
		switch (*++p) {
		case 's':
			fe_fmt_s(&b, va_arg(ap, sr_str));
			break;
		case 'c':
			sr_puts(&b, va_arg(ap, const char *));
			break;
		case 'd':
			fe_fmt_d(&b, va_arg(ap, int64_t));
			break;
		case 'q':
			fe_fmt_q(c->z->z, &b, va_arg(ap, sr_str)); /* a non-ASCII string records a not-ported stop */
			break;
		case 'B':
			fe_fmt_big(&b, va_arg(ap, const bigint *));
			break;
		case 'I':
			sr_putstr(&b, fe_ival_string(va_arg(ap, fe_ival)));
			break;
		case '%':
			sr_puts(&b, "%");
			break;
		default:
			fe_not_ported(c->z->z, "g2_reject: unknown verb %%%c", *p);
			va_end(ap);
			return;
		}
	}
	va_end(ap);
	fe_ctx_add(c, FE_REJECTED, code, n, sr_bufstr(&b));
}

int g2_record_type(sr_str t, int64_t *bits, int *is_signed)
{
	static const char *const names[] = {"u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"};
	for (int i = 0; i < 8; i++)
		if (sr_eqc(t, names[i])) {
			*bits = 8 << (i % 4);
			*is_signed = i >= 4;
			return 1;
		}
	return 0;
}

/* (*big.Int).IsInt64 and Int64 */
int g2_big_i64(const bigint *x, int64_t *v)
{
	uint64_t m = 0;
	if (x->n > 2)
		return 0;
	for (size_t i = x->n; i-- > 0;)
		m = m << 32 | x->l[i];
	if (!x->neg) {
		if (m > (uint64_t)INT64_MAX)
			return 0;
		*v = (int64_t)m;
		return 1;
	}
	if (m > (uint64_t)INT64_MAX + 1)
		return 0;
	*v = m == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)m;
	return 1;
}

int g2_lit_int(fe_prog_ctx *c, const sr_node *lit, int64_t *v)
{
	bigint nb = {0};
	if (!fe_literal(c->z->z, c->a, lit, &nb))
		return 0;
	int ok = g2_big_i64(&nb, v);
	bigint_free(&nb);
	if (!ok) {
		fe_not_ported(c->z->z, "a literal beyond int64 read with Int64()");
		return 0;
	}
	return 1;
}
