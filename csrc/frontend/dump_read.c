/* dump_read.c — see dump_read.h. Each reader function mirrors the dump.c function that prints the same thing, line for line. */
#include "dump_read.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { K_MAP, K_RECORD, K_RING, K_GLOBAL, K_KTYPE, K_N };
static const char *const kind_name[K_N] = {"map", "record", "ring", "global", "ktype"};

/* The dump is read with a cursor, not split into lines: a declaration id is its Const printed raw (dump.c reg_id), so a Const
 * holding a newline spreads a decl line, every path under that decl, and every "&<kind>:<Const>" reference over several lines.
 * Paths are matched literally at the cursor; a value is the rest of its line, except a reference, which is matched against the
 * registered ids. */
typedef struct {
	int kind;
	sr_str name;
	void *obj;
} rentry;

typedef struct {
	const char *t;
	size_t n, pos;
	rentry *reg;
	size_t n_reg;
	jmp_buf jb;
	char *err;
} rd;

/* ---- errors ---- */

static void __attribute__((noreturn, format(printf, 2, 3))) die(rd *r, const char *fmt, ...)
{
	sr_buf b = {0};
	size_t line = 1;
	for (size_t k = 0; k < r->pos && k < r->n; k++)
		line += r->t[k] == '\n';
	if (r->pos < r->n)
		sr_printf(&b, "dump line %zu: ", line);
	else
		sr_puts(&b, "dump end: ");
	va_list ap;
	va_start(ap, fmt);
	char tmp[512];
	vsnprintf(tmp, sizeof tmp, fmt, ap);
	va_end(ap);
	sr_puts(&b, tmp);
	sr_putc(&b, 0);
	r->err = b.p;
	longjmp(r->jb, 1);
}

static const char *cs(sr_str s) /* NUL-terminated copy, for messages */
{
	char *p = sr_alloc(s.n + 1);
	if (s.n)
		memcpy(p, s.p, s.n);
	return p;
}

/* ---- paths ---- */

static sr_str cat(sr_str a, const char *b)
{
	size_t nb = strlen(b);
	char *p = sr_alloc(a.n + nb + 1);
	if (a.n)
		memcpy(p, a.p, a.n);
	memcpy(p + a.n, b, nb);
	return (sr_str){p, a.n + nb};
}

static sr_str idx(sr_str path, size_t i)
{
	sr_buf b = {0};
	sr_putstr(&b, path);
	sr_printf(&b, "[%zu]", i);
	return sr_bufstr(&b);
}

/* ---- the cursor ---- */

static int at(const rd *r, sr_str s) { return r->n - r->pos >= s.n && memcmp(r->t + r->pos, s.p, s.n) == 0; }

/* the text from the cursor to the end of its line, for messages */
static sr_str here(const rd *r)
{
	const char *nl = memchr(r->t + r->pos, '\n', r->n - r->pos);
	return (sr_str){r->t + r->pos, nl ? (size_t)(nl - (r->t + r->pos)) : r->n - r->pos};
}

/* consumes "<path> = " */
static void expect_path(rd *r, sr_str path)
{
	if (r->pos == r->n)
		die(r, "want %s, have the end of the dump", cs(path));
	sr_str k = cat(path, " = ");
	if (!at(r, k))
		die(r, "want %s, have %s", cs(path), cs(here(r)));
	r->pos += k.n;
}

/* consumes "<path> = <value>\n" and returns the value */
static sr_str expect(rd *r, sr_str path)
{
	expect_path(r, path);
	sr_str v = here(r);
	if (r->pos + v.n == r->n)
		die(r, "%s: the line has no newline", cs(path));
	r->pos += v.n + 1;
	return v;
}

/* ---- values ---- */

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void put_rune(sr_buf *b, uint32_t c)
{
	if (c < 0x80) {
		sr_putc(b, (char)c);
	} else if (c < 0x800) {
		sr_putc(b, (char)(0xC0 | (c >> 6)));
		sr_putc(b, (char)(0x80 | (c & 0x3F)));
	} else if (c < 0x10000) {
		sr_putc(b, (char)(0xE0 | (c >> 12)));
		sr_putc(b, (char)(0x80 | ((c >> 6) & 0x3F)));
		sr_putc(b, (char)(0x80 | (c & 0x3F)));
	} else {
		sr_putc(b, (char)(0xF0 | (c >> 18)));
		sr_putc(b, (char)(0x80 | ((c >> 12) & 0x3F)));
		sr_putc(b, (char)(0x80 | ((c >> 6) & 0x3F)));
		sr_putc(b, (char)(0x80 | (c & 0x3F)));
	}
}

/* strconv.QuoteToASCII's output (sr_quote_ascii) back to the bytes; only the forms that quoter writes are accepted */
static int unquote(sr_str q, sr_str *out)
{
	if (q.n < 2 || q.p[0] != '"' || q.p[q.n - 1] != '"')
		return 0;
	sr_buf b = {0};
	for (size_t i = 1; i < q.n - 1;) {
		unsigned char c = (unsigned char)q.p[i];
		if (c == '"' || c < 0x20 || c >= 0x7F)
			return 0;
		if (c != '\\') {
			sr_putc(&b, (char)c);
			i++;
			continue;
		}
		if (i + 1 >= q.n - 1)
			return 0;
		char e = q.p[i + 1];
		i += 2;
		switch (e) {
		case 'a': sr_putc(&b, '\a'); break;
		case 'b': sr_putc(&b, '\b'); break;
		case 'f': sr_putc(&b, '\f'); break;
		case 'n': sr_putc(&b, '\n'); break;
		case 'r': sr_putc(&b, '\r'); break;
		case 't': sr_putc(&b, '\t'); break;
		case 'v': sr_putc(&b, '\v'); break;
		case '\\': sr_putc(&b, '\\'); break;
		case '"': sr_putc(&b, '"'); break;
		case 'x':
		case 'u':
		case 'U': {
			size_t w = e == 'x' ? 2 : e == 'u' ? 4 : 8;
			if (i + w > q.n - 1)
				return 0;
			uint32_t v = 0;
			for (size_t k = 0; k < w; k++) {
				int h = hexval(q.p[i + k]);
				if (h < 0)
					return 0;
				v = v << 4 | (uint32_t)h;
			}
			i += w;
			if (e == 'x')
				sr_putc(&b, (char)v); /* a raw byte (an invalid UTF-8 byte or a control byte) */
			else if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF))
				return 0;
			else
				put_rune(&b, v);
			break;
		}
		default:
			return 0;
		}
	}
	*out = sr_bufstr(&b);
	return 1;
}

static sr_str v_str(rd *r, sr_str path)
{
	sr_str v = expect(r, path), s;
	if (!unquote(v, &s))
		die(r, "%s: not a quoted string: %s", cs(path), cs(v));
	return s;
}

/* a decimal as Go's %d / strconv prints it: no '+', no leading zeros, no "-0" */
static int dec_ok(sr_str v, int allow_neg)
{
	size_t i = 0;
	if (allow_neg && v.n > 0 && v.p[0] == '-')
		i = 1;
	if (i == v.n)
		return 0;
	if (v.p[i] == '0' && (v.n - i > 1 || i == 1))
		return 0;
	for (size_t k = i; k < v.n; k++)
		if (v.p[k] < '0' || v.p[k] > '9')
			return 0;
	return 1;
}

static int64_t v_int(rd *r, sr_str path)
{
	sr_str v = expect(r, path);
	if (!dec_ok(v, 1) || v.n > 20)
		die(r, "%s: not an int64: %s", cs(path), cs(v));
	int neg = v.p[0] == '-';
	uint64_t m = 0;
	for (size_t k = neg; k < v.n; k++) {
		uint64_t d = (uint64_t)(v.p[k] - '0');
		if (m > (UINT64_MAX - d) / 10)
			die(r, "%s: out of int64 range: %s", cs(path), cs(v));
		m = m * 10 + d;
	}
	if ((!neg && m > (uint64_t)INT64_MAX) || (neg && m > (uint64_t)INT64_MAX + 1))
		die(r, "%s: out of int64 range: %s", cs(path), cs(v));
	return neg ? (int64_t)(0 - m) : (int64_t)m;
}

static uint64_t v_uint(rd *r, sr_str path)
{
	sr_str v = expect(r, path);
	if (!dec_ok(v, 0) || v.n > 20)
		die(r, "%s: not a uint64: %s", cs(path), cs(v));
	uint64_t m = 0;
	for (size_t k = 0; k < v.n; k++) {
		uint64_t d = (uint64_t)(v.p[k] - '0');
		if (m > (UINT64_MAX - d) / 10)
			die(r, "%s: out of uint64 range: %s", cs(path), cs(v));
		m = m * 10 + d;
	}
	return m;
}

static int v_bool(rd *r, sr_str path)
{
	sr_str v = expect(r, path);
	if (sr_eqc(v, "true"))
		return 1;
	if (sr_eqc(v, "false"))
		return 0;
	die(r, "%s: not a bool: %s", cs(path), cs(v));
}

/* "nil" (returns 0, *is_nil = 1) or "#<n>" */
static size_t v_len(rd *r, sr_str path, int *is_nil)
{
	sr_str v = expect(r, path);
	if (sr_eqc(v, "nil")) {
		*is_nil = 1;
		return 0;
	}
	*is_nil = 0;
	sr_str d = {v.p + 1, v.n ? v.n - 1 : 0};
	if (v.n < 2 || v.p[0] != '#' || !dec_ok(d, 0) || d.n > 9)
		die(r, "%s: not a length: %s", cs(path), cs(v));
	size_t n = 0;
	for (size_t k = 0; k < d.n; k++)
		n = n * 10 + (size_t)(d.p[k] - '0');
	return n;
}

static fe_pos v_pos(rd *r, sr_str path)
{
	fe_pos p;
	p.file = v_str(r, cat(path, ".File"));
	p.line = v_int(r, cat(path, ".Line"));
	p.col = v_int(r, cat(path, ".Col"));
	return p;
}

static sr_str *v_strs(rd *r, sr_str path, size_t *n, int *is_nil)
{
	*n = v_len(r, path, is_nil);
	if (*is_nil)
		return NULL;
	sr_str *v = sr_alloc((*n + 1) * sizeof *v);
	for (size_t i = 0; i < *n; i++)
		v[i] = v_str(r, idx(path, i));
	return v;
}

/* consumes the subtree at `path` (not stored) up to the line that starts with "<next> = ", the field the dumper prints after it.
 * The subtree starts with "<path> = " (nil, a slice length) or, for a non-nil expression, which prints no line of its own, with
 * "<path>." (its first field). Its values may hold raw ids with newlines, so its end is found by the next field's path. */
static void skip_subtree(rd *r, sr_str path, sr_str next)
{
	if (!at(r, cat(path, ".")))
		expect_path(r, path);
	sr_str k = cat(cat(sr_cstr("\n"), cs(next)), " = ");
	for (size_t p = r->pos; p < r->n; p++)
		if (r->t[p] == '\n' && r->n - p >= k.n && memcmp(r->t + p, k.p, k.n) == 0) {
			r->pos = p + 1;
			return;
		}
	die(r, "%s: no %s after it", cs(path), cs(next));
}

/* skip_prefix: a subtree with no fixed next path (the last field of a program): `path = nil`, or every line under `path.` */
static void skip_prefix(rd *r, sr_str path)
{
	if (at(r, cat(path, " = "))) {
		sr_str v = expect(r, path);
		if (!sr_eqc(v, "nil"))
			die(r, "%s: nil or its fields: %s", cs(path), cs(v));
		return;
	}
	sr_str k = cat(path, ".");
	if (!at(r, k))
		expect_path(r, path);
	while (at(r, k)) {
		size_t p = r->pos;
		while (p < r->n && r->t[p] != '\n')
			p++;
		r->pos = p < r->n ? p + 1 : p;
	}
}

/* ---- declarations ---- */

static void *new_obj(int kind)
{
	static const size_t sz[K_N] = {sizeof(fe_map_decl), sizeof(fe_record_decl), sizeof(fe_ring_decl), sizeof(fe_global_decl),
	                               sizeof(fe_kernel_type_decl)};
	return sr_alloc(sz[kind]);
}

static void read_body(rd *r, sr_str path, int kind, void *p);

/* every declaration type starts with const_name (Go: Const), the id the dumper registers it under; "" is an anonymous one */
static sr_str const_of(const void *p) { return *(const sr_str *)p; }

/* a declaration pointer: nil, anon <kind> (read here in full), or &<kind>:<Const> */
static void *v_decl(rd *r, sr_str path, int kind)
{
	expect_path(r, path);
	if (at(r, sr_cstr("nil\n"))) {
		r->pos += 4;
		return NULL;
	}
	sr_str anon = cat(cat(sr_cstr("anon "), kind_name[kind]), "\n");
	if (at(r, anon)) {
		r->pos += anon.n;
		void *p = new_obj(kind);
		read_body(r, path, kind, p);
		if (const_of(p).n != 0)
			die(r, "%s: an anonymous %s has the Const %s", cs(path), kind_name[kind], cs(const_of(p)));
		return p;
	}
	sr_str pre = cat(cat(sr_cstr("&"), kind_name[kind]), ":");
	if (!at(r, pre))
		die(r, "%s: not nil, anon %s or a reference to a %s: %s", cs(path), kind_name[kind], kind_name[kind], cs(here(r)));
	r->pos += pre.n;
	/* the longest registered id that ends at a newline here; a wrong pick (an id that is a prefix of another ended by a newline)
	 * leaves the cursor inside the reference, and the next path does not match there: loud */
	rentry *best = NULL;
	for (size_t i = 0; i < r->n_reg; i++) {
		rentry *e = &r->reg[i];
		if (e->kind == kind && at(r, cat(e->name, "\n")) && (!best || e->name.n > best->name.n))
			best = e;
	}
	if (!best)
		die(r, "%s: a reference to %s:%s, which has no decl block", cs(path), kind_name[kind], cs(here(r)));
	r->pos += best->name.n + 1;
	return best->obj;
}

static void read_record_field(rd *r, sr_str path, fe_record_field *f)
{
	f->name = v_str(r, cat(path, ".Name"));
	f->bits = v_int(r, cat(path, ".Bits"));
	f->is_signed = v_bool(r, cat(path, ".Signed"));
	f->pad = v_bool(r, cat(path, ".Pad"));
	f->offset = v_int(r, cat(path, ".Offset"));
	f->count = v_int(r, cat(path, ".Count"));
}

static void read_tp_field(rd *r, sr_str path, fe_tp_field *f)
{
	f->name = v_str(r, cat(path, ".Name"));
	f->offset = v_int(r, cat(path, ".Offset"));
	f->type = v_str(r, cat(path, ".Type"));
	f->n = v_int(r, cat(path, ".N"));
}

static void read_record(rd *r, sr_str path, fe_record_decl *d)
{
	d->const_name = v_str(r, cat(path, ".Const"));
	sr_str fp = cat(path, ".Fields");
	d->n_fields = v_len(r, fp, &d->fields_nil);
	d->fields = sr_alloc((d->n_fields + 1) * sizeof *d->fields);
	for (size_t i = 0; i < d->n_fields; i++)
		read_record_field(r, idx(fp, i), &d->fields[i]);
	d->size = v_int(r, cat(path, ".Size"));
	d->align = v_int(r, cat(path, ".Align"));
	d->pos = v_pos(r, cat(path, ".Pos"));
	d->struct_pos = v_pos(r, cat(path, ".StructPos"));
}

static void read_map(rd *r, sr_str path, fe_map_decl *m)
{
	m->const_name = v_str(r, cat(path, ".Const"));
	m->name = v_str(r, cat(path, ".Name"));
	m->value_bits = v_int(r, cat(path, ".ValueBits"));
	m->is_signed = v_bool(r, cat(path, ".Signed"));
	m->max_entries = v_uint(r, cat(path, ".MaxEntries"));
	m->record = v_decl(r, cat(path, ".Record"), K_RECORD);
	m->kind = v_str(r, cat(path, ".Kind"));
	m->class_name = v_str(r, cat(path, ".Class"));
	m->key_bits = v_int(r, cat(path, ".KeyBits"));
	m->key_signed = v_bool(r, cat(path, ".KeySigned"));
	m->key_record = v_decl(r, cat(path, ".KeyRecord"), K_RECORD);
	m->pos = v_pos(r, cat(path, ".Pos"));
}

static void read_ring(rd *r, sr_str path, fe_ring_decl *g)
{
	g->const_name = v_str(r, cat(path, ".Const"));
	g->name = v_str(r, cat(path, ".Name"));
	g->record = v_decl(r, cat(path, ".Record"), K_RECORD);
	g->size = v_uint(r, cat(path, ".Size"));
	g->pos = v_pos(r, cat(path, ".Pos"));
}

static void read_global(rd *r, sr_str path, fe_global_decl *g)
{
	g->const_name = v_str(r, cat(path, ".Const"));
	g->name = v_str(r, cat(path, ".Name"));
	g->class_name = v_str(r, cat(path, ".Class"));
	g->section = v_str(r, cat(path, ".Section"));
	g->bits = v_int(r, cat(path, ".Bits"));
	g->is_signed = v_bool(r, cat(path, ".Signed"));
	g->optional = v_bool(r, cat(path, ".Optional"));
	g->pos = v_pos(r, cat(path, ".Pos"));
}

static void read_ktype(rd *r, sr_str path, fe_kernel_type_decl *k)
{
	k->const_name = v_str(r, cat(path, ".Const"));
	k->name = v_str(r, cat(path, ".Name"));
	sr_str fp = cat(path, ".Fields");
	k->n_fields = v_len(r, fp, &k->fields_nil);
	k->fields = sr_alloc((k->n_fields + 1) * sizeof *k->fields);
	for (size_t i = 0; i < k->n_fields; i++) {
		sr_str e = idx(fp, i);
		fe_kernel_field *f = &k->fields[i];
		f->name = v_str(r, cat(e, ".Name"));
		f->kind = v_str(r, cat(e, ".Kind"));
		f->bits = v_int(r, cat(e, ".Bits"));
		f->is_signed = v_bool(r, cat(e, ".Signed"));
		f->ptr = v_str(r, cat(e, ".Ptr"));
		f->count = v_int(r, cat(e, ".Count"));
	}
	k->pos = v_pos(r, cat(path, ".Pos"));
	k->struct_pos = v_pos(r, cat(path, ".StructPos"));
	sr_str hp = cat(path, ".HandlePoss");
	k->n_handle_poss = v_len(r, hp, &k->handle_poss_nil);
	k->handle_poss = sr_alloc((k->n_handle_poss + 1) * sizeof *k->handle_poss);
	for (size_t i = 0; i < k->n_handle_poss; i++)
		k->handle_poss[i] = v_pos(r, idx(hp, i));
}

static void read_body(rd *r, sr_str path, int kind, void *p)
{
	switch (kind) {
	case K_MAP: read_map(r, path, p); break;
	case K_RECORD: read_record(r, path, p); break;
	case K_RING: read_ring(r, path, p); break;
	case K_GLOBAL: read_global(r, path, p); break;
	default: read_ktype(r, path, p); break;
	}
}

/* a pointer-array field of declarations: nil or #n, then each element */
static void **v_decls(rd *r, sr_str path, int kind, size_t *n, int *is_nil)
{
	*n = v_len(r, path, is_nil);
	void **v = sr_alloc((*n + 1) * sizeof *v);
	for (size_t i = 0; i < *n; i++)
		v[i] = v_decl(r, idx(path, i), kind);
	return v;
}

/* ---- Program and Result ---- */

static fe_program *read_program(rd *r, sr_str path)
{
	if (at(r, cat(path, " = "))) { /* a nil program; a non-nil one prints no line of its own */
		sr_str v = expect(r, path);
		if (!sr_eqc(v, "nil"))
			die(r, "%s: a program is nil or its fields: %s", cs(path), cs(v));
		return NULL;
	}
	fe_program *p = sr_alloc(sizeof *p);
	p->name = v_str(r, cat(path, ".Name"));
	p->kind = v_str(r, cat(path, ".Kind"));
	p->target = v_str(r, cat(path, ".Target"));
	p->nargs = v_int(r, cat(path, ".Nargs"));
	p->ret = v_str(r, cat(path, ".Ret"));
	sr_str x = cat(path, ".Params");
	p->n_params = v_len(r, x, &p->params_nil);
	p->params = sr_alloc((p->n_params + 1) * sizeof *p->params);
	for (size_t i = 0; i < p->n_params; i++) {
		p->params[i].n = v_int(r, cat(idx(x, i), ".N"));
		p->params[i].type = v_str(r, cat(idx(x, i), ".Type"));
	}
	x = cat(path, ".TArgs");
	p->n_t_args = v_len(r, x, &p->t_args_nil);
	p->t_args = sr_alloc((p->n_t_args + 1) * sizeof *p->t_args);
	for (size_t i = 0; i < p->n_t_args; i++) {
		sr_str e = idx(x, i);
		p->t_args[i].idx = v_int(r, cat(e, ".Idx"));
		p->t_args[i].kt = v_decl(r, cat(e, ".KT"), K_KTYPE);
		p->t_args[i].type = v_str(r, cat(e, ".Type"));
		p->t_args[i].null = v_bool(r, cat(e, ".Null"));
	}
	x = cat(path, ".TFields");
	p->n_t_fields = v_len(r, x, &p->t_fields_nil);
	p->t_fields = sr_alloc((p->n_t_fields + 1) * sizeof *p->t_fields);
	for (size_t i = 0; i < p->n_t_fields; i++)
		read_tp_field(r, idx(x, i), &p->t_fields[i]);
	p->f_params = v_strs(r, cat(path, ".FParams"), &p->n_f_params, &p->f_params_nil);
	skip_subtree(r, cat(path, ".FRet"), cat(path, ".FBorrow"));
	p->f_borrow = v_int(r, cat(path, ".FBorrow"));
	p->f_borrow_map = v_decl(r, cat(path, ".FBorrowMap"), K_MAP);
	p->f_win = v_int(r, cat(path, ".FWin"));
	p->f_win_len = v_int(r, cat(path, ".FWinLen"));
	p->f_ctx = v_int(r, cat(path, ".FCtx"));
	p->f_ctx_kind = v_str(r, cat(path, ".FCtxKind"));
	p->binary_sha = v_str(r, cat(path, ".BinarySHA"));
	p->binary_path = v_str(r, cat(path, ".BinaryPath"));
	p->sys_target = v_str(r, cat(path, ".SysTarget"));
	p->globals = (fe_global_decl **)v_decls(r, cat(path, ".Globals"), K_GLOBAL, &p->n_globals, &p->globals_nil);
	p->pos = v_pos(r, cat(path, ".Pos"));
	p->decl_pos = v_pos(r, cat(path, ".DeclPos"));
	skip_subtree(r, cat(path, ".Body"), cat(path, ".Verdict"));
	p->body.nil = 1;
	p->verdict = v_str(r, cat(path, ".Verdict"));
	p->verdict_const = v_str(r, cat(path, ".VerdictConst"));
	p->redir_map = v_decl(r, cat(path, ".RedirMap"), K_MAP);
	skip_subtree(r, cat(path, ".RedirKey"), cat(path, ".GuardVerdict"));
	p->guard_verdict = v_str(r, cat(path, ".GuardVerdict"));
	skip_subtree(r, cat(path, ".FmodVal"), cat(path, ".FmodGuard"));
	sr_str gp = cat(path, ".FmodGuard");
	sr_str g = expect(r, gp);
	if (!sr_eqc(g, "nil")) {
		p->fmod_guard = sr_alloc(sizeof *p->fmod_guard);
		if (!dec_ok(g, 1) || !bigint_parse_dec(p->fmod_guard, g.p, g.n))
			die(r, "%s: not nil or a decimal: %s", cs(gp), cs(g));
	}
	p->verdict_pos = v_pos(r, cat(path, ".VerdictPos"));
	p->end_line = v_int(r, cat(path, ".EndLine"));
	p->maps = (fe_map_decl **)v_decls(r, cat(path, ".Maps"), K_MAP, &p->n_maps, &p->maps_nil);
	p->rings = (fe_ring_decl **)v_decls(r, cat(path, ".Rings"), K_RING, &p->n_rings, &p->rings_nil);
	p->so_type = v_str(r, cat(path, ".SOType"));
	p->so_member = v_str(r, cat(path, ".SOMember"));
	x = cat(path, ".SOArgs");
	int so_nil;
	p->n_so_args = v_len(r, x, &so_nil);
	p->so_args = sr_alloc((p->n_so_args + 1) * sizeof *p->so_args);
	for (size_t i = 0; i < p->n_so_args; i++)
		p->so_args[i] = v_int(r, idx(x, i));
	skip_prefix(r, cat(path, ".SOVal"));
	p->scx = v_bool(r, cat(path, ".Scx"));
	return p;
}

static fe_program **read_programs(rd *r, sr_str path, size_t *n, int *is_nil)
{
	*n = v_len(r, path, is_nil);
	fe_program **v = sr_alloc((*n + 1) * sizeof *v);
	for (size_t i = 0; i < *n; i++)
		v[i] = read_program(r, idx(path, i));
	return v;
}

/* result.Membership["<key>"]: the key is the quoted text between the brackets */
static void read_membership(rd *r, sr_str path, fe_result *res)
{
	int is_nil;
	size_t n = v_len(r, path, &is_nil);
	res->membership_nil = is_nil;
	sr_str prev = {0};
	for (size_t i = 0; i < n; i++) {
		/* the key is quoted, so it holds no raw newline: the path is everything before the line's first " = " after the quote */
		if (!at(r, cat(path, "[\"")))
			die(r, "want %s[<key>] (entry %zu of %zu), have %s", cs(path), i + 1, n, cs(here(r)));
		size_t q = r->pos + path.n + 1, e = q + 1;
		while (e < r->n && r->t[e] != '"' && r->t[e] != '\n')
			e += r->t[e] == '\\' ? 2 : 1;
		if (e >= r->n || r->t[e] != '"' || e + 1 >= r->n || r->t[e + 1] != ']')
			die(r, "%s: the key is not a quoted string", cs(here(r)));
		sr_str key, kpath = {r->t + r->pos, e + 2 - r->pos};
		if (!unquote((sr_str){r->t + q, e + 1 - q}, &key))
			die(r, "%s: the key is not a quoted string", cs(kpath));
		if (i > 0) { /* sorted, distinct (sort.Strings over the map's keys) */
			size_t m = prev.n < key.n ? prev.n : key.n;
			int c = m ? memcmp(prev.p, key.p, m) : 0;
			if (c > 0 || (c == 0 && prev.n >= key.n))
				die(r, "%s: keys out of order or repeated", cs(kpath));
		}
		prev = key;
		fe_str_list *sl = sr_alloc(sizeof *sl);
		int ln;
		size_t k;
		sl->v = v_strs(r, kpath, &k, &ln);
		sl->n = k;
		fe_name_set(&res->membership, key, sl);
	}
}

static fe_code code_of(rd *r, sr_str path, sr_str text)
{
	for (int c = 0; c < FE_NCODES; c++)
		if (sr_eqc(text, fe_code_text((fe_code)c)))
			return (fe_code)c;
	die(r, "%s: not a code: %s", cs(path), cs(text));
}

static void read_diags(rd *r, sr_str path, fe_diags *ds)
{
	int is_nil;
	size_t n = v_len(r, path, &is_nil);
	if (is_nil)
		return; /* ds->v stays NULL: Go's nil */
	ds->v = sr_alloc((n + 1) * sizeof *ds->v);
	ds->cap = n + 1;
	for (size_t i = 0; i < n; i++) {
		sr_str e = idx(path, i);
		fe_diag *g = &ds->v[ds->n++];
		int64_t v = v_int(r, cat(e, ".Verdict"));
		if (v < FE_VERIFIED || v > FE_UNKNOWN)
			die(r, "%s.Verdict: not a verdict: %lld", cs(e), (long long)v);
		g->verdict = (fe_verdict)v;
		sr_str cp = cat(e, ".Code");
		g->code = code_of(r, cp, v_str(r, cp));
		g->pos = v_pos(r, cat(e, ".Pos"));
		int pn;
		g->path = v_strs(r, cat(e, ".Path"), &g->n_path, &pn);
		g->msg = v_str(r, cat(e, ".Msg"));
	}
}

static void read_result(rd *r, fe_result *res)
{
	sr_str path = sr_cstr("result");
	res->source = v_str(r, cat(path, ".Source"));
	res->programs = read_programs(r, cat(path, ".Programs"), &res->n_programs, &res->programs_nil);
	res->maps = (fe_map_decl **)v_decls(r, cat(path, ".Maps"), K_MAP, &res->n_maps, &res->maps_nil);
	res->rings = (fe_ring_decl **)v_decls(r, cat(path, ".Rings"), K_RING, &res->n_rings, &res->rings_nil);
	res->globals = (fe_global_decl **)v_decls(r, cat(path, ".Globals"), K_GLOBAL, &res->n_globals, &res->globals_nil);
	res->kernel_types =
	    (fe_kernel_type_decl **)v_decls(r, cat(path, ".KernelTypes"), K_KTYPE, &res->n_kernel_types, &res->kernel_types_nil);
	res->funcs = read_programs(r, cat(path, ".Funcs"), &res->n_funcs, &res->funcs_nil);
	sr_str so = cat(path, ".StructOps");
	res->n_struct_ops = v_len(r, so, &res->struct_ops_nil);
	res->struct_ops = sr_alloc((res->n_struct_ops + 1) * sizeof *res->struct_ops);
	for (size_t i = 0; i < res->n_struct_ops; i++) {
		sr_str e = idx(so, i);
		fe_struct_ops_decl *d = sr_alloc(sizeof *d);
		d->const_name = v_str(r, cat(e, ".Const"));
		d->type = v_str(r, cat(e, ".Type"));
		d->kname = v_str(r, cat(e, ".KName"));
		sr_str o = cat(e, ".Ops");
		d->n_ops = v_len(r, o, &d->ops_nil);
		d->ops = sr_alloc((d->n_ops + 1) * sizeof *d->ops);
		for (size_t j = 0; j < d->n_ops; j++) {
			d->ops[j].member = v_str(r, cat(idx(o, j), ".Member"));
			d->ops[j].program = v_str(r, cat(idx(o, j), ".Program"));
		}
		sr_str dx = cat(e, ".Data"); /* the keys are the three data members, sorted */
		int data_nil;
		size_t nd = v_len(r, dx, &data_nil);
		static const char *const dk[] = {"dispatch_max_batch", "flags", "timeout_ms"};
		d->data_keys = sr_alloc((nd + 1) * sizeof *d->data_keys);
		d->data_vals = sr_alloc((nd + 1) * sizeof *d->data_vals);
		for (int q = 0; q < 3 && d->n_data < nd; q++) {
			sr_str kp = cat(dx, "[\"");
			kp = cat(cat(kp, dk[q]), "\"]");
			if (!at(r, kp))
				continue;
			d->data_keys[d->n_data] = sr_cstr(dk[q]);
			d->data_vals[d->n_data++] = (uint64_t)v_int(r, kp);
		}
		if (d->n_data != nd)
			die(r, "%s: want %zu data members, read %zu", cs(dx), nd, d->n_data);
		d->pos = v_pos(r, cat(e, ".Pos"));
		d->end_line = v_int(r, cat(e, ".EndLine"));
		res->struct_ops[i] = d;
	}
	read_membership(r, cat(path, ".Membership"), res);
	sr_str x = cat(path, ".Edges");
	res->n_edges = v_len(r, x, &res->edges_nil);
	res->edges = sr_alloc((res->n_edges + 1) * sizeof *res->edges);
	for (size_t i = 0; i < res->n_edges; i++) {
		sr_str e = idx(x, i);
		res->edges[i].from = v_str(r, cat(e, ".From"));
		res->edges[i].to = v_str(r, cat(e, ".To"));
		res->edges[i].pos = v_pos(r, cat(e, ".Pos"));
		res->edges[i].dispatch = v_str(r, cat(e, ".Dispatch"));
	}
	read_diags(r, cat(path, ".Diags"), &res->diags);
}

/* ---- the whole dump ---- */

static int at_line_start(const rd *r, size_t p) { return p == 0 || r->t[p - 1] == '\n'; }

/* the first pass: one object per "decl <kind>:<Const>" line. A Const may hold a newline, so the id ends at the first newline after
 * which the block's first line, "<kind>:<Const>.Const = ", follows. */
static void registry(rd *r)
{
	size_t cap = 16;
	r->reg = sr_alloc(cap * sizeof *r->reg);
	sr_str decl = sr_cstr("decl ");
	for (size_t p = 0; p < r->n; p++) {
		if (!at_line_start(r, p) || r->n - p < decl.n || memcmp(r->t + p, decl.p, decl.n) != 0)
			continue;
		r->pos = p;
		size_t s = p + decl.n;
		int kind = -1;
		for (int k = 0; k < K_N; k++) {
			size_t kn = strlen(kind_name[k]);
			if (r->n - s > kn && memcmp(r->t + s, kind_name[k], kn) == 0 && r->t[s + kn] == ':')
				kind = k;
		}
		if (kind < 0)
			die(r, "a decl line of no known kind: %s", cs(here(r)));
		size_t ns = s + strlen(kind_name[kind]) + 1, ne = 0;
		for (size_t q = ns; q < r->n && !ne; q++) {
			if (r->t[q] != '\n')
				continue;
			sr_str name = {r->t + ns, q - ns};
			sr_buf fb = {0};
			sr_puts(&fb, kind_name[kind]);
			sr_putc(&fb, ':');
			sr_putstr(&fb, name);
			sr_puts(&fb, ".Const = ");
			sr_str f = sr_bufstr(&fb);
			if (r->n - (q + 1) >= f.n && memcmp(r->t + q + 1, f.p, f.n) == 0)
				ne = q;
		}
		if (!ne)
			die(r, "%s: no block follows the decl line", cs(here(r)));
		sr_str name = {r->t + ns, ne - ns};
		for (size_t i = 0; i < r->n_reg; i++)
			if (r->reg[i].kind == kind && sr_eq(r->reg[i].name, name))
				die(r, "two decl blocks have the id %s:%s", kind_name[kind], cs(name));
		if (r->n_reg > 0) { /* the dumper's order: by kind, then by name in byte order */
			rentry *pv = &r->reg[r->n_reg - 1];
			size_t m = pv->name.n < name.n ? pv->name.n : name.n;
			int c = m ? memcmp(pv->name.p, name.p, m) : 0;
			if (pv->kind > kind || (pv->kind == kind && (c > 0 || (c == 0 && pv->name.n > name.n))))
				die(r, "decl %s:%s is out of the dumper's order", kind_name[kind], cs(name));
		}
		if (r->n_reg == cap) {
			rentry *nv = sr_alloc(2 * cap * sizeof *nv);
			memcpy(nv, r->reg, cap * sizeof *nv);
			r->reg = nv;
			cap *= 2;
		}
		r->reg[r->n_reg++] = (rentry){kind, name, new_obj(kind)};
		p = ne;
	}
	r->pos = 0;
}

sr_result fe_read_dump(sr_str text, fe_result *out)
{
	memset(out, 0, sizeof *out);
	rd r = {0};
	r.t = text.p;
	r.n = text.n;
	if (setjmp(r.jb))
		return sr_err("%s", r.err);
	if (at(&r, sr_cstr("error = ")))
		die(&r, "an error dump (Analyze returned an error), not a Result");
	if (r.n == 0 || r.t[r.n - 1] != '\n')
		die(&r, "the dump does not end in a newline");
	registry(&r);
	sr_str dom, dv = expect(&r, sr_cstr("domain"));
	if (!unquote(dv, &dom))
		die(&r, "domain: not a quoted string");
	for (size_t e = 0; e < r.n_reg; e++) {
		rentry *en = &r.reg[e];
		sr_buf ib = {0};
		sr_puts(&ib, kind_name[en->kind]);
		sr_putc(&ib, ':');
		sr_putstr(&ib, en->name);
		sr_str id = sr_bufstr(&ib);
		sr_buf lb = {0};
		sr_puts(&lb, "decl ");
		sr_putstr(&lb, id);
		sr_putc(&lb, '\n');
		if (!at(&r, sr_bufstr(&lb)))
			die(&r, "want the block of decl %s, have %s", cs(id), cs(here(&r)));
		r.pos += lb.n;
		read_body(&r, id, en->kind, en->obj);
		if (!sr_eq(const_of(en->obj), en->name))
			die(&r, "decl %s: its Const is %s", cs(id), cs(const_of(en->obj)));
	}
	read_result(&r, out);
	/* the dump of a Result that Generate lowers ends in one line for the mlir part ("mlir = <q>", "mlir error = <q>" or
	 * "mlir = none"); <q> is quoted ASCII, so the part is a single line. The artefacts do not use it: it is read past, not read. */
	if (at(&r, sr_cstr("mlir = ")) || at(&r, sr_cstr("mlir error = "))) {
		sr_str ml = here(&r);
		if (r.pos + ml.n == r.n)
			die(&r, "the mlir line has no final newline");
		r.pos += ml.n + 1;
	}
	if (r.pos != r.n)
		die(&r, "text after the Result: %s", cs(here(&r)));
	return sr_ok;
}

/* the restricted-c3 filter. A skipped field's subtree is the text from the line "<prog>.<field> = " to the line that starts the
 * next field the dumper prints (FRet -> FBorrow, Body -> Verdict, RedirKey -> GuardVerdict, FmodVal -> FmodGuard; SOVal line by line — Scx, the last field, is not under it), where <prog> is
 * result.Programs[i] or result.Funcs[i]; its lines can hold raw ids with newlines, so the end is found by the next field's path. */
void fe_dump_restrict(sr_buf *out, sr_str dump)
{
	static const char *const skip[][2] = {{".FRet", ".FBorrow"}, {".Body", ".Verdict"}, {".RedirKey", ".GuardVerdict"},
	                                      {".FmodVal", ".FmodGuard"}};
	static const char *const progs[] = {"result.Programs[", "result.Funcs["};
	for (size_t s = 0; s < dump.n;) {
		const char *nl = memchr(dump.p + s, '\n', dump.n - s);
		size_t len = nl ? (size_t)(nl - (dump.p + s)) + 1 : dump.n - s;
		size_t end = s + len; /* the text kept or dropped ends here */
		/* the mlir line is read past by the reader, so it is not part of the restricted lines either */
		if ((len > 7 && memcmp(dump.p + s, "mlir = ", 7) == 0) || (len > 13 && memcmp(dump.p + s, "mlir error = ", 13) == 0))
			goto drop;
		for (size_t g = 0; g < 2; g++) {
			size_t pl = strlen(progs[g]);
			if (len <= pl || memcmp(dump.p + s, progs[g], pl) != 0)
				continue;
			size_t k = s + pl;
			while (k < s + len && dump.p[k] >= '0' && dump.p[k] <= '9')
				k++;
			if (k == s + pl || k >= s + len || dump.p[k] != ']')
				continue;
			sr_str prog = {dump.p + s, k + 1 - s};
			/* SOVal is a program's last field, so its subtree has no next path: each of its lines starts with
			 * "<prog>.SOVal = " or "<prog>.SOVal." (its strings are quoted ASCII — no raw newline) and is dropped (skip_prefix) */
			if (s + len - (k + 1) >= 9 && memcmp(dump.p + k + 1, ".SOVal", 6) == 0 &&
			    (memcmp(dump.p + k + 7, " = ", 3) == 0 || dump.p[k + 7] == '.'))
				goto drop;
			for (size_t q = 0; q < 4; q++) {
				size_t fl = strlen(skip[q][0]);
				/* "<prog><field> = " or "<prog><field>." (a non-nil expression's first field) */
				if (s + len - (k + 1) < fl + 3 || memcmp(dump.p + k + 1, skip[q][0], fl) != 0 ||
				    (memcmp(dump.p + k + 1 + fl, " = ", 3) != 0 && dump.p[k + 1 + fl] != '.'))
					continue;
				sr_buf nb = {0};
				sr_putc(&nb, '\n');
				sr_putstr(&nb, prog);
				sr_puts(&nb, skip[q][1]);
				sr_puts(&nb, " = ");
				sr_str nx = sr_bufstr(&nb);
				end = dump.n;
				for (size_t p = s; p + nx.n <= dump.n; p++)
					if (memcmp(dump.p + p, nx.p, nx.n) == 0) {
						end = p + 1;
						break;
					}
				goto drop;
			}
		}
		sr_putstr(out, (sr_str){dump.p + s, len});
		s = end;
		continue;
	drop:
		s = end;
	}
}
