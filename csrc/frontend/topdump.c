/* topdump.c — the canonical dump of fe_top. It mirrors internal/frontend/e187_dump_test.go: the same field order, the same
 * value rules (strconv.QuoteToASCII strings, {Name=v ...} structs, nil / [] slices, sorted maps) and the same identity numbering
 * of declaration pointers (in the order the dump first meets them, then one defs line each). */
#include "top_int.h"

#include <stdlib.h>
#include <string.h>

enum { D_MAP, D_RECORD, D_RING, D_GLOBAL, D_KT };

typedef struct {
	int type;
	const void *p;
} ident;

typedef struct {
	sr_buf *b;
	ident *ids;
	size_t n_ids;
} dumper;

static const char *const type_names[] = {"MapDecl", "RecordDecl", "RingDecl", "GlobalDecl", "KernelTypeDecl"};

static void q(dumper *d, sr_str s) { sr_quote_ascii(d->b, s); }
static void s(dumper *d, const char *x) { sr_puts(d->b, x); }
static void i64(dumper *d, int64_t v) { sr_printf(d->b, "%lld", (long long)v); }
static void u64(dumper *d, uint64_t v) { sr_printf(d->b, "%llu", (unsigned long long)v); }
static void bl(dumper *d, int v) { s(d, v ? "true" : "false"); }

static sr_str const_of(int type, const void *p)
{
	switch (type) {
	case D_MAP:
		return ((const fe_map_decl *)p)->const_name;
	case D_RECORD:
		return ((const fe_record_decl *)p)->const_name;
	case D_RING:
		return ((const fe_ring_decl *)p)->const_name;
	case D_GLOBAL:
		return ((const fe_global_decl *)p)->const_name;
	default:
		return ((const fe_kernel_type_decl *)p)->const_name;
	}
}

static void ptr(dumper *d, int type, const void *p)
{
	if (!p) {
		s(d, "nil");
		return;
	}
	size_t id = d->n_ids;
	for (size_t i = 0; i < d->n_ids; i++)
		if (d->ids[i].p == p) {
			id = i;
			break;
		}
	if (id == d->n_ids)
		T_PUSH(d->ids, d->n_ids, ((ident){type, p}));
	s(d, "&");
	q(d, const_of(type, p));
	sr_printf(d->b, "#%zu", id);
}

static void pos(dumper *d, fe_pos p)
{
	s(d, "{File=");
	q(d, p.file);
	s(d, " Line=");
	i64(d, p.line);
	s(d, " Col=");
	i64(d, p.col);
	s(d, "}");
}

/* ---- struct values (Go field order) ---- */
static void record_field(dumper *d, const fe_record_field *f)
{
	s(d, "{Name=");
	q(d, f->name);
	s(d, " Bits=");
	i64(d, f->bits);
	s(d, " Signed=");
	bl(d, f->is_signed);
	s(d, " Pad=");
	bl(d, f->pad);
	s(d, " Offset=");
	i64(d, f->offset);
	s(d, " Count=");
	i64(d, f->count);
	s(d, "}");
}

static void kernel_field(dumper *d, const fe_kernel_field *f)
{
	s(d, "{Name=");
	q(d, f->name);
	s(d, " Kind=");
	q(d, f->kind);
	s(d, " Bits=");
	i64(d, f->bits);
	s(d, " Signed=");
	bl(d, f->is_signed);
	s(d, " Ptr=");
	q(d, f->ptr);
	s(d, " Count=");
	i64(d, f->count);
	s(d, "}");
}

#define SLICE(d, arr, n, isnil, elem)                                                                                              \
	do {                                                                                                                       \
		if (isnil) {                                                                                                       \
			s(d, "nil");                                                                                               \
		} else {                                                                                                           \
			s(d, "[");                                                                                                 \
			for (size_t i_ = 0; i_ < (n); i_++) {                                                                      \
				if (i_ > 0)                                                                                        \
					s(d, " ");                                                                                 \
				elem(d, &(arr)[i_]);                                                                               \
			}                                                                                                          \
			s(d, "]");                                                                                                 \
		}                                                                                                                  \
	} while (0)

static void pos_p(dumper *d, const fe_pos *p) { pos(d, *p); }

static void map_decl(dumper *d, const fe_map_decl *m)
{
	s(d, "{Const=");
	q(d, m->const_name);
	s(d, " Name=");
	q(d, m->name);
	s(d, " ValueBits=");
	i64(d, m->value_bits);
	s(d, " Signed=");
	bl(d, m->is_signed);
	s(d, " MaxEntries=");
	u64(d, m->max_entries);
	s(d, " Record=");
	ptr(d, D_RECORD, m->record);
	s(d, " Kind=");
	q(d, m->kind);
	s(d, " Class=");
	q(d, m->class_name);
	s(d, " KeyBits=");
	i64(d, m->key_bits);
	s(d, " KeySigned=");
	bl(d, m->key_signed);
	s(d, " KeyRecord=");
	ptr(d, D_RECORD, m->key_record);
	s(d, " Pos=");
	pos(d, m->pos);
	s(d, "}");
}

static void record_decl(dumper *d, const fe_record_decl *r)
{
	s(d, "{Const=");
	q(d, r->const_name);
	s(d, " Fields=");
	SLICE(d, r->fields, r->n_fields, r->fields_nil, record_field);
	s(d, " Size=");
	i64(d, r->size);
	s(d, " Align=");
	i64(d, r->align);
	s(d, " Pos=");
	pos(d, r->pos);
	s(d, " StructPos=");
	pos(d, r->struct_pos);
	s(d, "}");
}

static void ring_decl(dumper *d, const fe_ring_decl *r)
{
	s(d, "{Const=");
	q(d, r->const_name);
	s(d, " Name=");
	q(d, r->name);
	s(d, " Record=");
	ptr(d, D_RECORD, r->record);
	s(d, " Size=");
	u64(d, r->size);
	s(d, " Pos=");
	pos(d, r->pos);
	s(d, "}");
}

static void global_decl(dumper *d, const fe_global_decl *g)
{
	s(d, "{Const=");
	q(d, g->const_name);
	s(d, " Name=");
	q(d, g->name);
	s(d, " Class=");
	q(d, g->class_name);
	s(d, " Section=");
	q(d, g->section);
	s(d, " Bits=");
	i64(d, g->bits);
	s(d, " Signed=");
	bl(d, g->is_signed);
	s(d, " Optional=");
	bl(d, g->optional);
	s(d, " Pos=");
	pos(d, g->pos);
	s(d, "}");
}

static void kt_decl(dumper *d, const fe_kernel_type_decl *k)
{
	s(d, "{Const=");
	q(d, k->const_name);
	s(d, " Name=");
	q(d, k->name);
	s(d, " Fields=");
	SLICE(d, k->fields, k->n_fields, k->fields_nil, kernel_field);
	s(d, " Pos=");
	pos(d, k->pos);
	s(d, " StructPos=");
	pos(d, k->struct_pos);
	s(d, " HandlePoss=");
	SLICE(d, k->handle_poss, k->n_handle_poss, k->handle_poss_nil, pos_p);
	s(d, "}");
}

static void kparam(dumper *d, const fe_kparam *p)
{
	s(d, "{N=");
	i64(d, p->n);
	s(d, " Type=");
	q(d, p->type);
	s(d, "}");
}

static void tp_arg(dumper *d, const fe_tp_arg *a)
{
	s(d, "{Idx=");
	i64(d, a->idx);
	s(d, " KT=");
	ptr(d, D_KT, a->kt);
	s(d, " Type=");
	q(d, a->type);
	s(d, " Null=");
	bl(d, a->null);
	s(d, "}");
}

static void tp_field(dumper *d, const fe_tp_field *f)
{
	s(d, "{Name=");
	q(d, f->name);
	s(d, " Offset=");
	i64(d, f->offset);
	s(d, " Type=");
	q(d, f->type);
	s(d, " N=");
	i64(d, f->n);
	s(d, "}");
}

static void root_decl(dumper *d, const fe_root_decl *r)
{
	s(d, "{Name=");
	q(d, r->name);
	s(d, " Kind=");
	q(d, r->kind);
	s(d, " Pos=");
	pos(d, r->pos);
	s(d, " Target=");
	q(d, r->target);
	s(d, " Nargs=");
	i64(d, r->nargs);
	s(d, " Ret=");
	q(d, r->ret);
	s(d, " Params=");
	SLICE(d, r->params, r->n_params, r->params_nil, kparam);
	s(d, " BinarySHA=");
	q(d, r->binary_sha);
	s(d, " BinaryPath=");
	q(d, r->binary_path);
	s(d, " SysTarget=");
	q(d, r->sys_target);
	s(d, " TArgs=");
	SLICE(d, r->targs, r->n_targs, r->targs_nil, tp_arg);
	s(d, " TFields=");
	SLICE(d, r->tfields, r->n_tfields, r->tfields_nil, tp_field);
	s(d, " SOType=");
	q(d, r->so_type);
	s(d, " SOMember=");
	q(d, r->so_member);
	s(d, "}");
}

static void thread_ref(dumper *d, const fe_thread_ref *t)
{
	s(d, "{name=");
	q(d, t->name);
	s(d, " pos=");
	pos(d, t->pos);
	s(d, " line=");
	i64(d, t->line);
	s(d, "}");
}

static void diag(dumper *d, const fe_diag *x)
{
	s(d, "{Verdict=");
	i64(d, (int64_t)x->verdict);
	s(d, " Code=");
	q(d, sr_cstr(fe_code_text(x->code)));
	s(d, " Pos=");
	pos(d, x->pos);
	s(d, " Path=");
	if (x->n_path == 0 && !x->path) {
		s(d, "nil");
	} else {
		s(d, "[");
		for (size_t i = 0; i < x->n_path; i++) {
			if (i > 0)
				s(d, " ");
			q(d, x->path[i]);
		}
		s(d, "]");
	}
	s(d, " Msg=");
	q(d, x->msg);
	s(d, "}");
}

static void str_p(dumper *d, const sr_str *x) { q(d, *x); }

/* ---- list and table fields ---- */
#define LIST_FIELD(d, name, arr, n, isnil, elem)                                                                                   \
	do {                                                                                                                       \
		if (isnil) {                                                                                                       \
			sr_printf((d)->b, "%s nil\n", name);                                                                       \
		} else {                                                                                                           \
			sr_printf((d)->b, "%s len=%zu\n", name, (size_t)(n));                                                      \
			for (size_t i_ = 0; i_ < (n); i_++) {                                                                      \
				sr_printf((d)->b, "%s[%zu] ", name, i_);                                                           \
				elem(d, &(arr)[i_]);                                                                               \
				s(d, "\n");                                                                                        \
			}                                                                                                          \
		}                                                                                                                  \
	} while (0)

static int entry_cmp(const void *x, const void *y)
{
	return sr_cmp((*(const fe_name_entry *const *)x)->key, (*(const fe_name_entry *const *)y)->key);
}

/* a Go map field (never nil in the analyzer): sorted keys; type < 0 prints the bool true of a set */
static void table_field(dumper *d, const char *name, const fe_name_table *t, int type)
{
	const fe_name_entry **es = NULL;
	size_t n = 0;
	for (size_t i = 0; i < t->n; i++)
		if (!t->e[i].removed)
			T_PUSH(es, n, &t->e[i]);
	if (n > 1)
		qsort(es, n, sizeof *es, entry_cmp);
	sr_printf(d->b, "%s len=%zu\n", name, n);
	for (size_t i = 0; i < n; i++) {
		sr_printf(d->b, "%s[", name);
		q(d, es[i]->key);
		s(d, "] ");
		if (type < 0)
			bl(d, es[i]->val != NULL);
		else
			ptr(d, type, es[i]->val);
		s(d, "\n");
	}
}

static void map_p(dumper *d, fe_map_decl *const *m) { ptr(d, D_MAP, *m); }
static void ring_p(dumper *d, fe_ring_decl *const *r) { ptr(d, D_RING, *r); }
static void global_p(dumper *d, fe_global_decl *const *g) { ptr(d, D_GLOBAL, *g); }
static void kt_p(dumper *d, fe_kernel_type_decl *const *k) { ptr(d, D_KT, *k); }

static void defs(dumper *d)
{
	sr_buf body = {0}, *saved = d->b;
	d->b = &body;
	for (size_t i = 0; i < d->n_ids; i++) {
		ident x = d->ids[i];
		sr_printf(d->b, "defs[%zu] %s ", i, type_names[x.type]);
		switch (x.type) {
		case D_MAP:
			map_decl(d, x.p);
			break;
		case D_RECORD:
			record_decl(d, x.p);
			break;
		case D_RING:
			ring_decl(d, x.p);
			break;
		case D_GLOBAL:
			global_decl(d, x.p);
			break;
		default:
			kt_decl(d, x.p);
		}
		s(d, "\n");
	}
	d->b = saved;
	sr_printf(d->b, "defs len=%zu\n", d->n_ids);
	sr_putstr(d->b, sr_bufstr(&body));
}

void fe_top_dump(sr_buf *b, const fe_z *z, const fe_top *t)
{
	dumper d = {.b = b};
	if (t->outcome == FE_TOP_ERROR) {
		/* a not-ported stop has no Go counterpart: its own word, so it never compares equal */
		s(&d, t->err.kind == SR_NOT_PORTED ? "outcome not-ported\n" : "outcome error\n");
		s(&d, "err ");
		q(&d, t->err.text);
		s(&d, "\n");
		return;
	}
	if (t->outcome == FE_TOP_RETURNED) {
		s(&d, "outcome returned\n");
		LIST_FIELD(&d, "res.Diags", t->res_diags, t->n_res_diags, t->res_diags_nil, diag);
		return;
	}
	s(&d, "outcome continue\n");
	LIST_FIELD(&d, "threadRefs", t->thread_refs, t->n_thread_refs, t->thread_refs_nil, thread_ref);
	table_field(&d, "kts", &t->kts, D_KT);
	LIST_FIELD(&d, "ktOrder", t->kt_order, t->n_kt_order, t->kt_order_nil, kt_p);
	table_field(&d, "ktHandles", &t->kt_handles, D_KT);
	table_field(&d, "maps", &t->maps, D_MAP);
	LIST_FIELD(&d, "mapOrder", t->map_order, t->n_map_order, t->map_order_nil, map_p);
	table_field(&d, "badMaps", &t->bad_maps, -1);
	table_field(&d, "badHash", &t->bad_hash, -1);
	table_field(&d, "records", &t->records, D_RECORD);
	table_field(&d, "badRecs", &t->bad_recs, -1);
	table_field(&d, "rings", &t->rings, D_RING);
	LIST_FIELD(&d, "ringOrder", t->ring_order, t->n_ring_order, t->ring_order_nil, ring_p);
	table_field(&d, "badRings", &t->bad_rings, -1);
	table_field(&d, "globals", &t->globals, D_GLOBAL);
	LIST_FIELD(&d, "globalOrder", t->global_order, t->n_global_order, t->global_order_nil, global_p);
	table_field(&d, "badGlobals", &t->bad_globals, -1);
	LIST_FIELD(&d, "rootKinds", t->root_kinds, t->n_root_kinds, t->root_kinds_nil, str_p);
	LIST_FIELD(&d, "diags", z->diags.v, z->diags.n, z->diags.v == NULL, diag);
	LIST_FIELD(&d, "roots", t->roots, t->n_roots, t->roots_nil, root_decl);
	s(&d, "inject ");
	q(&d, t->inject);
	s(&d, "\nplain\n");
	/* dumpAnalysis(z.plain, nil, nil): the diagnostics argument is nil */
	sr_analysis plain = t->plain;
	plain.diags = NULL;
	plain.n_diags = 0;
	sr_buf pb = {0};
	sr_dump_analysis(&pb, &plain);
	sr_putstr(b, sr_bufstr(&pb));
	defs(&d);
}
