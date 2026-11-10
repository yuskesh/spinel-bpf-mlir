/* body_decl — the methods of the declaration types that the body, the lowerer and the schema writer call (G1 owns these 13 by
 * the contract of 2026-11-13). Pure functions of the declaration structs of top.h; each comment names the Go it follows. Strings
 * come from the arena (sr_alloc).
 * Boundary: the `%q` of a record's constant name (fe_record_decl_mlir_type, fe_record_decl_shape does not use it) is Go's for ASCII
 * names; a name with a byte >= 0x80 is written unquoted-as-is inside the quotes (the byte comparison with Go covers ASCII names only). */
#include "body.h"

#include <stdio.h>
#include <string.h>

/* record.go RecordField.Size */
int64_t fe_record_field_size(const fe_record_field *f)
{
	if (f->count > 0) return f->bits / 8 * f->count;
	return f->bits / 8;
}

/* record.go RecordField.TypeName */
sr_str fe_record_field_type_name(const fe_record_field *f)
{
	sr_buf b = {0};
	sr_printf(&b, "%c%lld", f->is_signed ? 'i' : 'u', (long long)f->bits);
	return sr_bufstr(&b);
}

/* record.go RecordField.DeclType */
sr_str fe_record_field_decl_type(const fe_record_field *f)
{
	if (f->count > 0) {
		sr_buf b = {0};
		sr_printf(&b, "[%lld]", (long long)f->count);
		sr_putstr(&b, fe_record_field_type_name(f));
		return sr_bufstr(&b);
	}
	return fe_record_field_type_name(f);
}

/* record.go RecordField.Flat: n >= 1 always (an array member has count > 0). */
void fe_record_field_flat(const fe_record_field *f, sr_str **names, int64_t **offsets, size_t *n)
{
	if (f->count == 0) {
		*names = sr_alloc(sizeof(sr_str));
		*offsets = sr_alloc(sizeof(int64_t));
		(*names)[0] = f->name;
		(*offsets)[0] = f->offset;
		*n = 1;
		return;
	}
	*n = (size_t)f->count;
	*names = sr_alloc(*n * sizeof(sr_str));
	*offsets = sr_alloc(*n * sizeof(int64_t));
	for (int64_t i = 0; i < f->count; i++) {
		sr_buf b = {0};
		sr_putstr(&b, f->name);
		sr_printf(&b, "[%lld]", (long long)i);
		(*names)[i] = sr_bufstr(&b);
		(*offsets)[i] = f->offset + i * f->bits / 8;
	}
}

/* record.go RecordField.Range: the member type's range (u64 stops at 2^63-1 — the Ruby Integer limit). bits >= 1. */
fe_ival fe_record_field_range(const fe_record_field *f)
{
	fe_ival r = {1, {0}, {0}};
	intv one = intv_from_i64(1), t;
	if (f->is_signed) {
		intv_lsh(one, (uint64_t)(f->bits - 1), &t);
		r.lo = intv_neg(t);
		intv_sub(t, one, &r.hi);
		return r;
	}
	r.lo = intv_from_i64(0);
	if (f->bits == 64) {
		r.hi = intv_from_i64(INT64_MAX);
		return r;
	}
	intv_lsh(one, (uint64_t)f->bits, &t);
	intv_sub(t, one, &r.hi);
	return r;
}

/* record.go RecordDecl.HasArray */
int fe_record_decl_has_array(const fe_record_decl *r)
{
	for (size_t i = 0; i < r->n_fields; i++)
		if (r->fields[i].count > 0) return 1;
	return 0;
}

/* record.go RecordDecl.MLIRType: `!ebpf.record<%q, %d>` */
sr_str fe_record_decl_mlir_type(const fe_record_decl *r)
{
	sr_buf b = {0};
	sr_puts(&b, "!ebpf.record<");
	if (!sr_quote_go_ascii(&b, r->const_name)) {
		sr_putc(&b, '"');
		sr_putstr(&b, r->const_name);
		sr_putc(&b, '"');
	}
	sr_printf(&b, ", %lld>", (long long)r->size);
	return sr_bufstr(&b);
}

/* record.go RecordDecl.Shape: `S|size=24;a:0:u32;…` */
sr_str fe_record_decl_shape(const fe_record_decl *r)
{
	sr_buf b = {0};
	sr_putstr(&b, r->const_name);
	sr_printf(&b, "|size=%lld;", (long long)r->size);
	for (size_t i = 0; i < r->n_fields; i++) {
		const fe_record_field *f = &r->fields[i];
		sr_str *ns;
		int64_t *os;
		size_t n;
		fe_record_field_flat(f, &ns, &os, &n);
		sr_str tn = fe_record_field_type_name(f);
		for (size_t j = 0; j < n; j++) {
			sr_putstr(&b, ns[j]);
			sr_printf(&b, ":%lld:", (long long)os[j]);
			sr_putstr(&b, tn);
			sr_putc(&b, ';');
		}
	}
	return sr_bufstr(&b);
}

/* globals.go GlobalDecl.Counter */
int fe_global_counter(const fe_global_decl *g) { return sr_eqc(g->class_name, "Counter"); }

/* globals.go GlobalDecl.TypeName */
sr_str fe_global_type_name(const fe_global_decl *g)
{
	sr_buf b = {0};
	sr_printf(&b, "%c%lld", g->is_signed ? 'i' : 'u', (long long)g->bits);
	return sr_bufstr(&b);
}

/* lpm.go MapDecl.IsLpm */
int fe_map_is_lpm(const fe_map_decl *m) { return sr_eqc(m->kind, "lpm_trie"); }

/* lpm.go MapDecl.Flags: BPF_F_NO_PREALLOC (1) for lpm_trie, else 0 */
uint64_t fe_map_flags(const fe_map_decl *m) { return fe_map_is_lpm(m) ? 1 : 0; }

/* devmap.go MapDecl.IsDevmap */
int fe_map_is_devmap(const fe_map_decl *m) { return sr_eqc(m->kind, "devmap"); }

/* analyze.go MapDecl.IsHash */
int fe_g1_map_is_hash(const fe_map_decl *m) { return sr_eqc(m->kind, "hash") || sr_eqc(m->kind, "lru_hash") || sr_eqc(m->kind, "percpu_hash"); }

/* analyze.go MapDecl.IsArray: array and percpu_array ("" is array) */
int fe_g1_map_is_array(const fe_map_decl *m) { return m->kind.n == 0 || sr_eqc(m->kind, "percpu_array"); }

/* analyze.go MapDecl.ClassName */
sr_str fe_g1_map_class_name(const fe_map_decl *m)
{
	if (m->class_name.n) return m->class_name;
	return sr_cstr(m->record ? "RecordMap" : "ArrayMap");
}

/* analyze.go MapDecl.KeyTypeName */
sr_str fe_g1_map_key_type_name(const fe_map_decl *m)
{
	sr_buf b = {0};
	if (m->key_record) {
		sr_puts(&b, "record:");
		sr_putstr(&b, m->key_record->const_name);
	} else if (fe_g1_map_is_array(m) || sr_eqc(m->kind, "devmap") || sr_eqc(m->kind, "sockmap")) {
		sr_puts(&b, "u32");
	} else {
		sr_printf(&b, "%c%lld", m->key_signed ? 'i' : 'u', (long long)m->key_bits);
	}
	return sr_bufstr(&b);
}

