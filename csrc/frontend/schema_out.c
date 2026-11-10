/* schema_out — Schema, MapsJSON and RecordsTable in C. Each function names the Go it follows (internal/frontend at the time of
 * this port): schema.go for Schema / MapsJSON / usedRecords / ringSize, kernel.go for kernelTypesSchema / tpArgsSchema / ktName,
 * fmodret.go for fmodArgsSchema, record.go for RecordsTable, globals.go for globalRows. JSON key order is the Go struct's; an
 * omitempty field is skipped here. A Go nil slice is "null", an empty non-nil one "[]". */
#include "schema_out.h"

#include <string.h>

#include "jsonout.h"

/* ---- recordTypes (record.go) and traceInt (schema.go): a miss is Go's zero value {0, 0} ---- */
static void trace_bits(sr_str t, int64_t *bits, int *sign)
{
	static const struct {
		const char *n;
		int bits, sign;
	} tab[] = {{"u8", 8, 0}, {"u16", 16, 0}, {"u32", 32, 0}, {"u64", 64, 0}, {"i8", 8, 1}, {"i16", 16, 1}, {"i32", 32, 1}, {"i64", 64, 1}};
	*bits = 0, *sign = 0;
	for (size_t i = 0; i < sizeof tab / sizeof *tab; i++)
		if (sr_eqc(t, tab[i].n)) {
			*bits = tab[i].bits, *sign = tab[i].sign;
			return;
		}
}

/* schemaInt: {"kind": "int", "bits", "signed", "endianness": "little", "alignment": bits/8} */
static void w_int(fe_jw *w, int64_t bits, int is_signed)
{
	fe_jw_obj_begin(w);
	fe_jw_keyc(w, "kind");
	fe_jw_strc(w, "int");
	fe_jw_keyc(w, "bits");
	fe_jw_i64(w, bits);
	fe_jw_keyc(w, "signed");
	fe_jw_bool(w, is_signed);
	fe_jw_keyc(w, "endianness");
	fe_jw_strc(w, "little");
	fe_jw_keyc(w, "alignment");
	fe_jw_i64(w, bits / 8);
	fe_jw_obj_end(w);
}

static void w_trace_int(fe_jw *w, sr_str t)
{
	int64_t bits;
	int sign;
	trace_bits(t, &bits, &sign);
	w_int(w, bits, sign);
}

static void w_kv_str(fe_jw *w, const char *k, sr_str v)
{
	fe_jw_keyc(w, k);
	fe_jw_str(w, v);
}

static void w_kv_strc(fe_jw *w, const char *k, const char *v)
{
	fe_jw_keyc(w, k);
	fe_jw_strc(w, v);
}

/* a string "<prefix><s><suffix>" */
static sr_str cat3(const char *a, sr_str b, const char *c)
{
	sr_buf x = {0};
	sr_puts(&x, a);
	sr_putstr(&x, b);
	sr_puts(&x, c);
	return sr_bufstr(&x);
}

/* usedRecords (schema.go) */
fe_record_decl **fe_used_records(const fe_result *r, size_t *n)
{
	size_t cap = 2 * r->n_maps + r->n_rings + 1, k = 0;
	fe_record_decl **out = sr_alloc(cap * sizeof *out);
	fe_ptr_set seen = {0};
	for (size_t i = 0; i < r->n_maps; i++) {
		fe_record_decl *rs[2] = {r->maps[i]->key_record, r->maps[i]->record}; /* the key's record first (schema and maps.json order) */
		for (int j = 0; j < 2; j++)
			if (rs[j] && !fe_ptr_set_has(&seen, rs[j])) {
				fe_ptr_set_add(&seen, rs[j]);
				out[k++] = rs[j];
			}
	}
	for (size_t i = 0; i < r->n_rings; i++) {
		fe_record_decl *rd = r->rings[i]->record;
		if (!fe_ptr_set_has(&seen, rd)) {
			fe_ptr_set_add(&seen, rd);
			out[k++] = rd;
		}
	}
	*n = k;
	return out;
}

/* ktName (kernel.go): the kernel struct's name of a Struct constant, or the constant */
static sr_str kt_name(const fe_result *r, sr_str c)
{
	for (size_t i = 0; i < r->n_kernel_types; i++)
		if (sr_eq(r->kernel_types[i]->const_name, c))
			return r->kernel_types[i]->name;
	return c;
}

/* kernelTypesSchema (kernel.go): the elements of core.kernel_types */
static void w_kernel_types(fe_jw *w, const fe_result *r)
{
	fe_jw_arr_begin(w);
	for (size_t i = 0; i < r->n_kernel_types; i++) {
		const fe_kernel_type_decl *d = r->kernel_types[i];
		fe_jw_obj_begin(w);
		w_kv_str(w, "name", d->name);
		fe_jw_keyc(w, "note");
		fe_jw_str(w, cat3("Ruby Struct ", d->const_name, ""));
		fe_jw_keyc(w, "fields");
		if (d->n_fields == 0) {
			fe_jw_null(w); /* Go appends to a nil slice: none appended is nil */
		} else {
			fe_jw_arr_begin(w);
			for (size_t j = 0; j < d->n_fields; j++) {
				const fe_kernel_field *f = &d->fields[j];
				fe_jw_obj_begin(w);
				w_kv_str(w, "name", f->name);
				fe_jw_keyc(w, "type");
				if (sr_eqc(f->kind, "int")) {
					w_int(w, f->bits, f->is_signed);
				} else if (sr_eqc(f->kind, "kptr")) {
					fe_jw_obj_begin(w);
					w_kv_strc(w, "kind", "kptr");
					w_kv_str(w, "struct", kt_name(r, f->ptr));
					fe_jw_obj_end(w);
				} else if (sr_eqc(f->kind, "array")) {
					fe_jw_obj_begin(w);
					w_kv_strc(w, "kind", "array");
					fe_jw_keyc(w, "count");
					fe_jw_i64(w, f->count);
					fe_jw_keyc(w, "element");
					w_int(w, 8, f->is_signed);
					fe_jw_obj_end(w);
				} else if (sr_eqc(f->kind, "strptr")) {
					fe_jw_obj_begin(w);
					w_kv_strc(w, "kind", "strptr");
					fe_jw_obj_end(w);
				} else if (sr_eqc(f->kind, "struct")) {
					fe_jw_obj_begin(w);
					w_kv_strc(w, "kind", "struct");
					w_kv_str(w, "struct", kt_name(r, f->ptr));
					fe_jw_obj_end(w);
				} else {
					fe_jw_null(w); /* a kind none of the cases names: Go's nil interface */
				}
				fe_jw_obj_end(w);
			}
			fe_jw_arr_end(w);
		}
		fe_jw_obj_end(w);
	}
	fe_jw_arr_end(w);
}

/* tpArgsSchema (kernel.go): the length is the largest index + 1; a gap is null */
static void w_tp_args(fe_jw *w, const fe_program *p)
{
	int64_t n = 0;
	for (size_t i = 0; i < p->n_t_args; i++)
		if (p->t_args[i].idx + 1 > n)
			n = p->t_args[i].idx + 1;
	fe_jw_arr_begin(w);
	for (int64_t k = 0; k < n; k++) {
		const fe_tp_arg *a = NULL; /* the last argument with this index wins, as Go's out[a.Idx] = … */
		for (size_t i = 0; i < p->n_t_args; i++)
			if (p->t_args[i].idx == k)
				a = &p->t_args[i];
		if (!a) {
			fe_jw_null(w);
		} else if (a->kt && a->null) {
			fe_jw_obj_begin(w);
			w_kv_strc(w, "kind", "struct");
			w_kv_str(w, "name", a->kt->name);
			fe_jw_keyc(w, "nullable");
			fe_jw_bool(w, 1);
			fe_jw_obj_end(w);
		} else if (a->kt) {
			fe_jw_str(w, a->kt->name);
		} else {
			w_trace_int(w, a->type);
		}
	}
	fe_jw_arr_end(w);
}

/* fmodArgsSchema (fmodret.go): a slice of Nargs, a gap is null; called only when there are t_args */
static void w_fmod_args(fe_jw *w, const fe_program *p)
{
	fe_jw_arr_begin(w);
	for (int64_t k = 0; k < p->nargs; k++) {
		const fe_tp_arg *a = NULL;
		for (size_t i = 0; i < p->n_t_args; i++)
			if (p->t_args[i].idx == k)
				a = &p->t_args[i];
		if (a)
			w_trace_int(w, a->type);
		else
			fe_jw_null(w);
	}
	fe_jw_arr_end(w);
}

static void w_record_ref(fe_jw *w, sr_str sym)
{
	fe_jw_obj_begin(w);
	w_kv_strc(w, "kind", "record_ref");
	w_kv_str(w, "symbol", sym);
	fe_jw_obj_end(w);
}

static void w_param_kind(fe_jw *w, sr_str kind)
{
	fe_jw_obj_begin(w);
	w_kv_str(w, "kind", kind);
	fe_jw_obj_end(w);
}

/* the key order of schemaProgram: name, kind, attach_target, nargs, ret, maps, arch, params, binary_sha256, args, fields, note */
static void w_program(fe_jw *w, const fe_result *r, const fe_program *p)
{
	(void)r;
	sr_str k = p->kind;
	int has_nargs = sr_eqc(k, "fexit") || sr_eqc(k, "fmod_ret");
	int is_kp = sr_eqc(k, "kprobe") || sr_eqc(k, "uprobe") || sr_eqc(k, "ksyscall");
	int has_arch = sr_eqc(k, "kretprobe") || sr_eqc(k, "uretprobe") || is_kp;
	int has_sha = sr_eqc(k, "uretprobe") || is_kp;
	size_t n_params = is_kp ? p->n_params : 0;
	int n_args_out = 0; /* 0: omitted */
	if (sr_eqc(k, "fmod_ret")) {
		n_args_out = p->n_t_args > 0 && p->nargs > 0;
	} else if (sr_eqc(k, "tp_btf")) {
		int64_t n = 0;
		for (size_t i = 0; i < p->n_t_args; i++)
			if (p->t_args[i].idx + 1 > n)
				n = p->t_args[i].idx + 1;
		n_args_out = n > 0;
	} else if (sr_eqc(k, "fentry")) {
		n_args_out = p->n_t_args > 0;
	}
	int has_fields = sr_eqc(k, "tracepoint") && p->n_t_fields > 0;

	fe_jw_obj_begin(w);
	w_kv_str(w, "name", p->name);
	w_kv_str(w, "kind", k);
	w_kv_str(w, "attach_target", p->target);
	if (has_nargs) {
		fe_jw_keyc(w, "nargs");
		fe_jw_i64(w, p->nargs);
		fe_jw_keyc(w, "ret");
		w_trace_int(w, p->ret);
	}
	fe_jw_keyc(w, "maps");
	fe_jw_arr_begin(w);
	for (size_t i = 0; i < p->n_maps; i++)
		fe_jw_str(w, p->maps[i]->name);
	fe_jw_arr_end(w);
	if (has_arch)
		w_kv_strc(w, "arch", "x86_64");
	if (n_params > 0) {
		fe_jw_keyc(w, "params");
		fe_jw_arr_begin(w);
		for (size_t i = 0; i < n_params; i++) {
			const fe_kparam *kp = &p->params[i];
			fe_jw_obj_begin(w);
			fe_jw_keyc(w, "n");
			fe_jw_i64(w, kp->n);
			fe_jw_keyc(w, "type");
			if (sr_eqc(kp->type, "ptr"))
				w_param_kind(w, sr_cstr("ptr"));
			else if (sr_eqc(kp->type, "user_str") || sr_eqc(kp->type, "user_str_array") || sr_eqc(kp->type, "user_buf"))
				w_param_kind(w, kp->type);
			else
				w_trace_int(w, kp->type);
			fe_jw_obj_end(w);
		}
		fe_jw_arr_end(w);
	}
	if (has_sha && p->binary_sha.n > 0)
		w_kv_str(w, "binary_sha256", p->binary_sha);
	if (n_args_out) {
		fe_jw_keyc(w, "args");
		if (sr_eqc(k, "fmod_ret"))
			w_fmod_args(w, p);
		else
			w_tp_args(w, p);
	}
	if (has_fields) {
		fe_jw_keyc(w, "fields");
		fe_jw_arr_begin(w);
		for (size_t i = 0; i < p->n_t_fields; i++) {
			const fe_tp_field *f = &p->t_fields[i];
			fe_jw_obj_begin(w);
			w_kv_str(w, "name", f->name);
			fe_jw_keyc(w, "offset");
			fe_jw_i64(w, f->offset);
			fe_jw_keyc(w, "type");
			if (f->n > 0) {
				fe_jw_obj_begin(w);
				w_kv_strc(w, "kind", "array");
				w_kv_str(w, "elem", f->type);
				fe_jw_keyc(w, "n");
				fe_jw_i64(w, f->n);
				fe_jw_obj_end(w);
			} else if (sr_eqc(f->type, "user_str") || sr_eqc(f->type, "user_str_array")) {
				w_param_kind(w, f->type);
			} else {
				w_trace_int(w, f->type);
			}
			fe_jw_obj_end(w);
		}
		fe_jw_arr_end(w);
	}
	fe_jw_keyc(w, "note");
	fe_jw_str(w, cat3("Ruby def ", p->name, ""));
	fe_jw_obj_end(w);
}

static void w_empty_arr(fe_jw *w, const char *k)
{
	fe_jw_keyc(w, k);
	fe_jw_arr_begin(w);
	fe_jw_arr_end(w);
}

/* Schema (schema.go) */
void fe_schema_json(sr_buf *b, const fe_result *r)
{
	fe_jw w;
	fe_jw_init(&w, b);
	fe_jw_obj_begin(&w);
	fe_jw_keyc(&w, "version");
	fe_jw_i64(&w, 1);
	fe_jw_keyc(&w, "coverage");
	fe_jw_obj_begin(&w);
	w_kv_strc(&w, "programs", "complete");
	w_kv_strc(&w, "maps", "complete");
	w_kv_strc(&w, "records", "complete");
	w_kv_strc(&w, "telemetry", "complete");
	fe_jw_obj_end(&w);

	fe_jw_keyc(&w, "core");
	fe_jw_obj_begin(&w);
	if (r->n_kernel_types > 0) {
		fe_jw_keyc(&w, "kernel_types");
		w_kernel_types(&w, r);
	}
	/* records */
	fe_jw_keyc(&w, "records");
	fe_jw_arr_begin(&w);
	size_t nrec;
	fe_record_decl **recs = fe_used_records(r, &nrec);
	for (size_t i = 0; i < nrec; i++) {
		const fe_record_decl *rd = recs[i];
		fe_jw_obj_begin(&w);
		w_kv_str(&w, "symbol", rd->const_name);
		fe_jw_keyc(&w, "id");
		fe_jw_i64(&w, (int64_t)i);
		fe_jw_keyc(&w, "size");
		fe_jw_i64(&w, rd->size);
		fe_jw_keyc(&w, "min_size");
		fe_jw_i64(&w, rd->size);
		fe_jw_keyc(&w, "alignment");
		fe_jw_i64(&w, rd->align);
		w_kv_strc(&w, "required_through", "");
		fe_jw_keyc(&w, "note");
		fe_jw_str(&w, cat3("Ruby Struct ", rd->const_name, ""));
		fe_jw_keyc(&w, "fields");
		fe_jw_arr_begin(&w);
		for (size_t j = 0; j < rd->n_fields; j++) {
			const fe_record_field *f = &rd->fields[j];
			if (f->pad)
				continue; /* padding is not in the schema (a hole record.make zeroes) */
			fe_jw_obj_begin(&w);
			w_kv_str(&w, "name", f->name);
			fe_jw_keyc(&w, "offset");
			fe_jw_i64(&w, f->offset);
			w_kv_strc(&w, "expose", "int");
			w_kv_strc(&w, "note", "");
			fe_jw_keyc(&w, "type");
			if (f->count > 0) {
				fe_jw_obj_begin(&w);
				w_kv_strc(&w, "kind", "array");
				fe_jw_keyc(&w, "count");
				fe_jw_i64(&w, f->count);
				fe_jw_keyc(&w, "element");
				w_int(&w, f->bits, f->is_signed);
				fe_jw_obj_end(&w);
			} else {
				w_int(&w, f->bits, f->is_signed);
			}
			fe_jw_obj_end(&w);
		}
		fe_jw_arr_end(&w);
		fe_jw_obj_end(&w);
	}
	fe_jw_arr_end(&w);

	/* maps: the map decls, then the rings */
	fe_jw_keyc(&w, "maps");
	fe_jw_arr_begin(&w);
	for (size_t i = 0; i < r->n_maps; i++) {
		const fe_map_decl *m = r->maps[i];
		fe_jw_obj_begin(&w);
		w_kv_str(&w, "symbol", m->name);
		w_kv_str(&w, "kind", fe_map_kind(m));
		fe_jw_keyc(&w, "key");
		if (m->key_record)
			w_record_ref(&w, m->key_record->const_name);
		else if (fe_map_is_hash(m))
			w_int(&w, m->key_bits, m->key_signed);
		else
			w_int(&w, 32, 0); /* uint32T */
		fe_jw_keyc(&w, "value");
		if (m->record)
			w_record_ref(&w, m->record->const_name);
		else
			w_int(&w, m->value_bits, m->is_signed);
		fe_jw_keyc(&w, "max_entries");
		fe_jw_u64(&w, m->max_entries);
		fe_jw_keyc(&w, "flags");
		fe_jw_i64(&w, (int64_t)fe_map_flags(m)); /* int(m.Flags()) */
		w_kv_strc(&w, "record", "");
		fe_jw_keyc(&w, "note");
		fe_jw_str(&w, cat3("Ruby constant ", m->const_name, ""));
		fe_jw_obj_end(&w);
	}
	for (size_t i = 0; i < r->n_rings; i++) {
		const fe_ring_decl *rg = r->rings[i];
		fe_jw_obj_begin(&w);
		w_kv_str(&w, "symbol", rg->name);
		w_kv_strc(&w, "kind", "ringbuf");
		fe_jw_keyc(&w, "max_entries");
		fe_jw_u64(&w, rg->size);
		fe_jw_keyc(&w, "flags");
		fe_jw_i64(&w, 0);
		w_kv_str(&w, "record", rg->record->const_name);
		fe_jw_keyc(&w, "note");
		fe_jw_str(&w, cat3("Ruby constant ", rg->const_name, ""));
		fe_jw_obj_end(&w);
	}
	fe_jw_arr_end(&w);

	fe_jw_keyc(&w, "programs");
	fe_jw_arr_begin(&w);
	for (size_t i = 0; i < r->n_programs; i++)
		w_program(&w, r, r->programs[i]);
	fe_jw_arr_end(&w);

	if (r->n_globals > 0) { /* omitempty: core.globals */
		fe_jw_keyc(&w, "globals");
		fe_jw_arr_begin(&w);
		for (size_t i = 0; i < r->n_globals; i++) {
			const fe_global_decl *g = r->globals[i];
			fe_jw_obj_begin(&w);
			w_kv_str(&w, "name", g->name);
			w_kv_str(&w, "section", g->section);
			fe_jw_keyc(&w, "type");
			w_int(&w, g->bits, g->is_signed);
			sr_buf nb = {0};
			sr_puts(&nb, "Ruby constant ");
			sr_putstr(&nb, g->const_name);
			sr_puts(&nb, " (");
			sr_putstr(&nb, g->class_name);
			sr_puts(&nb, ")");
			fe_jw_keyc(&w, "note");
			fe_jw_str(&w, sr_bufstr(&nb));
			fe_jw_obj_end(&w);
		}
		fe_jw_arr_end(&w);
	}
	fe_jw_obj_end(&w);

	fe_jw_keyc(&w, "telemetry");
	fe_jw_obj_begin(&w);
	w_empty_arr(&w, "clocks");
	w_empty_arr(&w, "value_maps");
	w_empty_arr(&w, "bounds_sets");
	w_empty_arr(&w, "signals");
	fe_jw_obj_end(&w);
	fe_jw_keyc(&w, "extensions");
	fe_jw_obj_begin(&w);
	fe_jw_obj_end(&w);
	fe_jw_obj_end(&w);
	sr_putc(b, '\n');
}

/* MapsJSON (schema.go) */
void fe_maps_json(sr_buf *b, const fe_result *r)
{
	fe_jw w;
	fe_jw_init(&w, b);
	fe_jw_obj_begin(&w);
	size_t nrec;
	fe_record_decl **recs = fe_used_records(r, &nrec);
	if (nrec > 0) {
		/* map[string]shape: keys by the raw bytes; two records with one Const keep the later (a Go map assignment) */
		sr_str *keys = sr_alloc((nrec + 1) * sizeof *keys);
		const fe_record_decl **by = sr_alloc((nrec + 1) * sizeof *by);
		size_t nk = 0;
		for (size_t i = 0; i < nrec; i++) {
			size_t j;
			for (j = 0; j < nk; j++)
				if (sr_eq(keys[j], recs[i]->const_name))
					break;
			if (j == nk)
				keys[nk++] = recs[i]->const_name;
			by[j] = recs[i];
		}
		sr_str *sorted = sr_alloc((nk + 1) * sizeof *sorted);
		memcpy(sorted, keys, nk * sizeof *keys);
		fe_json_sort_keys(sorted, nk);
		fe_jw_keyc(&w, "records");
		fe_jw_obj_begin(&w);
		for (size_t i = 0; i < nk; i++) {
			const fe_record_decl *rd = NULL;
			for (size_t j = 0; j < nk; j++)
				if (sr_eq(keys[j], sorted[i]))
					rd = by[j];
			fe_jw_key(&w, sorted[i]);
			fe_jw_obj_begin(&w);
			fe_jw_keyc(&w, "size");
			fe_jw_i64(&w, rd->size);
			fe_jw_keyc(&w, "members");
			fe_jw_arr_begin(&w);
			for (size_t j = 0; j < rd->n_fields; j++) {
				const fe_record_field *f = &rd->fields[j];
				if (f->pad)
					continue;
				fe_jw_obj_begin(&w);
				w_kv_str(&w, "name", f->name);
				fe_jw_keyc(&w, "offset");
				fe_jw_i64(&w, f->offset);
				w_kv_str(&w, "type", fe_record_field_decl_type(f));
				fe_jw_obj_end(&w);
			}
			fe_jw_arr_end(&w);
			fe_jw_obj_end(&w);
		}
		fe_jw_obj_end(&w);
	}
	fe_jw_keyc(&w, "maps");
	fe_jw_arr_begin(&w);
	for (size_t i = 0; i < r->n_maps; i++) {
		const fe_map_decl *m = r->maps[i];
		uint64_t fl = fe_map_flags(m);
		fe_jw_obj_begin(&w);
		w_kv_str(&w, "name", m->name);
		w_kv_str(&w, "kind", fe_map_kind(m));
		w_kv_str(&w, "key", fe_map_key_type_name(m));
		w_kv_str(&w, "value", fe_map_type_name(m));
		fe_jw_keyc(&w, "max_entries");
		fe_jw_u64(&w, m->max_entries);
		if (fl != 0) {
			fe_jw_keyc(&w, "flags");
			fe_jw_u64(&w, fl);
		}
		fe_jw_obj_end(&w);
	}
	for (size_t i = 0; i < r->n_rings; i++) {
		const fe_ring_decl *rg = r->rings[i];
		fe_jw_obj_begin(&w);
		w_kv_str(&w, "name", rg->name);
		w_kv_strc(&w, "kind", "ringbuf");
		w_kv_strc(&w, "key", "-");
		fe_jw_keyc(&w, "value");
		fe_jw_str(&w, cat3("record:", rg->record->const_name, ""));
		fe_jw_keyc(&w, "max_entries");
		fe_jw_u64(&w, rg->size);
		fe_jw_obj_end(&w);
	}
	fe_jw_arr_end(&w);
	if (r->n_globals > 0) {
		fe_jw_keyc(&w, "globals");
		fe_jw_arr_begin(&w);
		for (size_t i = 0; i < r->n_globals; i++) {
			const fe_global_decl *g = r->globals[i];
			fe_jw_obj_begin(&w);
			w_kv_str(&w, "name", g->name);
			w_kv_str(&w, "section", g->section);
			sr_buf tn = {0};
			sr_printf(&tn, "%c%lld", g->is_signed ? 'i' : 'u', (long long)g->bits);
			fe_jw_keyc(&w, "type");
			fe_jw_str(&w, sr_bufstr(&tn));
			fe_jw_obj_end(&w);
		}
		fe_jw_arr_end(&w);
	}
	fe_jw_obj_end(&w);
	sr_putc(b, '\n');
}

/* RecordsTable (record.go) with globalRows (globals.go) */
void fe_records_table(sr_buf *b, const fe_result *r)
{
	for (size_t i = 0; i < r->n_maps; i++) {
		const fe_map_decl *m = r->maps[i];
		if (m->key_record) {
			sr_putstr(b, m->name);
			sr_puts(b, ":key|");
			sr_putstr(b, fe_record_decl_shape(m->key_record));
			sr_putc(b, '\n');
		}
		if (m->record) {
			sr_putstr(b, m->name);
			sr_putc(b, '|');
			sr_putstr(b, fe_record_decl_shape(m->record));
			sr_putc(b, '\n');
		}
	}
	for (size_t i = 0; i < r->n_rings; i++) {
		sr_putstr(b, r->rings[i]->name);
		sr_putc(b, '|');
		sr_putstr(b, fe_record_decl_shape(r->rings[i]->record));
		sr_putc(b, '\n');
	}
	for (size_t i = 0; i < r->n_globals; i++) {
		const fe_global_decl *g = r->globals[i];
		sr_puts(b, "G|");
		sr_putstr(b, g->name);
		sr_putc(b, '|');
		sr_putstr(b, g->section);
		sr_printf(b, "|%c%lld|%d\n", g->is_signed ? 'i' : 'u', (long long)g->bits, g->optional ? 1 : 0);
	}
}
