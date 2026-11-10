/* topdecl_record.c — internal/frontend/record.go: structOf, recordDecl, padHint, recordMapDecl, checkMemberDefs, inRootOrSample,
 * memberNames, sampleArgs. */
#include "top_int.h"

#include <string.h>

static sr_str node_name(const sr_node *n) { return t_str(n, "name"); }

int t_struct_of(t_ctx *c, const sr_node *n, t_struct_info **out)
{
	const sr_ast *a = c->a;
	const sr_node *v = t_ref(a, n, "value");
	if (!v || !t_is(v, "CallNode"))
		return 0;
	sr_str recv = t_const_name(a, t_ref(a, v, "receiver"));
	t_struct_info *s = sr_alloc(sizeof *s);
	if (sr_eqc(recv, "Struct") && sr_eqc(node_name(v), "new")) {
	} else if (sr_eqc(recv, "Data") && sr_eqc(node_name(v), "define")) {
		s->pos = t_pos(c, n);
		s->bad = t_s("Data.define has no member setters — a record is a Struct");
		*out = s;
		return 1;
	} else {
		return 0;
	}
	s->pos = t_pos(c, n);
	if (t_ref(a, v, "block")) {
		s->bad = t_s("a record Struct takes no block");
		*out = s;
		return 1;
	}
	t_nodes as = t_args(a, v);
	for (size_t i = 0; i < as.n; i++) {
		if (!t_is(as.v[i], "SymbolNode")) {
			s->bad = t_s("a record Struct takes Symbol literals only — no keyword_init, no string name");
			*out = s;
			return 1;
		}
		T_PUSH(s->names, s->n_names, t_str(as.v[i], "value"));
	}
	if (s->n_names == 0)
		s->bad = t_s("a record Struct needs at least one member");
	*out = s;
	return 1;
}

/* padHint */
static sr_str pad_hint(int64_t off, int64_t gap, int64_t first)
{
	sr_buf b = {0};
	int any = 0;
	while (gap > 0) {
		int64_t w = 4;
		while (w > 1 && (off % w != 0 || w > gap))
			w /= 2;
		if (any)
			sr_puts(&b, ", ");
		sr_printf(&b, "`_pad%lld: :u%lld`", (long long)first, (long long)(w * 8));
		any = 1;
		first++;
		off += w;
		gap -= w;
	}
	return sr_bufstr(&b);
}

static int64_t field_size(const fe_record_field *f) { return f->count > 0 ? f->bits / 8 * f->count : f->bits / 8; }

void t_record_decl(t_ctx *c, const sr_node *n, const t_structs *structs)
{
	const sr_ast *a = c->a;
	fe_z *z = c->z;
	fe_pos p = t_pos(c, n);
	t_nodes as = t_args(a, n);
	if (as.n != 2 || !t_is(as.v[0], "ConstantReadNode") || !t_is(as.v[1], "KeywordHashNode")) {
		t_add(z, FE_REJECTED, FE_SB024, p,
		      "a record is declared as `BPF.record(S, member: :u16, …)` with S a Struct constant and every member's type");
		return;
	}
	sr_str cn = node_name(as.v[0]);
	t_struct_info *s = t_structs_get(structs, cn);
	fe_name_set(&c->t->bad_recs, cn, (void *)1);
	if (!s) {
		t_add(z, FE_REJECTED, FE_SB024, t_pos(c, as.v[0]), "%s is not a top-level `%s = Struct.new(:m, …)`", cn, cn);
		return;
	}
	if (s->bad.n > 0) {
		t_add(z, FE_REJECTED, FE_SB024, s->pos, "%s: %s", cn, s->bad);
		return;
	}
	if (fe_name_has(&c->t->records, cn)) {
		t_add(z, FE_REJECTED, FE_SB024, p, "record %s is declared twice", cn);
		return;
	}
	fe_record_decl *r = sr_alloc(sizeof *r);
	*r = (fe_record_decl){.const_name = cn, .fields_nil = 1, .pos = p, .struct_pos = s->pos};
	sr_str *got = NULL;
	size_t n_got = 0;
	t_nodes els = t_arr(a, as.v[1], "elements");
	for (size_t i = 0; i < els.n; i++) {
		const sr_node *e = els.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		int64_t count = 0;
		if (t_is(e, "AssocNode") && k && t_is(k, "SymbolNode") && v && t_is(v, "ArrayNode")) {
			t_nodes ae = t_arr(a, v, "elements");
			sr_str kv = t_str(k, "value");
			if (ae.n != 2 || !t_is(ae.v[0], "SymbolNode") || !t_is(ae.v[1], "IntegerNode")) {
				t_add(z, FE_REJECTED, FE_SB024, t_pos(c, v),
				      "member %s: an array member is `%s: [:u32, N]` — the element type and a literal length", kv, kv);
				return;
			}
			bigint nb = {0};
			int ok = t_literal(z, a, ae.v[1], &nb);
			int64_t len = 0;
			int fits = ok && t_big_int64(&nb, &len);
			bigint_free(&nb);
			if (!fits || len < 1 || len > 64) {
				t_add(z, FE_REJECTED, FE_SB024, t_pos(c, ae.v[1]),
				      "member %s: the array length must be a literal 1..64 (bpf-mlir's record arrays)", kv);
				return;
			}
			if (t_pad_name(kv)) {
				t_add(z, FE_REJECTED, FE_SB024, t_pos(c, e),
				      "padding member %s cannot be an array — declare `_pad<N>` members as integers", kv);
				return;
			}
			count = len;
			v = ae.v[0];
		}
		if (!t_is(e, "AssocNode") || !k || !v || !t_is(k, "SymbolNode") || !t_is(v, "SymbolNode")) {
			t_add(z, FE_REJECTED, FE_SB024, t_pos(c, e),
			      "each member is `name: :type` (or `name: [:type, N]` for an array) with Symbol literals");
			return;
		}
		int64_t bits;
		int sg;
		if (!t_record_type(t_str(v, "value"), &bits, &sg)) {
			t_add(z, FE_REJECTED, FE_SB024, t_pos(c, v), "member %s: the type must be :u8 … :u64 or :i8 … :i64, got :%s",
			      t_str(k, "value"), t_str(v, "value"));
			return;
		}
		sr_str kv = t_str(k, "value");
		T_PUSH(got, n_got, kv);
		T_PUSH(r->fields, r->n_fields, ((fe_record_field){kv, bits, sg, t_pad_name(kv), 0, count}));
		r->fields_nil = 0;
	}
	sr_str gj = t_join(got, n_got, ","), sj = t_join(s->names, s->n_names, ",");
	if (!sr_eq(gj, sj)) {
		t_add(z, FE_REJECTED, FE_SB024, p,
		      "the members of BPF.record(%s, …) (%s) must be the Struct's members in the same order (%s)", cn,
		      t_join(got, n_got, ", "), t_join(s->names, s->n_names, ", "));
		return;
	}
	int64_t off = 0, max_align = 1, pad = 0;
	for (size_t i = 0; i < r->n_fields; i++) {
		fe_record_field *f = &r->fields[i];
		int64_t sz = f->bits / 8;
		if (off % sz != 0) {
			int64_t gap = sz - off % sz;
			t_add(z, FE_REJECTED, FE_SB024, p,
			      "record %s has %d implicit padding byte(s) before member %s (offset %d, alignment %d) — declare them before "
			      "%s: %s",
			      cn, gap, f->name, off, sz, f->name, pad_hint(off, gap, pad));
			return;
		}
		f->offset = off;
		off += field_size(f);
		if (sz > max_align)
			max_align = sz;
		if (f->pad)
			pad++;
	}
	if (off % max_align != 0) {
		int64_t gap = max_align - off % max_align;
		t_add(z, FE_REJECTED, FE_SB024, p,
		      "record %s has %d implicit trailing padding byte(s) (size %d, alignment %d) — declare them at the end: %s", cn, gap,
		      off, max_align, pad_hint(off, gap, pad));
		return;
	}
	int64_t named = 0;
	for (size_t i = 0; i < r->n_fields; i++)
		named += !r->fields[i].pad;
	if (named == 0) {
		t_add(z, FE_REJECTED, FE_SB024, p, "record %s has no named member", cn);
		return;
	}
	r->size = off;
	r->align = max_align;
	fe_name_delete(&c->t->bad_recs, cn);
	fe_name_set(&c->t->records, cn, r);
}

static sr_str member_names(const fe_record_decl *r)
{
	sr_str *ns = NULL;
	size_t n = 0;
	for (size_t i = 0; i < r->n_fields; i++)
		T_PUSH(ns, n, r->fields[i].name);
	return t_join(ns, n, ", ");
}

int t_sample_args(t_ctx *c, t_nodes sas, const fe_record_decl *r, const char *zero_msg, const char *where)
{
	const sr_ast *a = c->a;
	fe_z *z = c->z;
	for (size_t i = 0; i < sas.n; i++) {
		const sr_node *x = sas.v[i];
		const fe_record_field *f = &r->fields[i];
		if (f->count > 0) {
			if (where[0] != '\0' && !(!strcmp(where, "a ring buffer event") && f->bits == 8 && !f->is_signed)) {
				t_add(z, FE_REJECTED, FE_SB024, t_pos(c, x),
				      "record %s has the array member %s — %S takes records without array members (array members are for "
				      "record map values)",
				      r->const_name, f->name, where);
				return 0;
			}
			t_nodes as = t_args(a, x);
			if (!t_is(x, "CallNode") || !sr_eqc(node_name(x), "new") ||
			    !sr_eqc(t_const_name(a, t_ref(a, x, "receiver")), "Array") || as.n != 2 || !t_is(as.v[0], "IntegerNode") ||
			    !t_is(as.v[1], "IntegerNode")) {
				t_add(z, FE_REJECTED, FE_SB024, t_pos(c, x), "the sample of the array member %s is `Array.new(%d, 0)`", f->name,
				      f->count);
				return 0;
			}
			bigint nb = {0}, zero = {0};
			int ok1 = t_literal(z, a, as.v[0], &nb);
			int ok2 = t_literal(z, a, as.v[1], &zero);
			if (!ok1 || !ok2 || t_big_sign(&zero) != 0) {
				t_add(z, FE_REJECTED, FE_SB024, t_pos(c, x), "the sample of the array member %s is `Array.new(%d, 0)`", f->name,
				      f->count);
				bigint_free(&nb);
				bigint_free(&zero);
				return 0;
			}
			int64_t nv = 0;
			if (!t_big_int64(&nb, &nv) || nv != f->count) {
				t_add(z, FE_REJECTED, FE_SB024, t_pos(c, as.v[0]),
				      "the sample of the array member %s has %B elements, but BPF.record declares %d — they must be the same",
				      f->name, &nb, f->count);
				bigint_free(&nb);
				bigint_free(&zero);
				return 0;
			}
			bigint_free(&nb);
			bigint_free(&zero);
			continue;
		}
		int ok = t_is(x, "IntegerNode"), sign = 1;
		if (ok) {
			bigint lit = {0};
			ok = t_literal(z, a, x, &lit);
			sign = ok ? t_big_sign(&lit) : 0;
			bigint_free(&lit);
		}
		if (!ok || sign != 0) {
			t_add(z, FE_REJECTED, FE_SB024, t_pos(c, x), "%S", zero_msg);
			return 0;
		}
	}
	return 1;
}

void t_record_map_decl(t_ctx *c, const sr_node *n)
{
	const sr_ast *a = c->a;
	fe_z *z = c->z;
	fe_top *t = c->t;
	const sr_node *v = t_ref(a, n, "value");
	sr_str cn = node_name(n);
	fe_pos p = t_pos(c, n);
	fe_name_set(&t->bad_maps, cn, (void *)1);
	if (fe_name_has(&t->maps, cn)) {
		t_add(z, FE_REJECTED, FE_SB013, p, "constant %s is assigned twice", cn);
		return;
	}
	t_nodes as = t_args(a, v);
	if (as.n == 3 && t_is(as.v[1], "CallNode") && fe_name_has(&t->bad_recs, t_const_name(a, t_ref(a, as.v[1], "receiver"))))
		return;
	if (as.n != 3 || !t_is(as.v[0], "StringNode") || !t_is(as.v[1], "CallNode") || !t_is(as.v[2], "IntegerNode")) {
		t_add(z, FE_REJECTED, FE_SB013, p,
		      "a record map is declared as `%s = BPF::RecordMap.new(\"%s\", S.new(0, …), max_entries)` with literal arguments", cn,
		      cn);
		return;
	}
	sr_str name = t_str(as.v[0], "content");
	if (!sr_eq(name, cn)) {
		t_add(z, FE_REJECTED, FE_SB013, t_pos(c, as.v[0]),
		      "the map name %q differs from its constant %s — both sides look the map up by this name, so they must be the same",
		      name, cn);
		return;
	}
	for (size_t i = 0; i < t->n_map_order; i++)
		if (sr_eq(t->map_order[i]->name, name)) {
			t_add(z, FE_REJECTED, FE_SB013, p, "two map declarations use the name %q", name);
			return;
		}
	const sr_node *sample = as.v[1];
	sr_str sc = t_const_name(a, t_ref(a, sample, "receiver"));
	fe_record_decl *r = fe_name_get(&t->records, sc);
	if (!sr_eqc(node_name(sample), "new") || !r) {
		t_add(z, FE_REJECTED, FE_SB024, t_pos(c, sample),
		      "the sample must be `S.new(0, …)` of a record S declared with BPF.record");
		return;
	}
	t_nodes sas = t_args(a, sample);
	if (sas.n != r->n_fields) {
		t_add(z, FE_REJECTED, FE_SB024, t_pos(c, sample),
		      "the sample must give all %d members of %s explicitly (an omitted member is nil, which Spinel types as Integer — "
		      "upstream_suspects S5)",
		      (int64_t)r->n_fields, sc);
		return;
	}
	if (!t_sample_args(c, sas, r,
			   "the sample's members must be the literal 0 — it is a sample of the type, not an initial value (array entries "
			   "start as 0 in the kernel)",
			   ""))
		return;
	bigint ent = {0};
	if (!t_literal(z, a, as.v[2], &ent))
		return;
	uint64_t eu = 0;
	if (t_big_sign(&ent) <= 0 || !t_big_uint64(&ent, &eu) || eu > 0xffffffffULL) {
		t_add(z, FE_REJECTED, FE_SB013, t_pos(c, as.v[2]), "max_entries must be a positive integer below 2^32, got %B", &ent);
		bigint_free(&ent);
		return;
	}
	bigint_free(&ent);
	if (t_reserved_prefix(name)) {
		t_add(z, FE_REJECTED, FE_SB007, p, "map name %q uses the reserved prefix spinelbpf_", name);
		return;
	}
	fe_name_delete(&t->bad_maps, cn);
	fe_map_decl *m = sr_alloc(sizeof *m);
	*m = (fe_map_decl){.const_name = cn, .name = name, .record = r, .max_entries = eu, .pos = p};
	if (sr_eqc(t_const_name(a, t_ref(a, v, "receiver")), "BPF::PerCpuRecordMap")) {
		m->kind = t_s("percpu_array");
		m->class_name = t_s("PerCpuRecordMap");
	}
	fe_name_set(&t->maps, cn, m);
	T_PUSH(t->map_order, t->n_map_order, m);
	t->map_order_nil = 0;
}

/* ---- checkMemberDefs ---- */
typedef struct {
	sr_str name;
	sr_str owner;   /* the first owner met */
	int n_owners;   /* distinct owning records */
} member_owner;

typedef struct {
	t_ctx *c;
	member_owner *names;
	size_t n_names;
	fe_name_table is_root;
} member_w;

static const member_owner *owner_of(const member_w *w, sr_str name)
{
	for (size_t i = 0; i < w->n_names; i++)
		if (sr_eq(w->names[i].name, name))
			return &w->names[i];
	return NULL;
}

static void add_owner(member_w *w, sr_str name, sr_str owner)
{
	for (size_t i = 0; i < w->n_names; i++)
		if (sr_eq(w->names[i].name, name)) {
			if (!sr_eq(w->names[i].owner, owner))
				w->names[i].n_owners++;
			return;
		}
	T_PUSH(w->names, w->n_names, ((member_owner){name, owner, 1}));
}

/* names[...] ranges over z.records (a Go map): with two records sharing a member name the owner in the message depends on Go's map
 * order. The C makes that a named not-ported stop instead of a guess. */
static int owner_ok(member_w *w, const member_owner *o)
{
	if (o->n_owners > 1) {
		fe_not_ported(w->c->z, "SB011 names one of several records that own member %.*s — Go picks by map order", (int)o->name.n,
			      o->name.p);
		return 0;
	}
	return 1;
}

static int in_root_or_sample(const sr_ast *a, const sr_node *n, const fe_name_table *is_root)
{
	const int64_t *pp = sr_imap_get(&a->parent, n->id);
	while (pp) {
		const sr_node *x = t_node(a, *pp);
		if (!x)
			return 0;
		if (t_is(x, "DefNode") && fe_name_has(is_root, node_name(x)))
			return 1;
		if (t_is(x, "CallNode") && sr_eqc(node_name(x), "new") &&
		    sr_eqc(t_const_name(a, t_ref(a, x, "receiver")), "BPF::RecordMap"))
			return 1;
		pp = sr_imap_get(&a->parent, *pp);
	}
	return 0;
}

static int member_f(void *ctx, const sr_node *n)
{
	member_w *w = ctx;
	t_ctx *c = w->c;
	const sr_ast *a = c->a;
	fe_z *z = c->z;
	if (!sr_eq(sr_ast_file(a, n), z->base))
		return 1;
	if (t_is(n, "DefNode")) {
		const member_owner *o = owner_of(w, node_name(n));
		if (o && owner_ok(w, o))
			t_add(z, FE_REJECTED, FE_SB011, t_pos(c, n),
			      "`def %s` shares a name with a member of record %s — the eBPF side reads members by the declaration, so a user "
			      "method of that name is refused",
			      node_name(n), o->owner);
	} else if (t_is(n, "CallNode")) {
		if (sr_eqc(node_name(n), "new")) {
			sr_str rcn = t_const_name(a, t_ref(a, n, "receiver"));
			if (fe_name_has(&c->t->records, rcn)) {
				const fe_record_decl *rc = fe_name_get(&c->t->records, rcn);
				t_nodes as = t_args(a, n);
				int splat = 0;
				for (size_t i = 0; i < as.n; i++)
					splat |= t_is(as.v[i], "SplatNode");
				if (!splat && as.n != rc->n_fields && !in_root_or_sample(a, n, &w->is_root))
					t_add(z, FE_REJECTED, FE_SB024, t_pos(c, n),
					      "`%s.new` takes all %d members of record %s in the declaration order (%s), got %d — e.g. "
					      "`%s.new(v[0], …, v[%d])` for `v = obj.map_get(M, k)`",
					      rc->const_name, (int64_t)rc->n_fields, rc->const_name, member_names(rc), (int64_t)as.n,
					      rc->const_name, (int64_t)rc->n_fields - 1);
				for (size_t i = 0; i < as.n; i++)
					if (t_is(as.v[i], "SplatNode"))
						t_add(z, FE_REJECTED, FE_SB024, t_pos(c, n),
						      "`%s.new(*…)` — a splat makes Spinel type every member of record %s as untyped "
						      "program-wide (the eBPF side then refuses); pass the members explicitly, e.g. "
						      "`%s.new(v[0], v[1], …)`",
						      rcn, rcn, rcn);
			}
		}
		sr_str nm = node_name(n);
		if (sr_eqc(nm, "attr_accessor") || sr_eqc(nm, "attr_reader") || sr_eqc(nm, "attr_writer") ||
		    sr_eqc(nm, "alias_method")) {
			t_nodes as = t_args(a, n);
			for (size_t i = 0; i < as.n; i++)
				if (t_is(as.v[i], "SymbolNode")) {
					const member_owner *o = owner_of(w, t_str(as.v[i], "value"));
					if (o && owner_ok(w, o))
						t_add(z, FE_REJECTED, FE_SB011, t_pos(c, n), "`%s :%s` shares a name with a member of record %s",
						      nm, t_str(as.v[i], "value"), o->owner);
				}
		}
	} else if (t_is(n, "ClassNode")) {
		sr_str cp = t_const_name(a, t_ref(a, n, "constant_path"));
		if (fe_name_has(&c->t->records, cp))
			t_add(z, FE_REJECTED, FE_SB011, t_pos(c, n), "record %s is reopened — its members must stay the Struct's accessors",
			      cp);
	}
	return 1;
}

void t_check_member_defs(t_ctx *c, int64_t fid, const fe_root_decl *roots, size_t n_roots)
{
	(void)fid;
	member_w w = {.c = c};
	for (size_t i = 0; i < n_roots; i++)
		fe_name_set(&w.is_root, roots[i].name, (void *)1);
	const fe_name_table *rs = &c->t->records;
	for (size_t i = 0; i < rs->n; i++) {
		if (rs->e[i].removed)
			continue;
		const fe_record_decl *r = rs->e[i].val;
		for (size_t j = 0; j < r->n_fields; j++) {
			add_owner(&w, r->fields[j].name, r->const_name);
			add_owner(&w, t_cat(r->fields[j].name, t_s("=")), r->const_name);
		}
	}
	if (w.n_names == 0)
		return;
	t_walk(c->a, t_root(c->a), member_f, &w);
}
