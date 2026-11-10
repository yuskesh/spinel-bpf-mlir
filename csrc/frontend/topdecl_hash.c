/* topdecl_hash.c — ring.go ringDecl, hash.go sampleRecord / hashMapDecl / hashClasses, globals.go globalDecl / checkGlobalNames. */
#include "top_int.h"

#include <string.h>

static sr_str node_name(const sr_node *n) { return t_str(n, "name"); }

static int max_entries(t_ctx *c, const sr_node *x, uint64_t *out)
{
	bigint ent = {0};
	if (!t_literal(c->z, c->a, x, &ent))
		return 0;
	uint64_t eu = 0;
	if (t_big_sign(&ent) <= 0 || !t_big_uint64(&ent, &eu) || eu > 0xffffffffULL) {
		t_add(c->z, FE_REJECTED, FE_SB013, t_pos(c, x), "max_entries must be a positive integer below 2^32, got %B", &ent);
		bigint_free(&ent);
		return 0;
	}
	bigint_free(&ent);
	*out = eu;
	return 1;
}

/* ---- ring.go ringDecl ---- */
void t_ring_decl(t_ctx *c, const sr_node *n)
{
	const sr_ast *a = c->a;
	fe_z *z = c->z;
	fe_top *t = c->t;
	const sr_node *v = t_ref(a, n, "value");
	sr_str cn = node_name(n);
	fe_pos p = t_pos(c, n);
	fe_name_set(&t->bad_rings, cn, (void *)1);
	if (fe_name_has(&t->maps, cn) || fe_name_get(&t->rings, cn)) {
		t_add(z, FE_REJECTED, FE_SB013, p, "constant %s is assigned twice", cn);
		return;
	}
	t_nodes as = t_args(a, v);
	if (as.n == 3 && t_is(as.v[1], "CallNode") && fe_name_has(&t->bad_recs, t_const_name(a, t_ref(a, as.v[1], "receiver"))))
		return;
	if (as.n == 3 && t_is(as.v[0], "StringNode") && t_is(as.v[2], "IntegerNode") && !t_is(as.v[1], "CallNode")) {
		t_add(z, FE_REJECTED, FE_SB024, t_pos(c, as.v[1]),
		      "the sample must be `S.new(0, …)` of a record S declared with BPF.record");
		return;
	}
	if (as.n != 3 || !t_is(as.v[0], "StringNode") || !t_is(as.v[1], "CallNode") || !t_is(as.v[2], "IntegerNode")) {
		t_add(z, FE_REJECTED, FE_SB013, p,
		      "a ring buffer is declared as `%s = BPF::RingBuf.new(\"%s\", S.new(0, …), size)` with literal arguments", cn, cn);
		return;
	}
	sr_str name = t_str(as.v[0], "content");
	if (!sr_eq(name, cn)) {
		t_add(z, FE_REJECTED, FE_SB013, t_pos(c, as.v[0]), "the ring buffer name %q differs from its constant %s", name, cn);
		return;
	}
	for (size_t i = 0; i < t->n_map_order; i++)
		if (sr_eq(t->map_order[i]->name, name)) {
			t_add(z, FE_REJECTED, FE_SB013, p, "a map and a ring buffer use the name %q", name);
			return;
		}
	for (size_t i = 0; i < t->n_ring_order; i++)
		if (sr_eq(t->ring_order[i]->name, name)) {
			t_add(z, FE_REJECTED, FE_SB013, p, "two ring buffer declarations use the name %q", name);
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
		      "the sample must give all %d members of %s explicitly (upstream_suspects S5)", (int64_t)r->n_fields, sc);
		return;
	}
	if (!t_sample_args(c, sas, r, "the sample's members must be the literal 0 — it is a sample of the type", "a ring buffer event"))
		return;
	bigint size = {0};
	if (!t_literal(z, a, as.v[2], &size))
		return;
	uint64_t su = 0;
	if (!t_big_uint64(&size, &su) || su < 4096 || su > (uint64_t)1 << 31 || (su & (su - 1)) != 0) {
		t_add(z, FE_REJECTED, FE_SB013, t_pos(c, as.v[2]),
		      "the ring buffer size must be a power of two of at least 4096 bytes (the x86_64 page) and at most 2^31, got %B",
		      &size);
		bigint_free(&size);
		return;
	}
	bigint_free(&size);
	if (t_reserved_prefix(name)) {
		t_add(z, FE_REJECTED, FE_SB007, p, "ring buffer name %q uses the reserved prefix spinelbpf_", name);
		return;
	}
	fe_name_delete(&t->bad_rings, cn);
	fe_ring_decl *d = sr_alloc(sizeof *d);
	*d = (fe_ring_decl){cn, name, r, su, p};
	fe_name_set(&t->rings, cn, d);
	T_PUSH(t->ring_order, t->n_ring_order, d);
	t->ring_order_nil = 0;
}

/* ---- hash.go ---- */
static const struct {
	const char *recv, *kind;
	int record;
	const char *cls, *counterpart;
} hash_classes[] = {
    {"BPF::HashMap", "hash", 0, "HashMap", "RecordHashMap"},
    {"BPF::LruHashMap", "lru_hash", 0, "LruHashMap", "LruRecordHashMap"},
    {"BPF::RecordHashMap", "hash", 1, "RecordHashMap", "HashMap"},
    {"BPF::LruRecordHashMap", "lru_hash", 1, "LruRecordHashMap", "LruHashMap"},
    {"BPF::PerCpuHashMap", "percpu_hash", 0, "PerCpuHashMap", "PerCpuRecordHashMap"},
    {"BPF::PerCpuRecordHashMap", "percpu_hash", 1, "PerCpuRecordHashMap", "PerCpuHashMap"},
};

int t_hash_class(sr_str recv, const char **kind, int *record, const char **class_name)
{
	for (size_t i = 0; i < sizeof hash_classes / sizeof hash_classes[0]; i++)
		if (sr_eqc(recv, hash_classes[i].recv)) {
			*kind = hash_classes[i].kind;
			*record = hash_classes[i].record;
			*class_name = hash_classes[i].cls;
			return 1;
		}
	return 0;
}

static const char *counterpart(const char *cls)
{
	for (size_t i = 0; i < sizeof hash_classes / sizeof hash_classes[0]; i++)
		if (!strcmp(cls, hash_classes[i].cls))
			return hash_classes[i].counterpart;
	return "";
}

static fe_record_decl *sample_record(t_ctx *c, const sr_node *x)
{
	const sr_ast *a = c->a;
	sr_str sc = t_const_name(a, t_ref(a, x, "receiver"));
	fe_record_decl *r = fe_name_get(&c->t->records, sc);
	if (!sr_eqc(node_name(x), "new") || !r) {
		t_add(c->z, FE_REJECTED, FE_SB024, t_pos(c, x),
		      "the sample must be `S.new(0, …)` of a record S declared with BPF.record");
		return NULL;
	}
	t_nodes sas = t_args(a, x);
	if (sas.n != r->n_fields) {
		t_add(c->z, FE_REJECTED, FE_SB024, t_pos(c, x),
		      "the sample must give all %d members of %s explicitly (upstream_suspects S5)", (int64_t)r->n_fields, sc);
		return NULL;
	}
	if (!t_sample_args(c, sas, r, "the sample's members must be the literal 0 — it is a sample of the type, not an initial value",
			   "a hash map (key or value)"))
		return NULL;
	return r;
}

void t_hash_map_decl(t_ctx *c, const sr_node *n, const char *kind, int record, const char *cls)
{
	const sr_ast *a = c->a;
	fe_z *z = c->z;
	fe_top *t = c->t;
	const sr_node *v = t_ref(a, n, "value");
	sr_str cn = node_name(n);
	fe_pos p = t_pos(c, n);
	fe_name_set(&t->bad_maps, cn, (void *)1);
	fe_name_set(&t->bad_hash, cn, (void *)1);
	if (fe_name_has(&t->maps, cn)) {
		t_add(z, FE_REJECTED, FE_SB013, p, "constant %s is assigned twice", cn);
		return;
	}
	t_nodes as = t_args(a, v);
	for (size_t i = 0; i < as.n; i++)
		if (t_is(as.v[i], "CallNode") && fe_name_has(&t->bad_recs, t_const_name(a, t_ref(a, as.v[i], "receiver"))))
			return;
	sr_buf sb = {0};
	sr_puts(&sb, "`");
	sr_putstr(&sb, cn);
	sr_puts(&sb, " = BPF::");
	sr_puts(&sb, cls);
	sr_puts(&sb, ".new(\"");
	sr_putstr(&sb, cn);
	sr_puts(&sb, "\", key, value, max_entries)` with literal arguments — key is :u32 / :u64 / :i32 / :i64 or a record sample "
		     "`S.new(0, …)`");
	sr_puts(&sb, record ? ", value is a record sample `S.new(0, …)`" : ", value is :u32 / :u64 / :i32 / :i64");
	sr_str shape = sr_bufstr(&sb);
	if (as.n != 4 || !t_is(as.v[0], "StringNode") || !t_is(as.v[3], "IntegerNode")) {
		t_add(z, FE_REJECTED, FE_SB013, p, "a hash map is declared as %s", shape);
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
	fe_map_decl *m = sr_alloc(sizeof *m);
	*m = (fe_map_decl){.const_name = cn, .name = name, .kind = t_s(kind), .class_name = t_s(cls), .pos = p};
	const sr_node *k = as.v[1];
	if (t_is(k, "SymbolNode")) {
		int64_t b;
		int s;
		if (!t_int_type(t_str(k, "value"), &b, &s)) {
			t_add(z, FE_REJECTED, FE_SB013, t_pos(c, k),
			      "the key type must be :u32, :u64, :i32 or :i64 (8- and 16-bit keys are not accepted), got :%s", t_str(k, "value"));
			return;
		}
		m->key_bits = b;
		m->key_signed = s;
	} else if (t_is(k, "CallNode")) {
		if (!(m->key_record = sample_record(c, k)))
			return;
	} else {
		t_add(z, FE_REJECTED, FE_SB013, t_pos(c, k), "a hash map is declared as %s", shape);
		return;
	}
	const sr_node *x = as.v[2];
	if (record && t_is(x, "CallNode")) {
		if (!(m->record = sample_record(c, x)))
			return;
	} else if (!record && t_is(x, "SymbolNode")) {
		int64_t b;
		int s;
		if (!t_int_type(t_str(x, "value"), &b, &s)) {
			t_add(z, FE_REJECTED, FE_SB013, t_pos(c, x),
			      "the value type must be :u32, :u64, :i32 or :i64 (8- and 16-bit values are not accepted), got :%s",
			      t_str(x, "value"));
			return;
		}
		m->value_bits = b;
		m->is_signed = s;
	} else if (record) {
		t_add(z, FE_REJECTED, FE_SB013, t_pos(c, x),
		      "BPF::%S takes a record sample `S.new(0, …)` as its value — integer values use BPF::%S", cls, counterpart(cls));
		return;
	} else {
		t_add(z, FE_REJECTED, FE_SB013, t_pos(c, x), "BPF::%S takes an integer type as its value — record values use BPF::%S", cls,
		      counterpart(cls));
		return;
	}
	uint64_t eu;
	if (!max_entries(c, as.v[3], &eu))
		return;
	if (t_reserved_prefix(name)) {
		t_add(z, FE_REJECTED, FE_SB007, p, "map name %q uses the reserved prefix spinelbpf_", name);
		return;
	}
	fe_name_delete(&t->bad_maps, cn);
	fe_name_delete(&t->bad_hash, cn);
	m->max_entries = eu;
	fe_name_set(&t->maps, cn, m);
	T_PUSH(t->map_order, t->n_map_order, m);
	t->map_order_nil = 0;
}

/* ---- globals.go ---- */
int t_global_decl(t_ctx *c, const sr_node *n)
{
	const sr_ast *a = c->a;
	fe_z *z = c->z;
	fe_top *t = c->t;
	const sr_node *v = t_ref(a, n, "value");
	if (!v || !t_is(v, "CallNode") || !sr_eqc(node_name(v), "new"))
		return 0;
	sr_str rc = t_const_name(a, t_ref(a, v, "receiver"));
	const char *cls;
	if (sr_eqc(rc, "BPF::Config"))
		cls = "Config";
	else if (sr_eqc(rc, "BPF::OptionalConfig"))
		cls = "OptionalConfig";
	else if (sr_eqc(rc, "BPF::Counter"))
		cls = "Counter";
	else if (sr_eqc(rc, "BPF::Global"))
		cls = "Global";
	else if (sr_eqc(rc, "BPF::ExitInfo"))
		cls = "ExitInfo";
	else
		return 0;
	int counter = !strcmp(cls, "Counter"), bss = counter || !strcmp(cls, "Global");
	sr_str cn = node_name(n);
	fe_pos p = t_pos(c, n);
	fe_name_set(&t->bad_globals, cn, (void *)1);
	if (fe_name_has(&t->globals, cn)) {
		t_add(z, FE_REJECTED, FE_SB029, p, "constant %s is assigned twice", cn);
		return 1;
	}
	t_nodes as = t_args(a, v);
	if (!strcmp(cls, "ExitInfo")) { /* the .data user_exit_info record (no type argument) */
		if (as.n != 1 || !t_is(as.v[0], "StringNode")) {
			t_add(z, FE_REJECTED, FE_SB029, p, "an exit info is declared as `%s = BPF::ExitInfo.new(\"%s\")` with a String literal", cn, cn);
			return 1;
		}
		sr_str en = t_str(as.v[0], "content");
		if (!sr_eq(en, cn)) {
			t_add(z, FE_REJECTED, FE_SB029, t_pos(c, as.v[0]),
			      "the global name %q differs from its constant %s — both sides look the global up by this name", en, cn);
			return 1;
		}
		if (t_reserved_prefix(cn)) {
			t_add(z, FE_REJECTED, FE_SB007, p, "global name %q uses the reserved prefix spinelbpf_", cn);
			return 1;
		}
		fe_name_delete(&t->bad_globals, cn);
		fe_global_decl *g = sr_alloc(sizeof *g);
		*g = (fe_global_decl){cn, cn, t_s(cls), t_s("data"), 0, 0, 0, p};
		fe_name_set(&t->globals, cn, g);
		T_PUSH(t->global_order, t->n_global_order, g);
		t->global_order_nil = 0;
		return 1;
	}
	if (as.n != 2 || !t_is(as.v[0], "StringNode") || !t_is(as.v[1], "SymbolNode")) {
		t_add(z, FE_REJECTED, FE_SB029, p,
		      "a global is declared as `%s = BPF::%S.new(\"%s\", :u16)` with a String and a Symbol literal", cn, cls, cn);
		return 1;
	}
	sr_str name = t_str(as.v[0], "content");
	if (!sr_eq(name, cn)) {
		t_add(z, FE_REJECTED, FE_SB029, t_pos(c, as.v[0]),
		      "the global name %q differs from its constant %s — both sides look the global up by this name", name, cn);
		return 1;
	}
	sr_str ty = t_str(as.v[1], "value");
	int64_t bits;
	int sg;
	if (!t_record_type(ty, &bits, &sg)) {
		t_add(z, FE_REJECTED, FE_SB029, t_pos(c, as.v[1]), "the global's type must be one of :u8 … :u64 / :i8 … :i64, got :%s", ty);
		return 1;
	}
	if (counter && bits != 32 && bits != 64) {
		t_add(z, FE_REJECTED, FE_SB029, t_pos(c, as.v[1]),
		      "a Counter is :u32, :u64, :i32 or :i64 (the widths of ebpf.global.atomic_add), got :%s", ty);
		return 1;
	}
	if (t_reserved_prefix(name)) {
		t_add(z, FE_REJECTED, FE_SB007, p, "global name %q uses the reserved prefix spinelbpf_", name);
		return 1;
	}
	fe_name_delete(&t->bad_globals, cn);
	fe_global_decl *g = sr_alloc(sizeof *g);
	*g = (fe_global_decl){cn, name, t_s(cls), t_s(bss ? "bss" : "rodata"), bits, sg, !strcmp(cls, "OptionalConfig"), p};
	fe_name_set(&t->globals, cn, g);
	T_PUSH(t->global_order, t->n_global_order, g);
	t->global_order_nil = 0;
	return 1;
}

void t_check_global_names(t_ctx *c, const fe_root_decl *roots, size_t n_roots)
{
	fe_top *t = c->t;
	fe_name_table taken = {0}; /* the value is the const char * kind; the last assignment wins, as Go's map */
	for (size_t i = 0; i < t->n_map_order; i++)
		fe_name_set(&taken, t->map_order[i]->name, (void *)"map");
	for (size_t i = 0; i < t->n_ring_order; i++)
		fe_name_set(&taken, t->ring_order[i]->name, (void *)"ring buffer");
	for (size_t i = 0; i < n_roots; i++)
		fe_name_set(&taken, roots[i].name, (void *)"program");
	for (size_t i = 0; i < t->n_global_order; i++) {
		const fe_global_decl *g = t->global_order[i];
		const char *what = fe_name_get(&taken, g->name);
		if (what)
			t_add(c->z, FE_REJECTED, FE_SB029, g->pos,
			      "global %s has the same name as a %S — globals, maps and programs share the ELF symbol names", g->name, what);
	}
}
