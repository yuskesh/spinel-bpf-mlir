/* steps.c — analyze() steps 4-7 (internal/frontend/analyze.go analyze) and what they call: checkLibDefs, CompareTypes and
 * paramReads, membership, checkUserSideAPI; the MapDecl methods the core keeps; and the step 7 free functions moved to the core by
 * contract change 1 (oneReasonEach, usedGlobalsOf, widthRange, usesKernelTypes).
 *
 * Go map orders that reach the output are fixed here: checkLibDefs reports in sorted callee order (Go:
 * `range libCallees`); CompareTypes breaks its (Line, Col, Kind) ties by EndLine, EndCol (Go: sort.Slice over a map's keys); the
 * SB003 loop over Membership goes in sorted name order (Go: `range res.Membership`). */
#include "core.h"

#include <stdlib.h>
#include <string.h>

#define S(x) sr_cstr(x)
static int one_ = 1;
#define TRUE_ ((void *)&one_)

/* libCallees (analyze.go), sorted bytewise */
static const char *const lib_callees[] = {
    "ArrayMap#atomic_add", "ArrayMap#lookup", "ArrayMap#update", "CgroupSkb#check", "CgroupSkb#len", "Config#value", "Counter#add",
    "Counter#value", "DevMap#redirect", "FentryCtx#arg", "FentryCtx#kptr_or_null", "FexitCtx#ret", "FlowCtx#check", "FlowCtx#key",
    "FlowCtx#set_key", "FmodRetCtx#arg", "HashMap#add_or_init", "HashMap#delete", "HashMap#insert", "HashMap#lookup",
    "HashMap#replace", "HashMap#update", "KPtr#addr", "KPtr#copy", "KPtr#load", "KPtr#ptr", "KPtr#str", "KprobeCtx#arg",
    "KprobeCtx#read", "KretprobeCtx#ret", "KsyscallCtx#arg", "KsyscallCtx#argv_arg", "KsyscallCtx#str_arg", "LpmTrieMap#lookup",
    "LruHashMap#add_or_init", "LruHashMap#delete", "LruHashMap#insert", "LruHashMap#lookup", "LruHashMap#replace",
    "LruHashMap#update", "LruRecordHashMap#delete", "LruRecordHashMap#insert", "LruRecordHashMap#lookup",
    "LruRecordHashMap#replace", "LruRecordHashMap#update", "MapRef#atomic_add", "MapRef#load", "NfCtx#skb", "NfCtx#state",
    "OptionalConfig#value", "OutputStr#sent", "OutputStr#status", "PerCpuArrayMap#atomic_add", "PerCpuArrayMap#lookup",
    "PerCpuArrayMap#update", "PerCpuHashMap#add_or_init", "PerCpuHashMap#delete", "PerCpuHashMap#insert", "PerCpuHashMap#lookup",
    "PerCpuHashMap#replace", "PerCpuHashMap#update", "PerCpuRecordHashMap#delete", "PerCpuRecordHashMap#insert",
    "PerCpuRecordHashMap#lookup", "PerCpuRecordHashMap#replace", "PerCpuRecordHashMap#update", "PerCpuRecordMap#lookup",
    "PerCpuRecordMap#update", "RawTpCtx#arg", "RecordHashMap#delete", "RecordHashMap#insert", "RecordHashMap#lookup",
    "RecordHashMap#replace", "RecordHashMap#update", "RecordMap#lookup", "RecordMap#update", "RecordRef#atomic_add",
    "RecordRef#load", "RingBuf#output", "RingBuf#output_argv", "RingBuf#output_buf", "RingBuf#output_comm", "RingBuf#output_str",
    "RingBuf#output_str_or_discard", "SkBuff#len", "SkBuff#mark", "SkBuff#mark=", "SkLookupCtx#local_port", "SockMap#assign",
    "SocketFilterCtx#len", "TpBtfCtx#arg", "TpBtfCtx#kptr", "TpBtfCtx#kptr_or_null", "TracepointCtx#argv_field",
    "TracepointCtx#copy", "TracepointCtx#field", "TracepointCtx#str_field", "UprobeCtx#arg", "UprobeCtx#buf_arg",
    "UprobeCtx#str_arg", "UretprobeCtx#ret", "XdpMd#adjust_head", "XdpMd#adjust_tail", "XdpMd#ingress_ifindex", NULL};

/* ebpfOnlyHelpers (analyze.go) */
static const char *const ebpf_only_helpers[] = {"BPF.pid_tgid", "BPF.ktime_ns", "BPF.fmod_return", "XdpMd#check", "SkBuff#check",
						"Window#u8",	"Window#be16",	"Window#be32",	   "Window#le16", "Window#le32",
						NULL};

/* ---- MapDecl methods kept by the core (analyze.go MapDecl.MapKind, MapDecl.IsHash, MapDecl.IsArray, MapDecl.PerCPU,
 * MapDecl.ClassName, MapDecl.KeyTypeName, MapDecl.TypeName) ---- */
sr_str fe_map_kind(const fe_map_decl *m) { return m->kind.n ? m->kind : S("array"); }
int fe_map_is_hash(const fe_map_decl *m)
{
	return fe_streq(m->kind, "hash") || fe_streq(m->kind, "lru_hash") || fe_streq(m->kind, "percpu_hash");
}
int fe_map_is_array(const fe_map_decl *m) { return m->kind.n == 0 || fe_streq(m->kind, "percpu_array"); }
int fe_map_per_cpu(const fe_map_decl *m) { return m->kind.n >= 7 && memcmp(m->kind.p, "percpu_", 7) == 0; }
sr_str fe_map_class_name(const fe_map_decl *m)
{
	if (m->class_name.n)
		return m->class_name;
	return m->record ? S("RecordMap") : S("ArrayMap");
}
sr_str fe_map_key_type_name(const fe_map_decl *m)
{
	sr_buf b = {0};
	if (m->key_record) {
		sr_puts(&b, "record:");
		sr_putstr(&b, m->key_record->const_name);
	} else if (fe_map_is_array(m) || fe_streq(m->kind, "devmap") || fe_streq(m->kind, "sockmap")) {
		sr_puts(&b, "u32");
	} else {
		sr_printf(&b, "%c%lld", m->key_signed ? 'i' : 'u', (long long)m->key_bits);
	}
	return sr_bufstr(&b);
}
sr_str fe_map_type_name(const fe_map_decl *m)
{
	sr_buf b = {0};
	if (m->record) {
		sr_puts(&b, "record:");
		sr_putstr(&b, m->record->const_name);
	} else {
		sr_printf(&b, "%c%lld", m->is_signed ? 'i' : 'u', (long long)m->value_bits);
	}
	return sr_bufstr(&b);
}

/* ---- step 7's free functions ---- */

/* oneReasonEach (record.go) */
static sr_str pos_key(fe_pos p)
{
	sr_buf b = {0};
	fe_pos_string(&b, p);
	return sr_bufstr(&b);
}

fe_diags fe_one_reason_each(const fe_diags *ds)
{
#define STOP(d) ((d)->verdict == FE_REJECTED || (d)->verdict == FE_UNKNOWN)
	int has_reopen = 0, other = 0;
	fe_name_table thread_at = {0};
	for (size_t i = 0; i < ds->n; i++) {
		const fe_diag *d = &ds->v[i];
		if (STOP(d) && d->code == FE_SB016)
			has_reopen = 1;
		if (STOP(d) && d->code == FE_SB027)
			fe_name_set(&thread_at, pos_key(d->pos), TRUE_);
		if (STOP(d) && d->code != FE_SB010)
			other = 1;
	}
	fe_name_table seen = {0};
	fe_diags out = {0};
	for (size_t i = 0; i < ds->n; i++) {
		const fe_diag *d = &ds->v[i];
		if (STOP(d)) {
			sr_str pk = pos_key(d->pos);
			sr_str k = t_cat(t_cat(S(fe_code_text(d->code)), S("@")), pk);
			if (fe_name_get(&seen, k) || (d->code == FE_SB010 && other) || (d->code == FE_SB009 && has_reopen) ||
			    ((d->code == FE_SB001 || d->code == FE_SB002) && fe_name_get(&thread_at, pk)))
				continue;
			fe_name_set(&seen, k, TRUE_);
		}
		fe_diags_push(&out, *d);
	}
	return out;
#undef STOP
}

/* usedGlobalsOf (globals.go) */
fe_global_decl **fe_used_globals_of(fe_global_decl *const *order, size_t n_order, fe_program *const *progs, size_t n_progs, size_t *n_out)
{
	fe_ptr_set used = {0};
	for (size_t i = 0; i < n_progs; i++)
		for (size_t k = 0; k < progs[i]->n_globals; k++)
			fe_ptr_set_add(&used, progs[i]->globals[k]);
	fe_global_decl **out = NULL;
	*n_out = 0;
	for (size_t i = 0; i < n_order; i++)
		if (fe_ptr_set_has(&used, order[i]))
			T_PUSH(out, *n_out, order[i]);
	return out;
}

/* widthRange (globals.go) */
fe_ival fe_width_range(int64_t bits, int is_signed)
{
	if (bits >= 64)
		return is_signed ? fe_full_i64 : fe_iv(intv_from_i64(0), fe_i64_max);
	intv one = intv_from_i64(1), x;
	if (!is_signed) {
		if (bits < 0 || intv_lsh(one, (uint64_t)bits, &x) != INTV_OK) {
			fe_iv_overflow = 1;
			return fe_point(intv_from_i64(0));
		}
		return fe_iv(intv_from_i64(0), fe_iv_sub1(x, one));
	}
	if (bits < 1 || intv_lsh(one, (uint64_t)(bits - 1), &x) != INTV_OK) {
		fe_iv_overflow = 1; /* Go: Lsh by uint(-1) — a huge shift; never seen for declared widths */
		return fe_point(intv_from_i64(0));
	}
	return fe_iv(intv_neg(x), fe_iv_sub1(x, one));
}

/* usesKernelTypes (kernel.go) */
int fe_uses_kernel_types(const fe_program *p)
{
	return p && (fe_streq(p->kind, "tp_btf") || (fe_streq(p->kind, "fentry") && p->n_t_args > 0));
}

/* ---- checkLibDefs (analyze.go) ---- */
static sr_str base_name(sr_str path)
{
	size_t i = path.n;
	while (i > 0 && path.p[i - 1] == '/')
		i--;
	if (i == 0)
		return path.n ? S("/") : S(".");
	size_t end = i;
	while (i > 0 && path.p[i - 1] != '/')
		i--;
	return (sr_str){path.p + i, end - i};
}

static void check_lib_defs(fe_analysis *an)
{
	const sr_types *t = an->typing.types;
	for (size_t q = 0; lib_callees[q]; q++) {
		sr_str k = S(lib_callees[q]);
		for (size_t i = 0; i < t->n_types; i++) {
			const sr_type_rec *r = &t->types[i];
			if (!fe_streq(r->kind, "DefNode") || r->singleton)
				continue;
			if (!sr_eq(t_cat(t_cat(r->owner, S("#")), r->name), k))
				continue;
			if (!sr_eq(r->file, an->z->lib)) {
				int ok;
				sr_str msg = fe_cfmt(an->z, &ok, "`%s` is defined outside ruby/lib/bpf.rb — the eBPF side's API must be the library's", k);
				if (ok)
					fe_add(an->z, FE_REJECTED, FE_SB011, (fe_pos){base_name(r->file), r->line, r->col + 1}, msg);
			}
		}
	}
}

/* ---- CompareTypes (analyze.go) and paramReads (analyze.go) ---- */
typedef struct {
	sr_str file;
	int64_t line, col, end_line, end_col;
	sr_str kind;
} span_key;

static int str_cmp(sr_str a, sr_str b)
{
	size_t m = a.n < b.n ? a.n : b.n;
	int c = m ? memcmp(a.p, b.p, m) : 0;
	if (c)
		return c;
	return a.n < b.n ? -1 : a.n > b.n;
}

#define CMP(x, y)                                                                                                                  \
	do {                                                                                                                       \
		if ((x) != (y))                                                                                                    \
			return (x) < (y) ? -1 : 1;                                                                                 \
	} while (0)

static int key_cmp(const span_key *a, const span_key *b)
{
	int c = str_cmp(a->file, b->file);
	if (c)
		return c;
	CMP(a->line, b->line);
	CMP(a->col, b->col);
	CMP(a->end_line, b->end_line);
	CMP(a->end_col, b->end_col);
	return str_cmp(a->kind, b->kind);
}

/* Go's output order: Line, Col, Kind; C adds EndLine, EndCol and File for Go's unspecified ties */
static int out_cmp(const span_key *a, const span_key *b)
{
	CMP(a->line, b->line);
	CMP(a->col, b->col);
	int c = str_cmp(a->kind, b->kind);
	if (c)
		return c;
	CMP(a->end_line, b->end_line);
	CMP(a->end_col, b->end_col);
	return str_cmp(a->file, b->file);
}

static int key_eq(const span_key *a, const span_key *b) { return key_cmp(a, b) == 0; }

typedef struct {
	span_key k;
	int side; /* 0 plain, 1 typing */
	size_t seq;
	const sr_type_rec *r;
} ent;

static int ent_cmp(const void *x, const void *y)
{
	const ent *a = x, *b = y;
	int c = key_cmp(&a->k, &b->k);
	if (c)
		return c;
	CMP(a->side, b->side);
	CMP(a->seq, b->seq);
	return 0;
}

typedef struct {
	span_key k;
	sr_str p, t;           /* the joined lists */
	int has_p, has_t;
	const sr_type_rec *tone; /* the last typing record */
	sr_str *precs;
	size_t n_precs;
	int allowed;
} group;

static int group_out_cmp(const void *x, const void *y) { return out_cmp(&((const group *)x)->k, &((const group *)y)->k); }

static span_key key_of_rec(const sr_type_rec *r) { return (span_key){r->file, r->line, r->col, r->end_line, r->end_col, r->kind}; }
static span_key key_of_node(const sr_ast *a, const sr_node *n)
{
	return (span_key){sr_ast_file(a, n), n->line, n->col, n->end_line, n->end_col, n->type};
}

static int inside(const span_key *k, const span_key *o)
{
	if (k->line < o->line || (k->line == o->line && k->col < o->col))
		return 0;
	if (k->end_line > o->end_line || (k->end_line == o->end_line && k->end_col > o->end_col))
		return 0;
	return 1;
}

/* untypedOnly: on the joined "name|rbs|signature" strings, with Go's SplitN(r, "|", 3) */
static int untyped_only(const sr_str *recs, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		sr_str r = recs[i];
		size_t a = 0;
		while (a < r.n && r.p[a] != '|')
			a++;
		if (a == r.n)
			return 0;
		size_t b = a + 1;
		while (b < r.n && r.p[b] != '|')
			b++;
		if (b == r.n)
			return 0;
		sr_str rbs = {r.p + a + 1, b - a - 1}, rest = {r.p + b + 1, r.n - b - 1};
		if (!fe_streq(rbs, "untyped") || rest.n != 0)
			return 0;
	}
	return 1;
}

typedef struct {
	span_key *v;
	size_t n;
} keys;

static void compare_types(fe_analysis *an, const fe_name_table *roots, const keys *dependent)
{
	fe_z *z = an->z;
	const sr_types *ts[2] = {an->top->plain.types, an->typing.types};
	ent *es = NULL;
	size_t ne = 0;
	for (int side = 0; side < 2; side++)
		for (size_t i = 0; i < ts[side]->n_types; i++) {
			const sr_type_rec *r = &ts[side]->types[i];
			if (!sr_eq(r->file, z->base) || r->end_line > z->user_lines)
				continue;
			T_PUSH(es, ne, ((ent){key_of_rec(r), side, i, r}));
		}
	if (ne)
		qsort(es, ne, sizeof *es, ent_cmp);
	group *gs = NULL;
	size_t ng = 0;
	for (size_t i = 0; i < ne;) {
		size_t j = i;
		while (j < ne && key_eq(&es[j].k, &es[i].k))
			j++;
		group g;
		memset(&g, 0, sizeof g);
		g.k = es[i].k;
		sr_buf pb = {0}, tb = {0};
		for (size_t q = i; q < j; q++) {
			const sr_type_rec *r = es[q].r;
			sr_buf one = {0};
			sr_putstr(&one, r->name);
			sr_putc(&one, '|');
			sr_putstr(&one, r->rbs);
			sr_putc(&one, '|');
			sr_putstr(&one, r->signature);
			sr_str s = sr_bufstr(&one);
			sr_buf *b = es[q].side ? &tb : &pb;
			int *has = es[q].side ? &g.has_t : &g.has_p;
			if (*has)
				sr_putc(b, ';');
			sr_putstr(b, s);
			*has = 1;
			if (es[q].side)
				g.tone = r;
			else
				T_PUSH(g.precs, g.n_precs, s);
		}
		g.p = sr_bufstr(&pb);
		g.t = sr_bufstr(&tb);
		T_PUSH(gs, ng, g);
		i = j;
	}
	/* allowed: the root defs' spans and the RequiredParameterNodes inside them */
	for (size_t i = 0; i < ng; i++) {
		const sr_type_rec *r = gs[i].tone;
		if (r && fe_streq(r->kind, "DefNode") && fe_name_get(roots, r->name) && fe_streq(r->owner, "Object"))
			gs[i].allowed = 1;
	}
	for (size_t i = 0; i < ng; i++) {
		const sr_type_rec *r = gs[i].tone;
		if (!r || !fe_streq(r->kind, "RequiredParameterNode"))
			continue;
		for (size_t q = 0; q < ng && !gs[i].allowed; q++)
			if (gs[q].allowed && fe_streq(gs[q].k.kind, "DefNode") && inside(&gs[i].k, &gs[q].k))
				gs[i].allowed = 1;
	}
	if (ng) {
		/* stable insertion order is not needed: out_cmp is total on distinct keys */
		qsort(gs, ng, sizeof *gs, group_out_cmp);
	}
	for (size_t i = 0; i < ng; i++) {
		group *g = &gs[i];
		if (sr_eq(g->p, g->t) || g->allowed)
			continue;
		int additive = 0;
		for (size_t q = 0; q < dependent->n && !additive; q++)
			additive = key_eq(&dependent->v[q], &g->k);
		if (additive && untyped_only(g->precs, g->n_precs))
			continue;
		if (additive && fe_streq(g->k.kind, "DefNode"))
			continue;
		int ok;
		sr_str msg = fe_cfmt(z, &ok,
				     "the typing probe changed Spinel's inference of this %s (without: %q, with: %q) — the eBPF side's types must not depend on the injected call",
				     g->k.kind, g->p, g->t);
		if (!ok)
			return;
		fe_add(z, FE_REJECTED, FE_SB010, (fe_pos){z->base, g->k.line, g->k.col + 1}, msg);
	}
}

typedef struct {
	const fe_name_table *tainted;
	int found;
} reads_walk;

static int reads_walk_fn(void *u, const sr_node *y)
{
	reads_walk *w = u;
	if (t_is(y, "LocalVariableReadNode") && fe_name_get(w->tainted, t_str(y, "name")))
		w->found = 1;
	return !w->found;
}

static int reads_tainted(const sr_ast *a, const sr_node *x, const fe_name_table *tainted)
{
	reads_walk w = {tainted, 0};
	if (x)
		t_walk(a, x, reads_walk_fn, &w);
	return w.found;
}

typedef struct {
	const sr_ast *a;
	fe_name_table *tainted;
	int changed;
} taint_walk;

static int taint_walk_fn(void *u, const sr_node *x)
{
	taint_walk *w = u;
	const sr_ast *a = w->a;
	sr_str nm = t_str(x, "name");
	if ((t_is(x, "LocalVariableWriteNode") || t_is(x, "LocalVariableOperatorWriteNode")) && !fe_name_get(w->tainted, nm) &&
	    reads_tainted(a, t_ref(a, x, "value"), w->tainted)) {
		fe_name_set(w->tainted, nm, TRUE_);
		w->changed = 1;
	}
	if (t_is(x, "MultiWriteNode") && reads_tainted(a, t_ref(a, x, "value"), w->tainted)) {
		t_nodes ls = t_arr(a, x, "lefts");
		for (size_t i = 0; i < ls.n; i++)
			if (t_is(ls.v[i], "LocalVariableTargetNode") && !fe_name_get(w->tainted, t_str(ls.v[i], "name"))) {
				fe_name_set(w->tainted, t_str(ls.v[i], "name"), TRUE_);
				w->changed = 1;
			}
	}
	return 1;
}

typedef struct {
	const sr_ast *a;
	const sr_node *n;
	const fe_name_table *tainted, *defs, *is_root;
	fe_name_table *tp; /* name -> sr_imap* */
	sr_str **work;
	size_t *n_work;
	keys *out;
} collect_walk;

static int collect_walk_fn(void *u, const sr_node *x)
{
	collect_walk *w = u;
	const sr_ast *a = w->a;
	if (x != w->n && reads_tainted(a, x, w->tainted))
		T_PUSH(w->out->v, w->out->n, key_of_node(a, x));
	sr_str nm = t_str(x, "name");
	if (t_is(x, "CallNode") && !t_ref(a, x, "receiver") && fe_name_get(w->defs, nm) && !fe_name_get(w->is_root, nm)) {
		t_nodes as = t_args(a, x);
		for (size_t i = 0; i < as.n; i++) {
			if (!reads_tainted(a, as.v[i], w->tainted))
				continue;
			sr_imap *m = fe_name_get(w->tp, nm);
			if (!m) {
				m = sr_alloc(sizeof *m);
				memset(m, 0, sizeof *m);
				fe_name_set(w->tp, nm, m);
			}
			if (!sr_imap_get(m, (int64_t)i)) {
				int created;
				*sr_imap_slot(m, (int64_t)i, &created) = TRUE_;
				T_PUSH(*w->work, *w->n_work, nm);
			}
		}
	}
	return 1;
}

static keys param_reads(fe_analysis *an)
{
	const sr_ast *a = an->typing.ast;
	int64_t fid = t_user_file_id(a, an->z->base);
	fe_name_table is_root = {0}, defs = {0}, tp = {0}, done = {0};
	for (size_t i = 0; i < an->top->n_roots; i++)
		fe_name_set(&is_root, an->top->roots[i].name, TRUE_);
	t_nodes top = t_top_statements(a, fid);
	for (size_t i = 0; i < top.n; i++)
		if (t_is(top.v[i], "DefNode") && !t_ref(a, top.v[i], "receiver"))
			fe_name_set(&defs, t_str(top.v[i], "name"), (void *)top.v[i]);
	sr_str *work = NULL;
	size_t n_work = 0, head = 0;
	for (size_t i = 0; i < an->top->n_roots; i++) {
		sr_str rn = an->top->roots[i].name;
		const sr_node *n = fe_name_get(&defs, rn);
		if (!n)
			continue;
		const sr_node *pn = t_ref(a, n, "parameters");
		if (pn && t_arr(a, pn, "requireds").n == 1) {
			sr_imap *m = sr_alloc(sizeof *m);
			memset(m, 0, sizeof *m);
			int created;
			*sr_imap_slot(m, 0, &created) = TRUE_;
			fe_name_set(&tp, rn, m);
			T_PUSH(work, n_work, rn);
		}
	}
	keys out = {0};
	while (head < n_work) {
		sr_str name = work[head++];
		const sr_node *n = fe_name_get(&defs, name);
		const sr_node *pn = t_ref(a, n, "parameters");
		t_nodes ps = t_arr(a, pn, "requireds");
		fe_name_table tainted = {0};
		sr_imap *ti = fe_name_get(&tp, name);
		int64_t *tk = ti ? sr_imap_sorted_keys(ti) : NULL;
		for (size_t q = 0; ti && q < ti->n; q++)
			if (tk[q] >= 0 && (size_t)tk[q] < ps.n)
				fe_name_set(&tainted, t_str(ps.v[tk[q]], "name"), TRUE_);
		for (int changed = 1; changed;) {
			taint_walk tw = {a, &tainted, 0};
			t_walk(a, n, taint_walk_fn, &tw);
			changed = tw.changed;
		}
		if (!fe_name_get(&is_root, name) && !fe_name_get(&done, name)) {
			T_PUSH(out.v, out.n, key_of_node(a, n));
			for (size_t q = 0; ti && q < ti->n; q++)
				if (tk[q] >= 0 && (size_t)tk[q] < ps.n)
					T_PUSH(out.v, out.n, key_of_node(a, ps.v[tk[q]]));
		}
		fe_name_set(&done, name, TRUE_);
		collect_walk cw = {a, n, &tainted, &defs, &is_root, &tp, &work, &n_work, &out};
		t_walk(a, n, collect_walk_fn, &cw);
	}
	return out;
}

/* ---- membership (analyze.go) ---- */
typedef struct {
	fe_analysis *an;
	const sr_ast *a;
	const sr_node *n;
	const fe_name_table *defs;
	fe_edge *out;
	size_t n_out;
} callees_walk;

static int callees_walk_fn(void *u, const sr_node *c)
{
	callees_walk *w = u;
	if (t_is(c, "DefNode") && c != w->n)
		return 0;
	if (!t_is(c, "CallNode") || c->line > w->an->z->user_lines)
		return 1;
	size_t cnt;
	long i = sr_codegen_of(w->an->typing.types, w->a, c, &cnt);
	if (i < 0)
		return 1;
	const sr_codegen_rec *cg = &w->an->typing.types->codegen[i];
	if (cg->callee.n == 0)
		return 1;
	if (fe_name_has(w->defs, cg->callee))
		T_PUSH(w->out, w->n_out, ((fe_edge){(sr_str){0}, cg->callee, fe_pos_of(w->an->z, w->a, c), cg->dispatch}));
	return 1;
}

typedef struct {
	fe_analysis *an;
	const sr_ast *a;
	const fe_name_table *defs;
	fe_name_table mem; /* name -> (intptr_t) bits: 1 user, 2 bpf */
	fe_edge *edges;
	size_t n_edges;
} mem_state;

static void callees_of(mem_state *m, const sr_node *n, fe_edge **out, size_t *n_out)
{
	callees_walk w = {m->an, m->a, n, m->defs, NULL, 0};
	if (n)
		t_walk(m->a, n, callees_walk_fn, &w);
	*out = w.out;
	*n_out = w.n_out;
}

static void visit(mem_state *m, sr_str name, int dom)
{
	intptr_t bits = (intptr_t)fe_name_get(&m->mem, name);
	if (!fe_name_has(&m->mem, name))
		fe_name_set(&m->mem, name, (void *)0);
	if (bits & dom)
		return;
	fe_name_set(&m->mem, name, (void *)(bits | dom));
	fe_edge *es;
	size_t ne;
	callees_of(m, fe_name_get(m->defs, name), &es, &ne);
	for (size_t i = 0; i < ne; i++) {
		es[i].from = name;
		T_PUSH(m->edges, m->n_edges, es[i]);
		visit(m, es[i].to, dom);
	}
}

static void membership(fe_analysis *an, const sr_ast *a, int64_t fid, const fe_name_table *defs, fe_result *res)
{
	mem_state m;
	memset(&m, 0, sizeof m);
	m.an = an;
	m.a = a;
	m.defs = defs;
	for (size_t i = 0; i < an->top->n_roots; i++)
		visit(&m, an->top->roots[i].name, 2);
	t_nodes top = t_top_statements(a, fid);
	for (size_t i = 0; i < top.n; i++) {
		const sr_node *n = top.v[i];
		if (t_is(n, "DefNode") || n->line > an->z->user_lines)
			continue;
		fe_edge *es;
		size_t ne;
		callees_of(&m, n, &es, &ne);
		for (size_t q = 0; q < ne; q++) {
			es[q].from = S("<top>");
			T_PUSH(m.edges, m.n_edges, es[q]);
			visit(&m, es[q].to, 1);
		}
	}
	memset(&res->membership, 0, sizeof res->membership);
	res->membership_nil = 0;
	for (size_t i = 0; i < m.mem.n; i++) {
		if (m.mem.e[i].removed)
			continue;
		intptr_t bits = (intptr_t)m.mem.e[i].val;
		fe_str_list *l = sr_alloc(sizeof *l);
		memset(l, 0, sizeof *l);
		if (bits & 1)
			T_PUSH(l->v, l->n, S("user"));
		if (bits & 2)
			T_PUSH(l->v, l->n, S("bpf"));
		fe_name_set(&res->membership, m.mem.e[i].key, l);
	}
	/* sort.Slice by (Line, Col): insertion sort keeps equal edges in order, as Go's sort does for the small slices seen */
	for (size_t i = 1; i < m.n_edges; i++)
		for (size_t j = i; j > 0; j--) {
			fe_edge *x = &m.edges[j], *y = &m.edges[j - 1];
			if (y->pos.line < x->pos.line || (y->pos.line == x->pos.line && y->pos.col <= x->pos.col))
				break;
			fe_edge t = *x;
			*x = *y;
			*y = t;
		}
	/* beyond 12 elements Go's pdqsort is not stable: fail closed only when two different edges share a position */
	for (size_t i = 1; m.n_edges > 12 && i < m.n_edges; i++) {
		const fe_edge *x = &m.edges[i - 1], *y = &m.edges[i];
		if (x->pos.line == y->pos.line && x->pos.col == y->pos.col &&
		    (!sr_eq(x->from, y->from) || !sr_eq(x->to, y->to) || !sr_eq(x->dispatch, y->dispatch) || !sr_eq(x->pos.file, y->pos.file))) {
			fe_not_ported(an->z, "edges that tie on (Line, Col) in a slice over 12 (Go's sort.Slice order is not stable there)");
			break;
		}
	}
	res->edges = m.edges;
	res->n_edges = m.n_edges;
	res->edges_nil = m.n_edges == 0;
}

/* ---- checkUserSideAPI (analyze.go) ---- */
typedef struct {
	fe_analysis *an;
	const sr_ast *a;
} api_walk;

static int api_walk_fn(void *u, const sr_node *c)
{
	api_walk *w = u;
	if (!t_is(c, "CallNode"))
		return 1;
	size_t cnt;
	long i = sr_codegen_of(w->an->typing.types, w->a, c, &cnt);
	if (i < 0)
		return 1;
	sr_str callee = w->an->typing.types->codegen[i].callee;
	if (t_in(callee, lib_callees) || t_in(callee, ebpf_only_helpers)) {
		int ok;
		sr_str msg = fe_cfmt(w->an->z, &ok, "`%s` is eBPF-side only — user space reads maps through the loaded object (SpinelBPF)", callee);
		if (ok)
			fe_add(w->an->z, FE_REJECTED, FE_SB003, fe_pos_of(w->an->z, w->a, c), msg);
	}
	return 1;
}

static void check_user_side_api(fe_analysis *an, const sr_ast *a, int64_t fid, const fe_name_table *defs)
{
	fe_ptr_set bpf = {0};
	for (size_t i = 0; i < an->top->n_roots; i++) {
		const sr_node *d = fe_name_get(defs, an->top->roots[i].name);
		if (d)
			fe_ptr_set_add(&bpf, d);
	}
	for (size_t i = 0; i < an->funcs.n; i++) {
		fe_func_info *fi = an->funcs.e[i].val;
		if (!an->funcs.e[i].removed && fi && fi->path)
			fe_ptr_set_add(&bpf, fi->def);
	}
	t_nodes top = t_top_statements(a, fid);
	for (size_t i = 0; i < top.n; i++) {
		const sr_node *n = top.v[i];
		if (fe_ptr_set_has(&bpf, n) || n->line > an->z->user_lines)
			continue;
		api_walk w = {an, a};
		t_walk(a, n, api_walk_fn, &w);
	}
}

/* ---- steps 4-7 ---- */
void fe_steps_4_to_7(fe_analysis *an, fe_result *res)
{
	fe_z *z = an->z;
	fe_top *t = an->top;
	const sr_ast *ta = an->typing.ast, *a = an->top->plain.ast;
	int64_t tfid = t_user_file_id(ta, z->base);

	/* 4 */
	check_lib_defs(an);

	/* 5 */
	fe_name_table defs = {0};
	t_nodes top = t_top_statements(ta, tfid);
	for (size_t i = 0; i < top.n; i++)
		if (t_is(top.v[i], "DefNode") && !t_ref(a, top.v[i], "receiver")) /* Go reads the receiver in the plain AST */
			fe_name_set(&defs, t_str(top.v[i], "name"), (void *)top.v[i]);
	fe_scan_subprograms(an, ta, &defs);
	size_t n_order;
	fe_func_info **order = fe_call_graph(an, ta, &defs, &n_order);
	for (size_t i = 0; i < t->n_roots; i++) {
		const sr_node *d = fe_name_get(&defs, t->roots[i].name);
		if (!d)
			continue;
		fe_program *p = fe_program_of(an, ta, d, &t->roots[i]);
		if (p) {
			T_PUSH(res->programs, res->n_programs, p);
			res->programs_nil = 0;
		}
	}
	for (size_t i = 0; i < n_order; i++) {
		fe_func_info *fi = order[i];
		if (fi->bad || !fi->called)
			continue;
		fe_program *fp = fe_function(an, ta, fi);
		if (fp)
			fi->prog = fp;
	}
	for (size_t i = 0; i < n_order; i++)
		if (order[i]->prog) {
			T_PUSH(res->funcs, res->n_funcs, order[i]->prog);
			res->funcs_nil = 0;
		}
	/* sort by declaration order (unique keys) */
	for (size_t i = 1; i < res->n_funcs; i++)
		for (size_t j = i; j > 0; j--) {
			fe_func_info *x = fe_name_get(&an->funcs, res->funcs[j]->name), *y = fe_name_get(&an->funcs, res->funcs[j - 1]->name);
			if (y->decl <= x->decl)
				break;
			fe_program *tmp = res->funcs[j];
			res->funcs[j] = res->funcs[j - 1];
			res->funcs[j - 1] = tmp;
		}
	fe_resolve_subprograms(an, order, n_order, res->programs, res->n_programs);

	/* 6 */
	fe_name_table root_set = {0};
	for (size_t i = 0; i < t->n_roots; i++)
		fe_name_set(&root_set, t->roots[i].name, TRUE_);
	keys dep = param_reads(an);
	compare_types(an, &root_set, &dep);

	/* 7 */
	membership(an, ta, tfid, &defs, res);
	size_t nk;
	sr_str *names = fe_sorted_set(&res->membership, &nk); /* Go ranges over the map: C goes in sorted name order */
	for (size_t i = 0; i < nk; i++) {
		const fe_str_list *l = fe_name_get(&res->membership, names[i]);
		if (l->n != 2)
			continue;
		const sr_node *dn = fe_name_get(&defs, names[i]);
		sr_str *path = sr_alloc(2 * sizeof *path);
		path[0] = S("user");
		path[1] = names[i];
		int ok;
		sr_str msg = fe_cfmt(z, &ok,
				     "function `%s` is reached from both the user-space side and the eBPF side ({User, BPF}) — the eBPF side's functions must not be called from Ruby",
				     names[i]);
		if (!ok)
			return;
		fe_diags_push(&z->diags, (fe_diag){FE_REJECTED, FE_SB003, fe_pos_of(z, ta, dn), path, 2, msg});
	}
	check_user_side_api(an, ta, tfid, &defs);
	fe_flush_thread_refs(z, t, &res->membership, &defs);

	/* the used maps */
	size_t n_all = res->n_programs + res->n_funcs;
	fe_program **all = sr_alloc((n_all + 1) * sizeof *all);
	for (size_t i = 0; i < res->n_programs; i++)
		all[i] = res->programs[i];
	for (size_t i = 0; i < res->n_funcs; i++)
		all[res->n_programs + i] = res->funcs[i];
	res->maps = t->map_order;
	res->n_maps = t->n_map_order;
	res->maps_nil = t->map_order_nil;
	if (res->n_programs > 0) {
		fe_ptr_set used = {0};
		for (size_t i = 0; i < n_all; i++)
			for (size_t k = 0; k < all[i]->n_maps; k++)
				fe_ptr_set_add(&used, all[i]->maps[k]);
		res->maps = NULL;
		res->n_maps = 0;
		res->maps_nil = 1;
		for (size_t i = 0; i < t->n_map_order; i++) {
			fe_map_decl *m = t->map_order[i];
			if (fe_ptr_set_has(&used, m)) {
				T_PUSH(res->maps, res->n_maps, m);
				res->maps_nil = 0;
				continue;
			}
			int ok;
			sr_str msg = fe_cfmt(z, &ok,
					     "map %s is declared but no eBPF program uses it — it is left out of the ELF, the schema and maps.json (user space cannot read it)",
					     m->name);
			if (ok)
				fe_add(z, FE_CONDITIONAL, FE_SB013, m->pos, msg);
		}
	}
	/* the used globals */
	size_t ng;
	res->globals = fe_used_globals_of(t->global_order, t->n_global_order, all, n_all, &ng);
	res->n_globals = ng;
	res->globals_nil = ng == 0;
	if (res->n_programs > 0) {
		fe_ptr_set used = {0};
		for (size_t i = 0; i < ng; i++)
			fe_ptr_set_add(&used, res->globals[i]);
		for (size_t i = 0; i < t->n_global_order; i++) {
			fe_global_decl *g = t->global_order[i];
			if (fe_ptr_set_has(&used, g))
				continue;
			int ok;
			sr_str msg = fe_cfmt(z, &ok,
					     "global %s is declared but no eBPF program reads or adds it — it is left out of the ELF, the schema and maps.json",
					     g->name);
			if (ok)
				fe_add(z, FE_CONDITIONAL, FE_SB013, g->pos, msg);
		}
	}
	/* the kernel types */
	for (size_t i = 0; i < res->n_programs; i++)
		if (fe_uses_kernel_types(res->programs[i]) || fe_streq(res->programs[i]->kind, "netfilter")) {
			res->kernel_types = t->kt_order;
			res->n_kernel_types = t->n_kt_order;
			res->kernel_types_nil = t->kt_order_nil;
			break;
		}
	/* the used rings */
	fe_ptr_set used_ring = {0};
	for (size_t i = 0; i < n_all; i++)
		for (size_t k = 0; k < all[i]->n_rings; k++)
			fe_ptr_set_add(&used_ring, all[i]->rings[k]);
	for (size_t i = 0; i < t->n_ring_order; i++) {
		fe_ring_decl *r = t->ring_order[i];
		if (fe_ptr_set_has(&used_ring, r)) {
			T_PUSH(res->rings, res->n_rings, r);
			res->rings_nil = 0;
		} else if (res->n_programs > 0) {
			int ok;
			sr_str msg = fe_cfmt(z, &ok,
					     "ring buffer %s is declared but no eBPF program outputs to it — it is left out of the ELF, the schema and maps.json",
					     r->name);
			if (ok)
				fe_add(z, FE_CONDITIONAL, FE_SB013, r->pos, msg);
		}
	}
	res->diags = fe_one_reason_each(&z->diags);
	if (fe_diags_blocking(&res->diags)) {
		res->programs = NULL;
		res->n_programs = 0;
		res->programs_nil = 1;
	}
}
