/* topdecl_kernel.c — internal/frontend/kernel.go: kernelTypeDecl, kernelTypesResolve, embedCycle, kernelHandleDecl, embedSample,
 * tpBtfDecl, structArgsDecl. (Go's ptrs map is written but never read — `_ = ptrs` — so it has no C counterpart.) */
#include "top_int.h"

#include <string.h>

static sr_str node_name(const sr_node *n) { return t_str(n, "name"); }

#define KBAD(pos, ...) t_add(c->z, FE_REJECTED, FE_SB033, (pos), __VA_ARGS__)

void t_kernel_type_decl(t_ctx *c, const sr_node *n, const t_structs *structs)
{
	const sr_ast *a = c->a;
	fe_top *t = c->t;
	fe_pos p = t_pos(c, n);
	t_nodes as = t_args(a, n);
	if (as.n != 3 || !t_is(as.v[0], "ConstantReadNode") || !t_is(as.v[1], "StringNode") || t_str(as.v[1], "content").n == 0 ||
	    !t_is(as.v[2], "KeywordHashNode")) {
		KBAD(p, "a kernel struct is declared as `BPF.kernel_type(S, \"kernel_name\", member: :i32, …)` — a Struct constant, the "
			"kernel struct's name and the members read");
		return;
	}
	sr_str cn = node_name(as.v[0]);
	t_struct_info *s = t_structs_get(structs, cn);
	if (!s) {
		KBAD(t_pos(c, as.v[0]), "%s is not a top-level `%s = Struct.new(:m, …)`", cn, cn);
		return;
	}
	if (s->bad.n > 0) {
		KBAD(s->pos, "%s: %s", cn, s->bad);
		return;
	}
	if (fe_name_get(&t->records, cn)) {
		KBAD(p, "%s is a record (BPF.record) — a kernel struct is its own Struct", cn);
		return;
	}
	if (fe_name_get(&t->kts, cn)) {
		KBAD(p, "kernel struct %s is declared twice", cn);
		return;
	}
	fe_kernel_type_decl *d = sr_alloc(sizeof *d);
	*d = (fe_kernel_type_decl){.const_name = cn, .name = t_str(as.v[1], "content"), .fields_nil = 1, .pos = p, .struct_pos = s->pos,
				   .handle_poss_nil = 1};
	sr_str *got = NULL;
	size_t n_got = 0;
	t_nodes els = t_arr(a, as.v[2], "elements");
	for (size_t i = 0; i < els.n; i++) {
		const sr_node *e = els.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !t_is(k, "SymbolNode") || !v) {
			KBAD(t_pos(c, e), "each member is `name: :i32`, `name: [:kptr, S]` or `name: [:u8, N]`");
			return;
		}
		sr_str name = t_str(k, "value");
		if (!t_lower_ident(name) || t_in(name, t_ruby_keywords)) {
			KBAD(t_pos(c, k),
			     "member %s: the kernel member's name must be a lowercase Ruby identifier that is not a keyword (it becomes the "
			     "Struct's accessor) — read another field, or ask bpf-mlir for an alias",
			     name);
			return;
		}
		fe_kernel_field f = {.name = name};
		if (t_is(v, "SymbolNode")) {
			sr_str vv = t_str(v, "value");
			if (sr_eqc(vv, "strptr")) {
				f.kind = t_s("strptr");
				f.bits = 64;
			} else {
				int64_t b;
				int sg;
				if (!t_record_type(vv, &b, &sg)) {
					KBAD(t_pos(c, v),
					     "member %s: the type must be :i8 … :i64 / :u8 … :u64, `[:kptr, S]` or `[:u8, N]`, got :%s", name, vv);
					return;
				}
				f.kind = t_s("int");
				f.bits = b;
				f.is_signed = sg;
			}
		} else if (t_is(v, "ArrayNode")) {
			t_nodes ae = t_arr(a, v, "elements");
			if (ae.n != 2 || !t_is(ae.v[0], "SymbolNode")) {
				KBAD(t_pos(c, v), "member %s: `[:kptr, S]` or `[:u8, N]`", name);
				return;
			}
			sr_str e0 = t_str(ae.v[0], "value");
			if (sr_eqc(e0, "kptr") && t_is(ae.v[1], "ConstantReadNode")) {
				f.kind = t_s("kptr");
				f.ptr = node_name(ae.v[1]);
				f.bits = 64;
			} else if (sr_eqc(e0, "struct") && t_is(ae.v[1], "ConstantReadNode")) {
				f.kind = t_s("struct");
				f.ptr = node_name(ae.v[1]);
			} else if ((sr_eqc(e0, "u8") || sr_eqc(e0, "i8")) && t_is(ae.v[1], "IntegerNode")) {
				bigint nb = {0};
				int ok = t_literal(c->z, a, ae.v[1], &nb);
				int64_t len = 0;
				int fits = ok && t_big_int64(&nb, &len);
				bigint_free(&nb);
				if (!fits || len < 1 || len > 64) {
					KBAD(t_pos(c, ae.v[1]),
					     "member %s: the array length must be a literal 1..64 (bpf-mlir's kernel byte arrays — kfield.copy)",
					     name);
					return;
				}
				f.kind = t_s("array");
				f.bits = 8;
				f.is_signed = sr_eqc(e0, "i8");
				f.count = len;
			} else {
				KBAD(t_pos(c, v),
				     "member %s: `[:kptr, S]` (S a kernel struct), `[:struct, S]` (an embedded kernel struct) or `[:u8, N]` / "
				     "`[:i8, N]`",
				     name);
				return;
			}
		} else {
			KBAD(t_pos(c, v), "member %s: the type is a Symbol literal or `[:kptr, S]` / `[:u8, N]`", name);
			return;
		}
		T_PUSH(got, n_got, name);
		T_PUSH(d->fields, d->n_fields, f);
		d->fields_nil = 0;
	}
	if (d->n_fields == 0) {
		KBAD(p, "kernel struct %s reads no member", cn);
		return;
	}
	if (!sr_eq(t_join(got, n_got, ","), t_join(s->names, s->n_names, ","))) {
		KBAD(p, "the members of BPF.kernel_type(%s, …) (%s) must be the Struct's members in the same order (%s)", cn,
		     t_join(got, n_got, ", "), t_join(s->names, s->n_names, ", "));
		return;
	}
	fe_name_set(&t->kts, cn, d);
	T_PUSH(t->kt_order, t->n_kt_order, d);
	t->kt_order_nil = 0;
}

/* embedCycle: seen is shared down one path and cleared on the way back (Go's defer delete) */
typedef struct {
	t_ctx *c;
	sr_str start;
	fe_name_table seen;
} cyc;

static sr_str cyc_walk(cyc *w, sr_str cur, const sr_str *path, size_t n_path)
{
	const fe_kernel_type_decl *d = fe_name_get(&w->c->t->kts, cur);
	if (!d || fe_name_has(&w->seen, cur))
		return t_s("");
	fe_name_set(&w->seen, cur, (void *)1);
	sr_str res = t_s("");
	for (size_t i = 0; i < d->n_fields && res.n == 0; i++) {
		const fe_kernel_field *f = &d->fields[i];
		if (!sr_eqc(f->kind, "struct"))
			continue;
		sr_str *next = sr_alloc((n_path + 1) * sizeof *next);
		memcpy(next, path, n_path * sizeof *next);
		next[n_path] = f->ptr;
		if (sr_eq(f->ptr, w->start)) {
			res = t_join(next, n_path + 1, " -> ");
			break;
		}
		res = cyc_walk(w, f->ptr, next, n_path + 1);
	}
	fe_name_delete(&w->seen, cur);
	return res;
}

static sr_str embed_cycle(t_ctx *c, sr_str cn)
{
	cyc w = {.c = c, .start = cn};
	return cyc_walk(&w, cn, &cn, 1);
}

void t_kernel_types_resolve(t_ctx *c)
{
	fe_top *t = c->t;
	size_t n = t->n_kt_order;
	fe_kernel_type_decl **order = sr_alloc((n + 1) * sizeof *order);
	if (n > 0) /* kt_order is NULL when there are no kernel types; memcpy's pointers must not be NULL even for 0 bytes */
		memcpy(order, t->kt_order, n * sizeof *order);
	for (size_t i = 0; i < n; i++) {
		fe_kernel_type_decl *d = order[i];
		for (size_t j = 0; j < d->n_fields; j++) {
			const fe_kernel_field *f = &d->fields[j];
			if (!sr_eqc(f->kind, "kptr") && !sr_eqc(f->kind, "struct"))
				continue;
			if (!fe_name_get(&t->kts, f->ptr)) {
				if (sr_eqc(f->kind, "struct"))
					KBAD(d->pos, "member %s of %s embeds %s, which is not declared with BPF.kernel_type", f->name,
					     d->const_name, f->ptr);
				else
					KBAD(d->pos, "member %s of %s points to %s, which is not declared with BPF.kernel_type", f->name,
					     d->const_name, f->ptr);
				fe_name_delete(&t->kts, d->const_name);
			}
		}
	}
	for (size_t i = 0; i < n; i++) {
		fe_kernel_type_decl *d = order[i];
		if (!fe_name_get(&t->kts, d->const_name))
			continue;
		sr_str cy = embed_cycle(c, d->const_name);
		if (cy.n > 0) {
			KBAD(d->pos,
			     "kernel struct %s embeds itself by value (%s) — an embedded struct ([:struct, S]) cannot contain its container; "
			     "use [:kptr, S] for a pointer",
			     d->const_name, cy);
			fe_name_delete(&t->kts, d->const_name);
		}
	}
	fe_kernel_type_decl **keep = NULL;
	size_t n_keep = 0;
	for (size_t i = 0; i < n; i++)
		if (fe_name_get(&t->kts, order[i]->const_name))
			T_PUSH(keep, n_keep, order[i]);
	t->kt_order = keep;
	t->n_kt_order = n_keep;
	t->kt_order_nil = keep == NULL; /* Go: `var keep []*KernelTypeDecl` stays nil when nothing is kept */
}

static int array_sample(t_ctx *c, const sr_node *x, const fe_kernel_field *f)
{
	const sr_ast *a = c->a;
	t_nodes xa = t_args(a, x);
	if (!t_is(x, "CallNode") || !sr_eqc(node_name(x), "new") || !sr_eqc(t_const_name(a, t_ref(a, x, "receiver")), "Array") ||
	    xa.n != 2)
		return -1; /* the shape */
	bigint nb = {0}, zero = {0};
	int ok1 = t_literal(c->z, a, xa.v[0], &nb);
	int ok2 = t_literal(c->z, a, xa.v[1], &zero);
	int64_t nv = 0;
	int good = ok1 && ok2 && t_big_int64(&nb, &nv) && nv == f->count && t_big_sign(&zero) == 0;
	bigint_free(&nb);
	bigint_free(&zero);
	return good ? 1 : 0;
}

static int zero_literal(t_ctx *c, const sr_node *x)
{
	bigint lit = {0};
	int ok = t_literal(c->z, c->a, x, &lit);
	int sign = ok ? t_big_sign(&lit) : 1;
	bigint_free(&lit);
	return ok && sign == 0;
}

static int embed_sample(t_ctx *c, const sr_node *x, sr_str cn)
{
	const sr_ast *a = c->a;
	const fe_kernel_type_decl *d = fe_name_get(&c->t->kts, cn);
	if (!d || !t_is(x, "CallNode") || !sr_eqc(node_name(x), "new") || !sr_eq(t_const_name(a, t_ref(a, x, "receiver")), cn))
		return 0;
	t_nodes xs = t_args(a, x);
	if (xs.n != d->n_fields)
		return 0;
	for (size_t i = 0; i < xs.n; i++) {
		const fe_kernel_field *f = &d->fields[i];
		const sr_node *y = xs.v[i];
		if (sr_eqc(f->kind, "struct")) {
			if (!embed_sample(c, y, f->ptr))
				return 0;
		} else if (sr_eqc(f->kind, "array")) {
			if (array_sample(c, y, f) != 1)
				return 0;
		} else if (sr_eqc(f->kind, "strptr")) {
			if (!t_is(y, "StringNode") || t_str(y, "content").n != 0)
				return 0;
		} else {
			if (!t_is(y, "IntegerNode"))
				return 0;
			if (!zero_literal(c, y))
				return 0;
		}
	}
	return 1;
}

void t_kernel_handle_decl(t_ctx *c, const sr_node *n)
{
	const sr_ast *a = c->a;
	fe_top *t = c->t;
	const sr_node *v = t_ref(a, n, "value");
	sr_str h = node_name(n);
	t_nodes as = t_args(a, v);
	if (as.n != 1 || !t_is(as.v[0], "CallNode") || !sr_eqc(node_name(as.v[0]), "new")) {
		KBAD(t_pos(c, n), "a kernel struct's typing sample is `%s = BPF::KernelType.new(S.new(0, …))`", h);
		return;
	}
	sr_str sc = t_const_name(a, t_ref(a, as.v[0], "receiver"));
	fe_kernel_type_decl *d = fe_name_get(&t->kts, sc);
	if (!d) {
		KBAD(t_pos(c, as.v[0]), "%s is not declared with BPF.kernel_type", sc);
		return;
	}
	t_nodes sas = t_args(a, as.v[0]);
	if (sas.n != d->n_fields) {
		KBAD(t_pos(c, as.v[0]), "the sample must give all %d members of %s", (int64_t)d->n_fields, sc);
		return;
	}
	for (size_t i = 0; i < sas.n; i++) {
		const fe_kernel_field *f = &d->fields[i];
		const sr_node *x = sas.v[i];
		if (sr_eqc(f->kind, "struct")) {
			if (!embed_sample(c, x, f->ptr)) {
				KBAD(t_pos(c, x), "the sample of the embedded struct member %s is `%s.new(0, …)` with every member's sample",
				     f->name, f->ptr);
				return;
			}
			continue;
		}
		if (sr_eqc(f->kind, "array")) {
			if (array_sample(c, x, f) != 1) {
				KBAD(t_pos(c, x), "the sample of the array member %s is `Array.new(%d, 0)`", f->name, f->count);
				return;
			}
			continue;
		}
		if (sr_eqc(f->kind, "strptr")) {
			if (!t_is(x, "StringNode") || t_str(x, "content").n != 0) {
				KBAD(t_pos(c, x), "the sample of the :strptr member %s is the empty String literal \"\"", f->name);
				return;
			}
			continue;
		}
		int ok = t_is(x, "IntegerNode") && zero_literal(c, x);
		if (!ok) {
			KBAD(t_pos(c, x), "the sample's members are the literal 0 — it is a sample of the type for Spinel's inference");
			return;
		}
	}
	fe_name_set(&t->kt_handles, h, d);
	T_PUSH(d->handle_poss, d->n_handle_poss, t_pos(c, n));
	d->handle_poss_nil = 0;
}

/* structArgsDecl's bad(): SB033 at the call */
#define SBAD(...)                                                                                                                  \
	do {                                                                                                                       \
		KBAD(t_pos(c, n), __VA_ARGS__);                                                                                    \
		return 0;                                                                                                          \
	} while (0)

int t_struct_args_decl(t_ctx *c, const sr_node *n, t_nodes as, const char *kind, fe_root_decl *r)
{
	const sr_ast *a = c->a;
	fe_top *t = c->t;
	int fentry = !strcmp(kind, "fentry");
	const char *shape = fentry ? "`BPF.fentry :name, \"kernel_function\", args: {0 => [:or_null, TaskT]}`"
				   : "`BPF.tp_btf :name, \"tracepoint\", args: {0 => TaskT, 2 => :u32}`";
	if (as.n != 3 || !t_is(as.v[0], "SymbolNode") || !t_is(as.v[1], "StringNode") || t_str(as.v[1], "content").n == 0 ||
	    !t_is(as.v[2], "KeywordHashNode"))
		SBAD("a %S program is declared as %S — the arguments it reads, by index", kind, shape);
	const sr_node *hv = NULL;
	t_nodes els = t_arr(a, as.v[2], "elements");
	for (size_t i = 0; i < els.n; i++) {
		const sr_node *e = els.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !t_is(k, "SymbolNode") || !sr_eqc(t_str(k, "value"), "args") || hv)
			SBAD("the options of %S are exactly `args:`", shape);
		hv = v;
	}
	if (!hv || !t_is(hv, "HashNode"))
		SBAD("%S needs `args:` with a Hash literal of argument index (0..11) => a kernel struct's sample handle or an integer type",
		     shape);
	*r = (fe_root_decl){.name = t_str(as.v[0], "value"), .kind = t_s(kind), .pos = t_pos(c, n), .target = t_str(as.v[1], "content"),
			    .params_nil = 1, .targs_nil = 1, .tfields_nil = 1};
	int seen[12] = {0};
	t_nodes he = t_arr(a, hv, "elements");
	for (size_t j = 0; j < he.n; j++) {
		const sr_node *e = he.v[j];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !t_is(k, "IntegerNode") || !v)
			SBAD("each %S argument is `i => TaskT` or `i => :u32` with i an Integer literal 0..11", kind);
		bigint nb = {0};
		int ok = t_literal(c->z, a, k, &nb);
		int64_t i = 0;
		int fits = ok && t_big_int64(&nb, &i);
		bigint_free(&nb);
		if (!fits || i < 0 || i > 11 || seen[i])
			SBAD("a %S argument index is 0..11 (the u64 context slots) and appears once", kind);
		seen[i] = 1;
		if (fentry && t_is(v, "ConstantReadNode"))
			SBAD("argument %d: a fentry struct argument is always nullable — declare it `%d => [:or_null, T]` and read it with "
			     "`q = ctx.kptr_or_null(%d, T)` and `if q` (an integer argument is `%d => :u32` etc., read with `ctx.arg(%d)`)",
			     i, i, i, i, i);
		if (t_is(v, "ConstantReadNode")) {
			fe_kernel_type_decl *d = fe_name_get(&t->kt_handles, node_name(v));
			if (!d)
				SBAD("argument %d: %s is not a kernel struct's sample handle (`%s = BPF::KernelType.new(S.new(0, …))`)", i,
				     node_name(v), node_name(v));
			T_PUSH(r->targs, r->n_targs, ((fe_tp_arg){.idx = i, .kt = d}));
		} else if (t_is(v, "SymbolNode")) {
			int64_t b;
			int sg;
			if (!t_record_type(t_str(v, "value"), &b, &sg))
				SBAD("argument %d: an integer argument's type is one of :i8 … :i64 / :u8 … :u64", i);
			T_PUSH(r->targs, r->n_targs, ((fe_tp_arg){.idx = i, .type = t_str(v, "value")}));
		} else if (t_is(v, "ArrayNode")) {
			t_nodes ae = t_arr(a, v, "elements");
			if (ae.n != 2 || !t_is(ae.v[0], "SymbolNode") || !sr_eqc(t_str(ae.v[0], "value"), "or_null") ||
			    !t_is(ae.v[1], "ConstantReadNode") || !fe_name_get(&t->kt_handles, node_name(ae.v[1])))
				SBAD("argument %d: a nullable struct argument is `[:or_null, T]` with T a kernel struct's sample handle", i);
			T_PUSH(r->targs, r->n_targs,
			       ((fe_tp_arg){.idx = i, .kt = fe_name_get(&t->kt_handles, node_name(ae.v[1])), .null = 1}));
		} else {
			SBAD("argument %d: a kernel struct's sample handle or an integer type Symbol", i);
		}
		r->targs_nil = 0;
	}
	return 1;
}

int t_tp_btf_decl(t_ctx *c, const sr_node *n, t_nodes as, fe_root_decl *r) { return t_struct_args_decl(c, n, as, "tp_btf", r); }
