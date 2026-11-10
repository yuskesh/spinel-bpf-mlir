/* top.c — analyze() steps 1-2 and the step 3 text (internal/frontend/analyze.go: analyze up to the typing run, scanTop, rootCall,
 * mapDecl, scanProgramWide). The Go code is the canon; each function names its Go counterpart. */
#include "top_int.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* lpm.go lpmKey4 */
static fe_record_field lpm_key4_fields[] = {{{"prefixlen", 9}, 32, 0, 0, 0, 0}, {{"addr", 4}, 8, 0, 0, 4, 4}};
fe_record_decl fe_lpm_key4 = {{"spinelbpf_lpm_key4", 18}, lpm_key4_fields, 2, 0, 8, 4, {{"", 0}, 0, 0}, {{"", 0}, 0, 0}};

static const char splice_msg[] =
    "Spinel spliced its builtins (enumerable.rb / enumerator.rb — the code names a method that Enumerable defines, such as count or "
    "map) and shifted this file's line numbers, and the shift could not be measured from the named nodes "
    "(docs/upstream_suspects.md S11) — rename the method or avoid the call";

fe_pos t_pos(t_ctx *c, const sr_node *n)
{
	if (!n) {
		t_nil_panic = 1; /* Go: a.File(nil) panics */
		return (fe_pos){{"", 0}, 0, 0};
	}
	return fe_pos_of(c->z, c->a, n);
}

static sr_str node_name(const sr_node *n) { return t_str(n, "name"); }

/* ---- rootCall ---- */

static int is_sym(const sr_node *x) { return t_is(x, "SymbolNode"); }

static int symbol_only(t_ctx *c, const sr_node *n, t_nodes as, const char *kind, const char *msg, fe_root_decl *r)
{
	if (as.n != 1 || !is_sym(as.v[0]))
		BAD("%S", msg);
	*r = (fe_root_decl){.name = t_str(as.v[0], "value"), .kind = t_s(kind), .pos = t_pos(c, n), .params_nil = 1, .targs_nil = 1,
			    .tfields_nil = 1};
	return 1;
}

static int sym_direction(t_ctx *c, const sr_node *n, t_nodes as, const char *kind, const char *msg, fe_root_decl *r)
{
	if (as.n != 2 || !is_sym(as.v[0]) || !is_sym(as.v[1]) ||
	    (!sr_eqc(t_str(as.v[1], "value"), "ingress") && !sr_eqc(t_str(as.v[1], "value"), "egress")))
		BAD("%S", msg);
	*r = (fe_root_decl){.name = t_str(as.v[0], "value"), .kind = t_s(kind), .pos = t_pos(c, n), .target = t_str(as.v[1], "value"),
			    .params_nil = 1, .targs_nil = 1, .tfields_nil = 1};
	return 1;
}

/* intType of rootCall */
static int int_type(const sr_node *v, sr_str *t)
{
	if (!v || !is_sym(v)) {
		*t = t_s("");
		return 0;
	}
	int64_t b;
	int s;
	*t = t_str(v, "value");
	return t_record_type(*t, &b, &s);
}

int t_root_call(t_ctx *c, const sr_node *n, fe_root_decl *r)
{
	sr_str kind = node_name(n);
	t_nodes as = t_args(c->a, n);
	if (sr_eqc(kind, "xdp"))
		return symbol_only(c, n, as, "xdp", "`BPF.xdp` takes exactly one Symbol literal (`BPF.xdp :name`)", r);
	if (sr_eqc(kind, "flow_dissector"))
		return symbol_only(c, n, as, "flow_dissector",
				   "`BPF.flow_dissector` takes exactly one Symbol literal (`BPF.flow_dissector :name` — it is attached to a "
				   "network namespace in user space with `obj.attach_netns`)",
				   r);
	if (sr_eqc(kind, "sk_lookup"))
		return symbol_only(c, n, as, "sk_lookup", "`BPF.sk_lookup` takes exactly one Symbol literal (`BPF.sk_lookup :name`)", r);
	if (sr_eqc(kind, "netfilter"))
		return symbol_only(c, n, as, "netfilter",
				   "`BPF.netfilter` takes exactly one Symbol literal (`BPF.netfilter :name` — the hook is chosen in user space "
				   "with `obj.attach_netfilter(name, pf, hooknum, priority)`)",
				   r);
	if (sr_eqc(kind, "cgroup_skb"))
		return sym_direction(c, n, as, "cgroup_skb",
				     "a cgroup_skb program is declared as `BPF.cgroup_skb :name, :ingress` or `BPF.cgroup_skb :name, :egress` "
				     "(two Symbol literals — the second is the direction)",
				     r);
	if (sr_eqc(kind, "socket_filter"))
		return symbol_only(c, n, as, "socket_filter",
				   "`BPF.socket_filter` takes exactly one Symbol literal (`BPF.socket_filter :name` — it is attached to a socket "
				   "in user space with `obj.attach_socket`)",
				   r);
	if (sr_eqc(kind, "tcx"))
		return sym_direction(c, n, as, "sched_cls",
				     "a sched_cls program is declared as `BPF.tcx :name, :ingress` or `BPF.tcx :name, :egress` (two Symbol "
				     "literals — the second is the tcx direction)",
				     r);
	if (sr_eqc(kind, "tracepoint"))
		return t_tracepoint_decl(c, n, as, r);
	if (sr_eqc(kind, "uprobe") || sr_eqc(kind, "uretprobe"))
		return t_uprobe_decl(c, n, as, r);
	if (sr_eqc(kind, "tp_btf"))
		return t_tp_btf_decl(c, n, as, r);
	if (sr_eqc(kind, "fmod_ret"))
		return t_fmod_ret_decl(c, n, as, r);
	if (sr_eqc(kind, "fentry") && as.n == 3)
		return t_struct_args_decl(c, n, as, "fentry", r);

	const char *shape = "";
	if (sr_eqc(kind, "fentry"))
		shape = "`BPF.fentry :name, \"kernel_function\"`";
	else if (sr_eqc(kind, "fexit"))
		shape = "`BPF.fexit :name, \"kernel_function\", nargs: N, ret: :i32`";
	else if (sr_eqc(kind, "kprobe"))
		shape = "`BPF.kprobe :name, \"kernel_function\", params: {n => :u64, …}`";
	else if (sr_eqc(kind, "kretprobe"))
		shape = "`BPF.kretprobe :name, \"kernel_function\", ret: :i32`";
	else if (sr_eqc(kind, "raw_tp"))
		shape = "`BPF.raw_tp :name, \"tracepoint\"`";
	else if (sr_eqc(kind, "ksyscall"))
		shape = "`BPF.ksyscall :name, \"syscall\", params: {n => :u64, …}`";
	size_t want = 2;
	if (!sr_eqc(kind, "fentry") && !sr_eqc(kind, "raw_tp"))
		want = 3;
	if (as.n < 2 || !is_sym(as.v[0]) || !t_is(as.v[1], "StringNode") || t_str(as.v[1], "content").n == 0)
		BAD("a %s program is declared as %S with a Symbol and a non-empty String literal", kind, shape);
	if (as.n != want || (want == 3 && !t_is(as.v[2], "KeywordHashNode")))
		BAD("a %s program is declared as %S", kind, shape);
	*r = (fe_root_decl){.name = t_str(as.v[0], "value"), .kind = kind, .pos = t_pos(c, n), .target = t_str(as.v[1], "content"),
			    .params_nil = 1, .targs_nil = 1, .tfields_nil = 1};
	if (want == 2)
		return 1;
	fe_name_table opts = {0}; /* Go: map[string]*Node — a repeated key keeps the last value */
	t_nodes els = t_arr(c->a, as.v[2], "elements");
	for (size_t i = 0; i < els.n; i++) {
		const sr_node *e = els.v[i];
		const sr_node *k = t_ref(c->a, e, "key"), *v = t_ref(c->a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !v || !is_sym(k))
			BAD("the options of %S are `key: literal` pairs", shape);
		fe_name_set(&opts, t_str(k, "value"), (void *)v);
	}
	size_t n_opts = 0;
	for (size_t i = 0; i < opts.n; i++)
		n_opts += !opts.e[i].removed;
	if (sr_eqc(kind, "kretprobe")) {
		const sr_node *rv = fe_name_get(&opts, t_s("ret"));
		if (n_opts != 1 || !rv)
			BAD("%S needs exactly `ret:` (a Symbol :i8 … :u64 — the kernel does not check it; the value is the return register "
			    "cut to this width)",
			    shape);
		sr_str t;
		if (!int_type(rv, &t))
			BAD("`ret:` of %S is one of :i8 … :i64 / :u8 … :u64", shape);
		r->ret = t;
	} else if (sr_eqc(kind, "fexit")) {
		const sr_node *nv = fe_name_get(&opts, t_s("nargs")), *rv = fe_name_get(&opts, t_s("ret"));
		if (n_opts != 2 || !nv || !rv || !t_is(nv, "IntegerNode"))
			BAD("%S needs exactly `nargs:` (an Integer literal 0..12) and `ret:` (a Symbol :i8 … :u64)", shape);
		bigint nb = {0};
		int ok = t_literal(c->z, c->a, nv, &nb);
		int64_t na = 0;
		int fits = ok && t_big_int64(&nb, &na);
		bigint_free(&nb);
		if (!fits || na < 0 || na > 12)
			BAD("`nargs:` of %S is the target function's argument count, 0..12", shape);
		sr_str t;
		if (!int_type(rv, &t))
			BAD("`ret:` of %S is one of :i8 … :i64 / :u8 … :u64", shape);
		r->nargs = na;
		r->ret = t;
	} else if (sr_eqc(kind, "kprobe") || sr_eqc(kind, "ksyscall")) {
		int ksys = sr_eqc(kind, "ksyscall");
		if (ksys && (!t_tp_ident(r->target) || (r->target.n >= 4 && memcmp(r->target.p, "sys_", 4) == 0) ||
			     (r->target.n >= 2 && memcmp(r->target.p, "__", 2) == 0)))
			BAD("the target of %S is a syscall name — a C identifier without the `sys_` / `__` prefix (the wrapper "
			    "`__x64_sys_<name>` is derived), got %q",
			    shape, r->target);
		const sr_node *pv = fe_name_get(&opts, t_s("params"));
		if (n_opts != 1 || !pv || !t_is(pv, "HashNode") || t_arr(c->a, pv, "elements").n == 0)
			BAD("%S needs `params:` with a non-empty Hash literal of register number (1..6) => type", shape);
		int seen[7] = {0};
		t_nodes pe = t_arr(c->a, pv, "elements");
		for (size_t i = 0; i < pe.n; i++) {
			const sr_node *e = pe.v[i];
			const sr_node *k = t_ref(c->a, e, "key"), *v = t_ref(c->a, e, "value");
			if (!t_is(e, "AssocNode") || !k || !t_is(k, "IntegerNode"))
				BAD("each %s parameter is `n => :type` with n an Integer literal 1..6", kind);
			bigint nb = {0};
			int ok = t_literal(c->z, c->a, k, &nb);
			int64_t pn = 0;
			int fits = ok && t_big_int64(&nb, &pn);
			bigint_free(&nb);
			if (!fits || pn < 1 || pn > 6 || seen[pn])
				BAD("a %s parameter number is 1..6 (the x86_64 argument registers, 1-origin like the schema's n) and "
				    "appears once",
				    kind);
			sr_str t;
			int tok = int_type(v, &t);
			if (!tok && !ksys && v && is_sym(v) && sr_eqc(t_str(v, "value"), "ptr")) {
				t = t_s("ptr");
				tok = 1;
			}
			if (!tok && ksys && v && is_sym(v) &&
			    (sr_eqc(t_str(v, "value"), "user_str") || sr_eqc(t_str(v, "value"), "user_str_array"))) {
				t = t_str(v, "value");
				tok = 1;
			}
			if (!tok)
				BAD("a %s parameter type is one of :i8 … :i64 / :u8 … :u64%S%S", kind,
				    !ksys ? " or :ptr (a pointer read with `v, st = ctx.read(n, offset, :type)`)" : "",
				    ksys ? " or :user_str (a `const char *` — read with ctx.str_arg(n))" : "");
			seen[pn] = 1;
			T_PUSH(r->params, r->n_params, ((fe_kparam){pn, t}));
			r->params_nil = 0;
		}
	}
	return 1;
}

/* ---- mapDecl ---- */
void t_map_decl(t_ctx *c, const sr_node *n)
{
	const sr_ast *a = c->a;
	const sr_node *v = t_ref(a, n, "value");
	if (!v || !t_is(v, "CallNode") || !sr_eqc(node_name(v), "new"))
		return;
	sr_str rc = t_const_name(a, t_ref(a, v, "receiver"));
	if (!sr_eqc(rc, "BPF::ArrayMap") && !sr_eqc(rc, "BPF::PerCpuArrayMap") && !sr_eqc(rc, "BPF::LpmTrieMap") &&
	    !sr_eqc(rc, "BPF::DevMap") && !sr_eqc(rc, "BPF::SockMap"))
		return;
	const char *kind = "", *cls = "";
	if (sr_eqc(rc, "BPF::PerCpuArrayMap"))
		kind = "percpu_array", cls = "PerCpuArrayMap";
	else if (sr_eqc(rc, "BPF::LpmTrieMap"))
		kind = "lpm_trie", cls = "LpmTrieMap";
	else if (sr_eqc(rc, "BPF::DevMap"))
		kind = "devmap", cls = "DevMap";
	else if (sr_eqc(rc, "BPF::SockMap"))
		kind = "sockmap", cls = "SockMap";
	int lpm = !strcmp(kind, "lpm_trie");
	const char *shown = "ArrayMap";
	if (lpm || !strcmp(kind, "devmap") || !strcmp(kind, "sockmap"))
		shown = cls;
	sr_str cn = node_name(n);
	fe_pos p = t_pos(c, n);
	fe_name_set(&c->t->bad_maps, cn, (void *)1);
	if (fe_name_has(&c->t->maps, cn)) {
		t_add(c->z, FE_REJECTED, FE_SB013, p, "constant %s is assigned twice", cn);
		return;
	}
	t_nodes as = t_args(a, v);
	if (as.n == 3 && t_is(as.v[1], "IntegerNode")) {
		t_add(c->z, FE_REJECTED, FE_SB013, t_pos(c, as.v[1]),
		      "the value type is a Symbol — write `:u32`, `:u64`, `:i32` or `:i64` (e.g. `BPF::%S.new(\"%s\", %S, n)`)", shown, cn,
		      lpm ? ":u32" : ":u64");
		return;
	}
	if (as.n != 3 || !t_is(as.v[0], "StringNode") || !is_sym(as.v[1]) || !t_is(as.v[2], "IntegerNode")) {
		t_add(c->z, FE_REJECTED, FE_SB013, p,
		      "a map is declared as `%s = BPF::%S.new(\"%s\", %S, max_entries)` with literal arguments", cn, shown, cn,
		      lpm ? ":u32|:i32" : ":u32|:u64|:i32|:i64");
		return;
	}
	sr_str name = t_str(as.v[0], "content");
	if (!sr_eq(name, cn)) {
		t_add(c->z, FE_REJECTED, FE_SB013, t_pos(c, as.v[0]),
		      "the map name %q differs from its constant %s — both sides look the map up by this name, so they must be the same",
		      name, cn);
		return;
	}
	for (size_t i = 0; i < c->t->n_map_order; i++)
		if (sr_eq(c->t->map_order[i]->name, name)) {
			t_add(c->z, FE_REJECTED, FE_SB013, p, "two map declarations use the name %q", name);
			return;
		}
	sr_str vts = t_str(as.v[1], "value");
	int64_t vbits = 0;
	int vsigned = 0;
	t_int_type(vts, &vbits, &vsigned); /* Go: the [2]int zero value when absent */
	if (!strcmp(kind, "sockmap") && !sr_eqc(vts, "u64")) {
		t_add(c->z, FE_REJECTED, FE_SB013, t_pos(c, as.v[1]),
		      "the value type of a sockmap is :u64 (a socket — user space puts its fd), got :%s", vts);
		return;
	}
	if (!strcmp(kind, "devmap") && !sr_eqc(vts, "u32")) {
		t_add(c->z, FE_REJECTED, FE_SB013, t_pos(c, as.v[1]), "the value type of a devmap is :u32 (an ifindex), got :%s", vts);
		return;
	}
	if (lpm && vbits == 64) {
		t_add(c->z, FE_REJECTED, FE_SB013, t_pos(c, as.v[1]),
		      "the value type of an lpm_trie map is :u32 or :i32, got :%s — 64-bit values are not accepted yet", vts);
		return;
	}
	if (vbits == 0) {
		t_add(c->z, FE_REJECTED, FE_SB013, t_pos(c, as.v[1]), "the value type must be %S, got :%s",
		      lpm ? ":u32 or :i32" : ":u32, :u64, :i32 or :i64", vts);
		return;
	}
	bigint ent = {0};
	if (!t_literal(c->z, a, as.v[2], &ent))
		return;
	uint64_t eu = 0;
	if (t_big_sign(&ent) <= 0 || !t_big_uint64(&ent, &eu) || eu > 0xffffffffULL) {
		t_add(c->z, FE_REJECTED, FE_SB013, t_pos(c, as.v[2]), "max_entries must be a positive integer below 2^32, got %B", &ent);
		bigint_free(&ent);
		return;
	}
	bigint_free(&ent);
	if (t_reserved_prefix(name)) {
		t_add(c->z, FE_REJECTED, FE_SB007, p, "map name %q uses the reserved prefix spinelbpf_", name);
		return;
	}
	fe_name_delete(&c->t->bad_maps, cn);
	fe_map_decl *m = sr_alloc(sizeof *m);
	*m = (fe_map_decl){.const_name = cn, .name = name, .value_bits = vbits, .is_signed = vsigned, .max_entries = eu,
			   .kind = t_s(kind), .class_name = t_s(cls), .pos = p};
	if (lpm)
		m->key_record = &fe_lpm_key4;
	fe_name_set(&c->t->maps, cn, m);
	T_PUSH(c->t->map_order, c->t->n_map_order, m);
	c->t->map_order_nil = 0;
}

/* ---- scanTop ---- */
static int is_bpf_call(const sr_ast *a, const sr_node *n, const char *name)
{
	return t_is(n, "CallNode") && sr_eqc(node_name(n), name) && sr_eqc(t_const_name(a, t_ref(a, n, "receiver")), "BPF");
}

static int is_root_call(const sr_ast *a, const sr_node *n)
{
	return t_is(n, "CallNode") && t_root_kind(node_name(n)) && sr_eqc(t_const_name(a, t_ref(a, n, "receiver")), "BPF");
}

typedef struct {
	t_ctx *c;
	const sr_node *top;
} nested_root;

static int nested_root_f(void *ctx, const sr_node *x)
{
	nested_root *w = ctx;
	if (x != w->top && is_root_call(w->c->a, x))
		t_add(w->c->z, FE_REJECTED, FE_SB008, t_pos(w->c, x), "`BPF.%s` must be a top-level statement", node_name(x));
	return 1;
}

static sr_str decl_name(sr_str kind) { return sr_eqc(kind, "sched_cls") ? t_s("tcx") : kind; }

void t_scan_top(t_ctx *c, int64_t fid)
{
	const sr_ast *a = c->a;
	fe_top *t = c->t;
	fe_root_decl *roots = NULL;
	size_t n_roots = 0;
	fe_name_table seen = {0}, defs = {0};
	t_structs structs = {0};
	t_nodes top = t_top_statements(a, fid);
	for (size_t i = 0; i < top.n; i++) {
		const sr_node *n = top.v[i];
		if (t_is(n, "ConstantWriteNode")) {
			t_struct_info *si;
			if (t_struct_of(c, n, &si))
				T_PUSH(structs.e, structs.n, ((t_struct_entry){node_name(n), si}));
		}
	}
	for (size_t i = 0; i < top.n; i++)
		if (is_bpf_call(a, top.v[i], "record"))
			t_record_decl(c, top.v[i], &structs);
	for (size_t i = 0; i < top.n; i++)
		if (is_bpf_call(a, top.v[i], "kernel_type"))
			t_kernel_type_decl(c, top.v[i], &structs);
	t_kernel_types_resolve(c);
	for (size_t i = 0; i < top.n; i++) {
		const sr_node *n = top.v[i];
		const sr_node *v = t_ref(a, n, "value");
		if (t_is(n, "ConstantWriteNode") && v && t_is(v, "CallNode") && sr_eqc(node_name(v), "new") &&
		    sr_eqc(t_const_name(a, t_ref(a, v, "receiver")), "BPF::KernelType"))
			t_kernel_handle_decl(c, n);
	}
	for (size_t i = 0; i < top.n; i++) {
		const sr_node *n = top.v[i];
		if (t_is(n, "DefNode")) {
			if (!t_ref(a, n, "receiver"))
				fe_name_set(&defs, node_name(n), (void *)n);
		} else if (t_is(n, "CallNode")) {
			sr_str nm = node_name(n);
			if (sr_eqc(nm, "require") && !t_ref(a, n, "receiver")) {
				t_nodes as = t_args(a, n);
				if (as.n != 1 || !t_is(as.v[0], "StringNode") ||
				    (!sr_eqc(t_str(as.v[0], "content"), "bpf") && !sr_eqc(t_str(as.v[0], "content"), "spinelbpf")))
					t_add(c->z, FE_REJECTED, FE_SB001, t_pos(c, n),
					      "only `require \"bpf\"` and `require \"spinelbpf\"` are accepted (the program is one file)");
			} else if (sr_eqc(nm, "require_relative") || sr_eqc(nm, "load")) {
				t_add(c->z, FE_REJECTED, FE_SB001, t_pos(c, n),
				      "`%s` is not accepted (the program is one file plus `require \"bpf\"`)", nm);
			} else if (t_root_kind(nm) && sr_eqc(t_const_name(a, t_ref(a, n, "receiver")), "BPF")) {
				fe_root_decl r;
				if (!t_root_call(c, n, &r))
					continue;
				if (fe_name_has(&seen, r.name)) {
					t_add(c->z, FE_REJECTED, FE_SB008, t_pos(c, n), "`BPF.%s :%s` is declared twice", decl_name(r.kind),
					      r.name);
					continue;
				}
				fe_name_set(&seen, r.name, (void *)1);
				T_PUSH(roots, n_roots, r);
			}
		} else if (t_is(n, "ConstantWriteNode")) {
			if (t_global_decl(c, n))
				continue;
			const sr_node *v = t_ref(a, n, "value");
			const char *hk, *hcls;
			int hrec;
			if (v && t_is(v, "CallNode") && sr_eqc(node_name(v), "new") &&
			    (sr_eqc(t_const_name(a, t_ref(a, v, "receiver")), "BPF::RecordMap") ||
			     sr_eqc(t_const_name(a, t_ref(a, v, "receiver")), "BPF::PerCpuRecordMap"))) {
				t_record_map_decl(c, n);
			} else if (v && t_is(v, "CallNode") && sr_eqc(node_name(v), "new") &&
				   sr_eqc(t_const_name(a, t_ref(a, v, "receiver")), "BPF::RingBuf")) {
				t_ring_decl(c, n);
			} else if (t_hash_class(t_const_name(a, t_ref(a, v, "receiver")), &hk, &hrec, &hcls) && t_is(v, "CallNode") &&
				   sr_eqc(node_name(v), "new")) {
				t_hash_map_decl(c, n, hk, hrec, hcls);
			} else {
				t_map_decl(c, n);
			}
		}
	}
	for (size_t i = 0; i < top.n; i++) {
		const sr_node *n = top.v[i];
		if (is_root_call(a, n))
			continue;
		nested_root w = {c, n};
		t_walk(a, n, nested_root_f, &w);
	}
	fe_root_decl *out = NULL;
	size_t n_out = 0;
	for (size_t i = 0; i < n_roots; i++) {
		fe_root_decl *r = &roots[i];
		const sr_node *d = fe_name_get(&defs, r->name);
		if (!d) {
			t_add(c->z, FE_REJECTED, FE_SB008, r->pos, "`BPF.%s :%s` names no top-level `def %s`", decl_name(r->kind), r->name,
			      r->name);
			continue;
		}
		const sr_node *pn = t_ref(a, d, "parameters");
		int ok = 0;
		if (pn) {
			size_t cnt;
			int has;
			fe_node_arr(pn, "requireds", &cnt, &has);
			size_t nreq = cnt;
			fe_node_arr(pn, "optionals", &cnt, &has);
			size_t nopt = cnt;
			fe_node_arr(pn, "keywords", &cnt, &has);
			size_t nkw = cnt;
			fe_node_arr(pn, "posts", &cnt, &has);
			size_t npost = cnt;
			ok = nreq == 1 && nopt == 0 && nkw == 0 && npost == 0 && !t_ref(a, pn, "rest") && !t_ref(a, pn, "block") &&
			     !t_ref(a, pn, "keyword_rest");
		}
		if (ok) {
			t_nodes req = t_arr(a, pn, "requireds");
			if (req.n == 0)
				t_nil_panic = 1; /* Go: a.arr(...)[0] on an empty slice (a dangling child id) panics */
			else if (!t_is(req.v[0], "RequiredParameterNode"))
				ok = 0;
		}
		if (!ok) {
			t_add(c->z, FE_REJECTED, FE_SB008, t_pos(c, d),
			      "the eBPF program `%s` must take exactly one required parameter (the context) — no optional, rest, keyword "
			      "or block parameters",
			      r->name);
			continue;
		}
		T_PUSH(out, n_out, *r);
	}
	t_check_global_names(c, roots, n_roots);
	t->roots = out;
	t->n_roots = n_out;
	t->roots_nil = out == NULL;
}

/* ---- scanProgramWide ---- */
typedef struct {
	t_ctx *c;
	int64_t fid;
} wide;

static int wide_f(void *ctx, const sr_node *n)
{
	wide *w = ctx;
	t_ctx *c = w->c;
	const sr_ast *a = c->a;
	if (n->file_id != w->fid)
		return 1;
	if (t_is(n, "ClassNode") || t_is(n, "ModuleNode")) {
		sr_str name = t_const_name(a, t_ref(a, n, "constant_path"));
		size_t cut = 0;
		for (size_t i = 0; i < name.n; i++)
			if (name.p[i] == ':')
				cut = i + 1;
		sr_str sh = {name.p + cut, name.n - cut};
		if (t_in(sh, t_lib_names) || (name.n >= 5 && memcmp(name.p, "BPF::", 5) == 0))
			t_add(c->z, FE_REJECTED, FE_SB011, t_pos(c, n),
			      "`%s` is defined by ruby/lib/bpf.rb — the program must not define or reopen it", name);
		else if (t_in(sh, t_builtin_reopen))
			t_add(c->z, FE_UNKNOWN, FE_SB016, t_pos(c, n),
			      "the program reopens builtin `%s` — operators and calls may no longer mean what the eBPF side assumes", name);
	} else if (t_is(n, "SingletonClassNode")) {
		t_add(c->z, FE_UNKNOWN, FE_SB016, t_pos(c, n), "`class << …` is not accepted (call targets must be static)");
	} else if (t_is(n, "DefNode")) {
		sr_str name = node_name(n);
		if (t_in(name, t_dynamic_defs))
			t_add(c->z, FE_UNKNOWN, FE_SB016, t_pos(c, n), "the program defines `%s` — calls may no longer resolve statically",
			      name);
		if (t_reserved_prefix(name))
			t_add(c->z, FE_REJECTED, FE_SB007, t_pos(c, n), "`%s` uses the reserved prefix spinelbpf_", name);
		if (name.n >= 7 && memcmp(name.p, "__ebpf_", 7) == 0) /* Go: && !mutation("no-ebpf-prefix") — the user path */
			t_add(c->z, FE_REJECTED, FE_SB007, t_pos(c, n),
			      "`%s` uses the reserved prefix __ebpf_ — a program or an eBPF-side function becomes a symbol next to "
			      "bpf-mlir's internal functions (`__ebpf_present_*` — the outlined ring buffer present, `__ebpf_loop_cb_*` …); "
			      "rename it",
			      name);
	} else if (t_is(n, "CallNode")) {
		if (t_in(node_name(n), t_dynamic_calls))
			t_add(c->z, FE_UNKNOWN, FE_SB016, t_pos(c, n), "the program calls `%s` — calls may no longer resolve statically",
			      node_name(n));
	} else if (t_is(n, "ConstantWriteNode")) {
		/* Go: strings.ToLower. Only ASCII can produce the ASCII prefix: the two non-ASCII letters whose lower case is ASCII
		 * (U+212A KELVIN SIGN → k, U+0130 → i + U+0307) cannot complete `^_?spinelbpf_`, so lowering ASCII bytes is exact. */
		sr_str nm = node_name(n);
		char *lo = sr_alloc(nm.n + 1);
		for (size_t i = 0; i < nm.n; i++)
			lo[i] = nm.p[i] >= 'A' && nm.p[i] <= 'Z' ? (char)(nm.p[i] + 32) : nm.p[i];
		if (t_reserved_prefix((sr_str){lo, nm.n}))
			t_add(c->z, FE_REJECTED, FE_SB007, t_pos(c, n), "`%s` uses the reserved prefix spinelbpf_", nm);
	}
	return 1;
}

void t_scan_program_wide(t_ctx *c, int64_t fid)
{
	wide w = {c, fid};
	t_walk(c->a, t_root(c->a), wide_f, &w);
}

/* ---- threads ---- */
typedef struct {
	t_ctx *c;
	int64_t fid;
} threads_w;

static int threads_f(void *ctx, const sr_node *n)
{
	threads_w *w = ctx;
	if (n->file_id == w->fid && (t_is(n, "ConstantReadNode") || t_is(n, "ConstantPathNode")) &&
	    t_in(node_name(n), t_thread_consts)) {
		fe_top *t = w->c->t;
		T_PUSH(t->thread_refs, t->n_thread_refs, ((fe_thread_ref){node_name(n), t_pos(w->c, n), n->line}));
		t->thread_refs_nil = 0;
	}
	return 1;
}

/* ---- analyze steps 1-2 ---- */
static char *cstr(sr_str s)
{
	char *p = sr_alloc(s.n + 1);
	if (s.n > 0) /* an empty sr_str may have a NULL p */
		memcpy(p, s.p, s.n);
	return p;
}

static char *join(const char *a, const char *b)
{
	size_t la = strlen(a), lb = strlen(b);
	char *p = sr_alloc(la + lb + 2);
	memcpy(p, a, la);
	p[la] = '/';
	memcpy(p + la + 1, b, lb);
	return p;
}

void fe_flush_thread_refs(fe_z *z, fe_top *t, const fe_name_table *membership, const fe_name_table *defs)
{
	for (size_t i = 0; i < t->n_thread_refs; i++) {
		const fe_thread_ref *r = &t->thread_refs[i];
		int in_bpf = 0;
		for (size_t j = 0; membership && j < membership->n; j++) {
			const fe_name_entry *m = &membership->e[j];
			if (m->removed)
				continue;
			const sr_node *d = defs ? fe_name_get(defs, m->key) : NULL;
			if (!d || r->line < d->line || r->line > d->end_line)
				continue;
			const fe_str_list *ks = m->val;
			for (size_t k = 0; ks && k < ks->n; k++)
				if (sr_eqc(ks->v[k], "bpf"))
					in_bpf = 1;
		}
		if (in_bpf)
			t_add(z, FE_REJECTED, FE_SB027, r->pos,
			      "`%s` inside a function reached from an eBPF program — threads do not exist on the eBPF side", r->name);
	}
	t->thread_refs = NULL;
	t->n_thread_refs = 0;
	t->thread_refs_nil = 1;
}

static void returned(fe_top *t, const fe_diags *ds)
{
	t->outcome = FE_TOP_RETURNED;
	t->res_diags = ds->v;
	t->n_res_diags = ds->n;
	t->res_diags_nil = ds->v == NULL;
}

static sr_result finish(fe_z *z, fe_top *t, sr_result r)
{
	if (z->np.kind == SR_OK && t_nil_panic)
		fe_not_ported(z, "a Go nil-node panic path (a.ref / a.arr / a.File on nil)");
	if (z->np.kind != SR_OK)
		r = z->np;
	if (r.kind != SR_OK) {
		t->outcome = FE_TOP_ERROR;
		t->err = r;
	}
	return r;
}

sr_result fe_top_run(fe_z *z, const sr_spinel *sp, const char *work, sr_str inject_expr, fe_top *out)
{
	memset(out, 0, sizeof *out);
	t_nil_panic = 0;
	out->res_diags_nil = out->thread_refs_nil = out->kt_order_nil = out->map_order_nil = out->ring_order_nil = 1;
	out->global_order_nil = out->root_kinds_nil = out->roots_nil = 1;
	char *base = cstr(z->base), *dir = join(work, "plain");

	/* 1. the plain run */
	sr_analysis an;
	memset(&an, 0, sizeof an);
	sr_result r = sr_analyze(sp, dir, base, z->text, &an);
	if (r.kind != SR_OK)
		return finish(z, out, r);
	if (an.n_diags > 0) {
		for (size_t i = 0; i < z->n_lines; i++) {
			size_t g0, g1;
			sr_str l = z->lines[i];
			if (t_rel_require(l, &g0, &g1)) {
				sr_buf b = {0};
				sr_putc(&b, '`');
				sr_put(&b, l.p + g0, g1 - g0);
				sr_puts(&b, "` is not accepted (the program is one file plus `require \"bpf\"`); spinel: ");
				sr_putstr(&b, an.diags[0].msg);
				fe_diag *d = sr_alloc(sizeof *d);
				*d = (fe_diag){FE_REJECTED, FE_SB001, {z->base, (int64_t)i + 1, (int64_t)g0 + 1}, NULL, 0, sr_bufstr(&b)};
				fe_diags ds = {d, 1, 1};
				returned(out, &ds);
				return finish(z, out, sr_ok);
			}
		}
		fe_diag *d = sr_alloc(an.n_diags * sizeof *d);
		for (size_t i = 0; i < an.n_diags; i++)
			d[i] = (fe_diag){FE_REJECTED, FE_SB000, {an.diags[i].file, an.diags[i].line, an.diags[i].col}, NULL, 0,
					 an.diags[i].msg};
		fe_diags ds = {d, an.n_diags, an.n_diags};
		returned(out, &ds);
		return finish(z, out, sr_ok);
	}
	if (!an.ast)
		return finish(z, out, sr_not_ported("the plain run has no AST and no diagnostics (Go dereferences a nil AST)"));
	out->plain = an;
	const sr_ast *a = an.ast;
	int64_t fid = t_user_file_id(a, z->base);
	if (fid < 0) {
		sr_buf b = {0};
		sr_puts(&b, "spinel AST has no FILE record for ");
		sr_putstr(&b, z->base);
		return finish(z, out, sr_err_str(sr_bufstr(&b)));
	}
	int64_t k;
	if (!fe_align_splice(&out->plain, z->base, z->text, &k)) {
		t_add(z, FE_REJECTED, FE_SB000, (fe_pos){z->base, 0, 0}, "%S", splice_msg);
		returned(out, &z->diags);
		return finish(z, out, sr_ok);
	}

	int threads = 0;
	r = sr_uses_threads(sp, dir, base, &threads);
	if (r.kind != SR_OK)
		return finish(z, out, r);
	t_ctx c = {z, a, out};
	if (threads) {
		threads_w w = {&c, fid};
		t_walk(a, t_root(a), threads_f, &w);
	}

	/* 2. the top level */
	t_scan_top(&c, fid);
	for (size_t i = 0; i < out->n_roots; i++) {
		T_PUSH(out->root_kinds, out->n_root_kinds, out->roots[i].kind);
		out->root_kinds_nil = 0;
	}
	t_scan_program_wide(&c, fid);
	t_check_member_defs(&c, fid, out->roots, out->n_roots);
	if (out->n_roots == 0) {
		if (!fe_diags_blocking(&z->diags))
			t_add(z, FE_REJECTED, FE_SB008, (fe_pos){z->base, 0, 0},
			      "no eBPF program: declare one with `BPF.xdp :name` at the top level");
		fe_flush_thread_refs(z, out, NULL, NULL);
		returned(out, &z->diags);
		return finish(z, out, sr_ok);
	}

	/* 3. the injected text */
	sr_buf inj = {0};
	sr_putstr(&inj, z->text);
	sr_puts(&inj, "if false\n");
	for (size_t i = 0; i < out->n_roots; i++) {
		sr_puts(&inj, "  ");
		sr_putstr(&inj, out->roots[i].name);
		sr_putc(&inj, '(');
		if (inject_expr.n > 0) {
			sr_putstr(&inj, inject_expr);
		} else {
			const char *cc = t_ctx_class(out->roots[i].kind);
			sr_puts(&inj, "BPF::");
			sr_puts(&inj, cc ? cc : "");
			sr_puts(&inj, ".new");
		}
		sr_puts(&inj, ")\n");
	}
	sr_puts(&inj, "end\n");
	out->inject = sr_bufstr(&inj);
	out->outcome = FE_TOP_CONTINUE;
	return finish(z, out, sr_ok);
}
