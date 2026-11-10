/* structops.c — struct_ops: the member tables of tcp_congestion_ops and sched_ext_ops and `BPF.struct_ops`'s
 * declaration, the C twin of internal/frontend/structops.go (soType, tcpCongestionOps, schedExtOps, structOpsDecl). The messages
 * are Go's, byte for byte. */
#include "top_int.h"
#include <stdio.h>
#include <string.h>

static const fe_so_arg so_sock = {"sock", NULL, 0}, so_ptr = {"ptr", NULL, 0};
static const fe_so_arg so_task = {"task", NULL, 0}, so_exitinfo = {"exitinfo", NULL, 0}, so_bool = {"bool", NULL, 0};
static const fe_so_arg so_u8 = {"int", "u8", 8}, so_u32 = {"int", "u32", 32}, so_i32 = {"int", "i32", 32},
		       so_u64 = {"int", "u64", 64};
static const fe_so_arg so_enum32 = {"enum", "u32", 32};

static const fe_so_arg a_sock[] = {so_sock};
static const fe_so_arg a_cong_avoid[] = {so_sock, so_u32, so_u32};
static const fe_so_arg a_cong_control[] = {so_sock, so_u32, so_i32, so_ptr};
static const fe_so_arg a_set_state[] = {so_sock, so_u8};
static const fe_so_arg a_cwnd_event[] = {so_sock, so_enum32};
static const fe_so_arg a_sock_u32[] = {so_sock, so_u32};
static const fe_so_arg a_sock_ptr[] = {so_sock, so_ptr};

/* 7.3.1 include/net/tcp.h's struct tcp_congestion_ops (:1324), in Go's order */
static const fe_so_member tcp_cong_members[] = {
    {"cong_avoid", 1339, a_cong_avoid, 3, "void"},
    {"cong_control", 1343, a_cong_control, 4, "void"},
    {"ssthresh", 1346, a_sock, 1, "u32"},
    {"set_state", 1349, a_set_state, 2, "void"},
    {"cwnd_event", 1352, a_cwnd_event, 2, "void"},
    {"cwnd_event_tx_start", 1355, a_sock, 1, "void"},
    {"in_ack_event", 1358, a_sock_u32, 2, "void"},
    {"pkts_acked", 1361, a_sock_ptr, 2, "void"},
    {"min_tso_segs", 1364, a_sock, 1, "u32"},
    {"undo_cwnd", 1367, a_sock, 1, "u32"},
    {"sndbuf_expand", 1369, a_sock, 1, "u32"},
    {"init", 1383, a_sock, 1, "void"},
    {"release", 1385, a_sock, 1, "void"},
};

/* tcp_validate_congestion_control (7.3.1 net/ipv4/tcp_cong.c): each row is one requirement, NULL-terminated */
static const char *const req_ssthresh[] = {"ssthresh", NULL}, *const req_undo[] = {"undo_cwnd", NULL},
		  *const req_avoid[] = {"cong_avoid", "cong_control", NULL};
static const char *const *const tcp_cong_required[] = {req_ssthresh, req_undo, req_avoid};
static const fe_so_excluded tcp_cong_excluded[] = {
    {"get_info", "get_info returns size_t, a 64-bit return, which a struct_ops member does not support here", 0}};
static const char *const no_sleepable[] = {NULL};

static const fe_so_type tcp_congestion_ops = {
    .name = "tcp_congestion_ops", .header = "include/net/tcp.h", .line = 1324,
    .members = tcp_cong_members, .n_members = sizeof tcp_cong_members / sizeof tcp_cong_members[0],
    .required = tcp_cong_required, .n_required = sizeof tcp_cong_required / sizeof tcp_cong_required[0],
    .name_max = 16, .excluded = tcp_cong_excluded, .n_excluded = 1, .sleepable = no_sleepable};

/* 7.3.1 kernel/sched/ext/internal.h's struct sched_ext_ops (:347), in Go's order */
static const fe_so_arg s_task[] = {so_task}, s_task_u64[] = {so_task, so_u64}, s_select[] = {so_task, so_i32, so_u64},
		       s_dispatch[] = {so_i32, so_task}, s_task_bool[] = {so_task, so_bool}, s_task_u32[] = {so_task, so_u32},
		       s_task_ptr[] = {so_task, so_ptr}, s_i32_bool[] = {so_i32, so_bool}, s_ptr[] = {so_ptr},
		       s_dump_cpu[] = {so_ptr, so_i32, so_bool}, s_ptr_task[] = {so_ptr, so_task}, s_ptr_ptr[] = {so_ptr, so_ptr},
		       s_task_ptr_ptr[] = {so_task, so_ptr, so_ptr}, s_ptr_u32[] = {so_ptr, so_u32},
		       s_bandwidth[] = {so_ptr, so_u64, so_u64, so_u64}, s_ptr_bool[] = {so_ptr, so_bool}, s_ptr_u64[] = {so_ptr, so_u64},
		       s_ecaps[] = {so_i32, so_u64, so_u64}, s_i32[] = {so_i32}, s_exit[] = {so_exitinfo}, s_i32_ptr[] = {so_i32, so_ptr};

static const fe_so_member sched_ext_members[] = {
    {"select_cpu", 373, s_select, 3, "i32"},
    {"enqueue", 388, s_task_u64, 2, "void"},
    {"dequeue", 404, s_task_u64, 2, "void"},
    {"dispatch", 427, s_dispatch, 2, "void"},
    {"tick", 438, s_task, 1, "void"},
    {"runnable", 465, s_task_u64, 2, "void"},
    {"running", 482, s_task, 1, "void"},
    {"stopping", 502, s_task_bool, 2, "void"},
    {"quiescent", 522, s_task_u64, 2, "void"},
    {"set_weight", 569, s_task_u32, 2, "void"},
    {"set_cpumask", 578, s_task_ptr, 2, "void"},
    {"update_idle", 607, s_i32_bool, 2, "void"},
    {"init_task", 622, s_task_ptr, 2, "i32"},
    {"exit_task", 632, s_task_ptr, 2, "void"},
    {"enable", 641, s_task, 1, "void"},
    {"disable", 651, s_task, 1, "void"},
    {"dump", 659, s_ptr, 1, "void"},
    {"dump_cpu", 671, s_dump_cpu, 3, "void"},
    {"dump_task", 681, s_ptr_task, 2, "void"},
    {"cgroup_init", 707, s_ptr_ptr, 2, "i32"},
    {"cgroup_exit", 722, s_ptr, 1, "void"},
    {"cgroup_prep_move", 742, s_task_ptr_ptr, 3, "i32"},
    {"cgroup_move", 753, s_task_ptr_ptr, 3, "void"},
    {"cgroup_cancel_move", 765, s_task_ptr_ptr, 3, "void"},
    {"cgroup_set_weight", 780, s_ptr_u32, 2, "void"},
    {"cgroup_set_bandwidth", 802, s_bandwidth, 4, "void"},
    {"cgroup_set_idle", 816, s_ptr_bool, 2, "void"},
    {"sub_attach", 826, s_ptr, 1, "i32"},
    {"sub_detach", 832, s_ptr, 1, "void"},
    {"sub_caps_updated", 852, s_ptr_u64, 2, "void"},
    {"sub_ecaps_updated", 865, s_ecaps, 3, "void"},
    {"cpu_online", 878, s_i32, 1, "void"},
    {"cpu_offline", 887, s_i32, 1, "void"},
    {"init_cids", 900, NULL, 0, "i32"},
    {"init", 905, NULL, 0, "i32"},
    {"exit", 915, s_exit, 1, "void"},
    {"cpu_acquire", 1034, s_i32_ptr, 2, "void"},
    {"cpu_release", 1047, s_i32_ptr, 2, "void"},
};

static const fe_so_excluded sched_ext_excluded[] = {
    {"yield", "it returns bool, which a struct_ops member does not return in this version", 537},
    {"core_sched_before", "it returns bool, which a struct_ops member does not return in this version", 560},
};
/* bpf-mlir StructOpsTypes.def:69-74 (the rules of bpf_scx_init_member, 7.3.1 ext/ext.c:8171) */
static const fe_so_data sched_ext_data[] = {
    {"dispatch_max_batch", 924, 32, 2147483647, 0},
    {"flags", 929, 64, (1ull << 63) - 1, 0xff00000000000000ull},
    {"timeout_ms", 938, 32, 30000, 0},
};
static const fe_so_flag sched_ext_flags[] = {
    {"OPS_KEEP_BUILTIN_IDLE", 136, 1},       {"OPS_ENQ_LAST", 144, 2},           {"OPS_ENQ_EXITING", 158, 4},
    {"OPS_SWITCH_PARTIAL", 164, 8},          {"OPS_ENQ_MIGRATION_DISABLED", 177, 16}, {"OPS_ALLOW_QUEUED_WAKEUP", 193, 32},
    {"OPS_BUILTIN_IDLE_PER_NODE", 199, 64},  {"OPS_ALWAYS_ENQ_IMMED", 205, 128},  {"OPS_TID_TO_TASK", 216, 256},
};
/* only init, as scx_simple.bpf.c:134 (BPF_STRUCT_OPS_SLEEPABLE); the kernel allows more (ext.c:8250-8263) — a frontend limit */
static const char *const sched_ext_sleepable[] = {"init", NULL};

static const fe_so_type sched_ext_ops = {
    .name = "sched_ext_ops", .header = "kernel/sched/ext/internal.h", .line = 347,
    .members = sched_ext_members, .n_members = sizeof sched_ext_members / sizeof sched_ext_members[0],
    .name_max = 128, .name_line = 18, .excluded = sched_ext_excluded, .n_excluded = 2,
    .data = sched_ext_data, .n_data = 3, .flags = sched_ext_flags, .n_flags = sizeof sched_ext_flags / sizeof sched_ext_flags[0],
    .sleepable = sched_ext_sleepable};

const fe_so_type *const fe_so_types[] = {&sched_ext_ops, &tcp_congestion_ops, NULL};

const fe_so_type *fe_so_type_of(sr_str name)
{
	for (size_t i = 0; fe_so_types[i]; i++)
		if (sr_eqc(name, fe_so_types[i]->name))
			return fe_so_types[i];
	return NULL;
}

static const fe_so_member *member_of(const fe_so_type *t, sr_str name)
{
	for (size_t i = 0; i < t->n_members; i++)
		if (sr_eqc(name, t->members[i].name))
			return &t->members[i];
	return NULL;
}

static const fe_so_data *data_of(const fe_so_type *t, sr_str name)
{
	for (size_t i = 0; i < t->n_data; i++)
		if (sr_eqc(name, t->data[i].name))
			return &t->data[i];
	return NULL;
}

const fe_so_member *fe_so_member_of(sr_str type, sr_str member)
{
	const fe_so_type *t = fe_so_type_of(type);
	return t ? member_of(t, member) : NULL;
}

int fe_so_sleepable(sr_str type, sr_str member)
{
	const fe_so_type *t = fe_so_type_of(type);
	if (!t)
		return 0;
	for (const char *const *s = t->sleepable; *s; s++)
		if (sr_eqc(member, *s))
			return 1;
	return 0;
}

static sr_str member_names(const fe_so_type *t)
{
	sr_str *v = sr_alloc(t->n_members * sizeof *v);
	for (size_t i = 0; i < t->n_members; i++)
		v[i] = t_s(t->members[i].name);
	return t_join(v, t->n_members, ", ");
}

/* dataNames */
static sr_str data_names(const fe_so_type *t)
{
	sr_str *v = sr_alloc((t->n_data + 1) * sizeof *v);
	v[0] = t_s("`name:`");
	for (size_t i = 0; i < t->n_data; i++)
		v[i + 1] = t_cat(t_cat(t_s("`"), t_s(t->data[i].name)), t_s(":`"));
	return t_join(v, t->n_data + 1, ", ");
}

/* objName: bpf_obj_name_cpy's charset (7.3.1 kernel/bpf/syscall.c:1225 — isalnum, '_' and '.'), Go's `^[A-Za-z0-9_.]+$` */
static int obj_name(sr_str s)
{
	if (s.n == 0)
		return 0;
	for (size_t i = 0; i < s.n; i++) {
		unsigned char ch = (unsigned char)s.p[i];
		if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.'))
			return 0;
	}
	return 1;
}

/* soDataValue: 1 and *out, or 0 and the SB008 message in *msg */
static int data_value(t_ctx *c, const fe_so_type *t, sr_str key, const sr_node *v, uint64_t *out, sr_str *msg)
{
	int ok = 1;
	if (t_is(v, "IntegerNode")) {
		sr_str src = fe_slice(c->z, v);
		bigint x = {0};
		uint64_t u;
		int good = bigint_parse_ruby_int(&x, src.p, src.n) && t_big_sign(&x) >= 0 && t_big_uint64(&x, &u);
		bigint_free(&x);
		if (!good) {
			*msg = t_fmt(c->z, &ok, "`%s:` takes a non-negative Integer literal", key);
			return 0;
		}
		*out = u;
		return 1;
	}
	if (sr_eqc(key, "flags") && (t_is(v, "ConstantPathNode") || t_is(v, "ConstantReadNode"))) {
		sr_str cn = t_const_name(c->a, v);
		sr_str *names = sr_alloc((t->n_flags + 1) * sizeof *names);
		for (size_t i = 0; i < t->n_flags; i++) {
			names[i] = t_cat(t_s("BPF::Scx::"), t_s(t->flags[i].name));
			if (sr_eq(cn, names[i])) {
				*out = t->flags[i].value;
				return 1;
			}
		}
		*msg = t_fmt(c->z, &ok, "%s is not a flag of %S (the flags are %s)", cn, t->name, t_join(names, t->n_flags, ", "));
		return 0;
	}
	if (sr_eqc(key, "flags") && t_is(v, "CallNode") && sr_eqc(t_str(v, "name"), "|") && t_args(c->a, v).n == 1) {
		uint64_t l, r;
		if (!data_value(c, t, key, t_ref(c->a, v, "receiver"), &l, msg))
			return 0;
		if (!data_value(c, t, key, t_args(c->a, v).v[0], &r, msg))
			return 0;
		*out = l | r;
		return 1;
	}
	if (sr_eqc(key, "flags")) {
		*msg = t_s("`flags:` takes an Integer literal or `BPF::Scx::OPS_<NAME>` constants joined with `|`");
		return 0;
	}
	*msg = t_fmt(c->z, &ok, "`%s:` takes an Integer literal", key);
	return 0;
}

#define SO_BAD(at, ...)                                                                                                             \
	do {                                                                                                                       \
		t_add(c->z, FE_REJECTED, FE_SB008, (at), __VA_ARGS__);                                                             \
		return 0;                                                                                                          \
	} while (0)

int t_struct_ops_decl(t_ctx *c, const sr_node *n, fe_struct_ops_decl **out, fe_root_decl **roots, size_t *n_roots)
{
	const sr_ast *a = c->a;
	t_nodes as = t_args(a, n);
	fe_pos pos = t_pos(c, n);
	/* the tcp form in every message */
	const char *shape = "`BPF.struct_ops :Map, \"tcp_congestion_ops\", name: \"kname\", member: :callback, …`";
	*roots = NULL;
	*n_roots = 0;
	if (as.n != 3 || !t_is(as.v[0], "SymbolNode") || !t_is(as.v[1], "StringNode") || !t_is(as.v[2], "KeywordHashNode"))
		SO_BAD(pos, "a struct_ops table is declared as %S — a Symbol, a String literal and the keyword options", shape);
	const fe_so_type *t = fe_so_type_of(t_str(as.v[1], "content"));
	if (!t)
		SO_BAD(t_pos(c, as.v[1]),
		       "the String is not a struct_ops type of this version — the accepted types are sched_ext_ops and tcp_congestion_ops");
	fe_struct_ops_decl *d = sr_alloc(sizeof *d);
	*d = (fe_struct_ops_decl){.const_name = t_str(as.v[0], "value"), .type = t_s(t->name), .pos = pos, .ops_nil = 1, .end_line = n->end_line};
	fe_root_decl *rs = NULL;
	size_t nr = 0;
	int *declared = sr_alloc(t->n_members * sizeof *declared);
	memset(declared, 0, t->n_members * sizeof *declared);
	int name_seen = 0;
	t_nodes els = t_arr(a, as.v[2], "elements");
	for (size_t i = 0; i < els.n; i++) {
		const sr_node *e = els.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !v || !t_is(k, "SymbolNode"))
			SO_BAD(pos, "the options of %S are `key: literal` pairs", shape);
		sr_str key = t_str(k, "value");
		fe_pos at = t_pos(c, k);
		if (sr_eqc(key, "name")) {
			if (!t_is(v, "StringNode"))
				SO_BAD(t_pos(c, v), "`name:` of a %S table is a String literal (the kernel-visible name)", t->name);
			sr_str s = t_str(v, "content");
			if (s.n == 0 || (int64_t)s.n > t->name_max - 1 || !obj_name(s))
				SO_BAD(t_pos(c, v),
				       "`name:` is %d bytes; the kernel's name is 1 to %d bytes of [A-Za-z0-9_.] (bpf_obj_name_cpy; the %d-byte "
				       "field holds the NUL)",
				       (int64_t)s.n, t->name_max - 1, t->name_max);
			d->kname = s;
			name_seen = 1;
			continue;
		}
		const fe_so_excluded *ex = NULL;
		for (size_t q = 0; q < t->n_excluded; q++)
			if (sr_eqc(key, t->excluded[q].name))
				ex = &t->excluded[q];
		if (ex)
			SO_BAD(at, "the member `%s` of %S is not accepted in this version — %S", key, t->name, ex->why);
		const fe_so_data *dm = data_of(t, key);
		if (dm) { /* a data member besides name */
			for (size_t q = 0; q < d->n_data; q++)
				if (sr_eq(d->data_keys[q], key))
					SO_BAD(at, "the data member `%s:` is given twice", key);
			uint64_t x;
			sr_str msg;
			if (!data_value(c, t, key, v, &x, &msg))
				SO_BAD(t_pos(c, v), "%s", msg);
			if (x > dm->max || (x & dm->clear) != 0) {
				char rule[96];
				if (dm->clear != 0)
					snprintf(rule, sizeof rule, "without the bits 0x%llx (the kernel's internal flags)", (unsigned long long)dm->clear);
				else
					snprintf(rule, sizeof rule, "at most %llu", (unsigned long long)dm->max);
				SO_BAD(t_pos(c, v), "`%s:` is %u; %S.%s must be %S (bpf_scx_init_member, as bpf-mlir's struct_ops data rule)", key, x,
				       t->name, key, rule);
			}
			T_PUSH(d->data_keys, d->n_data, key);
			d->n_data--;
			T_PUSH(d->data_vals, d->n_data, x);
			continue;
		}
		const fe_so_member *m = member_of(t, key);
		if (!m) {
			if (t->n_data > 0)
				SO_BAD(at, "`%s` is not a member of %S (the members are %s; the data members are %s)", key, t->name, member_names(t),
				       data_names(t));
			SO_BAD(at, "`%s` is not a member of %S (the members are %s; the only data member is `name:`)", key, t->name,
			       member_names(t));
		}
		size_t mi = (size_t)(m - t->members);
		if (declared[mi])
			SO_BAD(at, "the member `%s` is given twice", key);
		if (!t_is(v, "SymbolNode"))
			SO_BAD(t_pos(c, v), "the member `%s` takes the callback's name as a Symbol (`%s: :callback`)", key, key);
		declared[mi] = 1;
		T_PUSH(d->ops, d->n_ops, ((fe_struct_ops_slot){key, t_str(v, "value")}));
		d->ops_nil = 0;
		T_PUSH(rs, nr,
		       ((fe_root_decl){.name = t_str(v, "value"), .kind = t_s("struct_ops"), .pos = pos, .target = d->const_name,
				       .nargs = m->nargs, .ret = t_s(m->ret), .params_nil = 1, .targs_nil = 1, .tfields_nil = 1,
				       .so_type = t_s(t->name), .so_member = key}));
	}
	if (!name_seen)
		SO_BAD(pos, "a %S table needs `name:` (the kernel-visible name)", t->name);
	for (size_t q = 0; q < t->n_required; q++) {
		int ok = 0;
		sr_str alts[4];
		size_t na = 0;
		for (const char *const *m = t->required[q]; *m; m++) {
			alts[na++] = t_s(*m);
			const fe_so_member *mm = member_of(t, t_s(*m));
			ok = ok || declared[mm - t->members];
		}
		if (!ok)
			SO_BAD(pos, "a %S table needs %s (tcp_validate_congestion_control)", t->name,
			       t_cat(t_cat(t_s("`"), t_join(alts, na, "` or `")), t_s("`")));
	}
	*out = d;
	*roots = rs;
	*n_roots = nr;
	return 1;
}
