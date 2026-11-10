/* top_util.c — steps 1-2 helpers: the AST accessors of ast.go / analyze.go, Go-format messages, name tables, integers, the regular
 * expressions of steps 1-2 (hand-written matchers) and the fixed tables. */
#include "top_int.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* ---- AST ---- */
const sr_node *t_node(const sr_ast *a, int64_t id)
{
	if (id < 0)
		return NULL;
	return sr_imap_get(&a->nodes, id);
}

int t_nil_panic;

const sr_node *t_ref(const sr_ast *a, const sr_node *n, const char *k)
{
	if (!n) {
		t_nil_panic = 1; /* Go: a.ref(nil, …) panics */
		return NULL;
	}
	int ok;
	int64_t id = fe_node_ref(n, k, &ok);
	return ok ? t_node(a, id) : NULL;
}

t_nodes t_arr(const sr_ast *a, const sr_node *n, const char *k)
{
	t_nodes out = {0};
	if (!n) {
		t_nil_panic = 1; /* Go: a.arr(nil, …) panics */
		return out;
	}
	size_t cnt;
	int ok;
	const int64_t *ids = fe_node_arr(n, k, &cnt, &ok);
	for (size_t i = 0; i < cnt; i++) {
		const sr_node *c = t_node(a, ids[i]);
		if (c)
			T_PUSH(out.v, out.n, c);
	}
	return out;
}

sr_str t_str(const sr_node *n, const char *k)
{
	int ok;
	return fe_node_str(n, k, &ok);
}

int t_is(const sr_node *n, const char *type) { return n && sr_eqc(n->type, type); }

const sr_node *t_root(const sr_ast *a) { return t_node(a, a->root); }

/* constName: ConstantReadNode / ConstantPathNode (one level) as "Counts" / "BPF::ArrayMap"; otherwise "". */
sr_str t_const_name(const sr_ast *a, const sr_node *n)
{
	sr_str none = {"", 0};
	if (!n)
		return none;
	if (sr_eqc(n->type, "ConstantReadNode"))
		return t_str(n, "name");
	if (sr_eqc(n->type, "ConstantPathNode")) {
		const sr_node *p = t_ref(a, n, "parent");
		if (!p)
			return t_cat(t_s("::"), t_str(n, "name"));
		sr_str pn = t_const_name(a, p);
		if (pn.n == 0)
			return none;
		return t_cat(t_cat(pn, t_s("::")), t_str(n, "name"));
	}
	return none;
}

t_nodes t_args(const sr_ast *a, const sr_node *call)
{
	const sr_node *an = t_ref(a, call, "arguments");
	if (!an)
		return (t_nodes){0};
	return t_arr(a, an, "arguments");
}

t_nodes t_top_statements(const sr_ast *a, int64_t fid)
{
	t_nodes out = {0};
	const sr_node *st = t_ref(a, t_root(a), "statements");
	if (!st)
		return out;
	t_nodes body = t_arr(a, st, "body");
	for (size_t i = 0; i < body.n; i++)
		if (body.v[i]->file_id == fid)
			T_PUSH(out.v, out.n, body.v[i]);
	return out;
}

/* userFileID ranges over a Go map; a FILE path is unique in Spinel's output, so the first match is the only one. */
int64_t t_user_file_id(const sr_ast *a, sr_str base)
{
	int64_t *keys = sr_imap_sorted_keys(&a->files);
	for (size_t i = 0; i < a->files.n; i++) {
		const sr_str *p = sr_imap_get(&a->files, keys[i]);
		if (p && sr_eq(*p, base))
			return keys[i];
	}
	return -1;
}

typedef struct {
	sr_str key; /* "R"+field or "A"+field */
	size_t idx;
} walk_field;

static int wf_cmp(const void *x, const void *y)
{
	return sr_cmp(((const walk_field *)x)->key, ((const walk_field *)y)->key);
}

/* walk: Go sorts the keys of n.Ref and n.Arr (map keys, so a field appears once — the last assignment wins, as fe_node_ref). */
void t_walk(const sr_ast *a, const sr_node *n, int (*f)(void *ctx, const sr_node *n), void *ctx)
{
	if (!n || !f(ctx, n))
		return;
	walk_field *fs = NULL;
	size_t nf = 0;
	for (size_t i = 0; i < n->n_ref; i++) {
		int dup = 0;
		for (size_t j = i + 1; j < n->n_ref; j++)
			dup |= sr_eq(n->ref[i].k, n->ref[j].k);
		if (!dup)
			T_PUSH(fs, nf, ((walk_field){t_cat(t_s("R"), n->ref[i].k), i}));
	}
	for (size_t i = 0; i < n->n_arr; i++) {
		int dup = 0;
		for (size_t j = i + 1; j < n->n_arr; j++)
			dup |= sr_eq(n->arr[i].k, n->arr[j].k);
		if (!dup)
			T_PUSH(fs, nf, ((walk_field){t_cat(t_s("A"), n->arr[i].k), i}));
	}
	if (nf > 1)
		qsort(fs, nf, sizeof *fs, wf_cmp);
	for (size_t i = 0; i < nf; i++) {
		if (fs[i].key.p[0] == 'R') {
			t_walk(a, t_node(a, n->ref[fs[i].idx].v), f, ctx);
		} else {
			const sr_kv_arr *ar = &n->arr[fs[i].idx];
			for (size_t j = 0; j < ar->n; j++) {
				const sr_node *c = t_node(a, ar->ids[j]);
				if (c)
					t_walk(a, c, f, ctx);
			}
		}
	}
}

/* ---- messages ---- */
static int vfmt(fe_z *z, sr_buf *b, const char *fmt, va_list ap)
{
	for (const char *p = fmt; *p; p++) {
		if (*p != '%') {
			sr_putc(b, *p);
			continue;
		}
		switch (*++p) {
		case 's':
			sr_putstr(b, va_arg(ap, sr_str));
			break;
		case 'S':
			sr_puts(b, va_arg(ap, const char *));
			break;
		case 'd':
			fe_fmt_d(b, va_arg(ap, int64_t));
			break;
		case 'u':
			sr_printf(b, "%llu", (unsigned long long)va_arg(ap, uint64_t));
			break;
		case 'q':
			if (!fe_fmt_q(z, b, va_arg(ap, sr_str)))
				return 0;
			break;
		case 'B':
			fe_fmt_big(b, va_arg(ap, const bigint *));
			break;
		case '%':
			sr_putc(b, '%');
			break;
		default:
			abort(); /* a verb this file does not define: a defect of the port */
		}
	}
	return 1;
}

sr_str t_fmt(fe_z *z, int *ok, const char *fmt, ...)
{
	sr_buf b = {0};
	va_list ap;
	va_start(ap, fmt);
	*ok = vfmt(z, &b, fmt, ap);
	va_end(ap);
	return sr_bufstr(&b);
}

void t_add(fe_z *z, fe_verdict v, fe_code c, fe_pos p, const char *fmt, ...)
{
	sr_buf b = {0};
	va_list ap;
	va_start(ap, fmt);
	int ok = vfmt(z, &b, fmt, ap);
	va_end(ap);
	if (ok)
		fe_add(z, v, c, p, sr_bufstr(&b));
}

/* ---- integers ---- */
int t_big_sign(const bigint *x) { return x->n == 0 ? 0 : x->neg ? -1 : 1; }

static int mag64(const bigint *x, uint64_t *m)
{
	if (x->n > 2)
		return 0;
	*m = x->n == 0 ? 0 : x->n == 1 ? x->l[0] : ((uint64_t)x->l[1] << 32) | x->l[0];
	return 1;
}

int t_big_int64(const bigint *x, int64_t *out)
{
	uint64_t m;
	if (!mag64(x, &m))
		return 0;
	if (x->neg) {
		if (m > (uint64_t)1 << 63)
			return 0;
		*out = (int64_t)(0 - m);
		return 1;
	}
	if (m > (uint64_t)INT64_MAX)
		return 0;
	*out = (int64_t)m;
	return 1;
}

int t_big_uint64(const bigint *x, uint64_t *out)
{
	uint64_t m;
	if (x->neg && x->n > 0)
		return 0;
	if (!mag64(x, &m))
		return 0;
	*out = m;
	return 1;
}

int t_literal(fe_z *z, const sr_ast *a, const sr_node *n, bigint *out) { return fe_literal(z, a, n, out); }

/* ---- regular expressions ---- */
/* `^_?spinelbpf_` */
int t_reserved_prefix(sr_str s)
{
	size_t i = s.n > 0 && s.p[0] == '_' ? 1 : 0;
	return s.n - i >= 10 && memcmp(s.p + i, "spinelbpf_", 10) == 0;
}

static int is_lower(char c) { return c >= 'a' && c <= 'z'; }
static int is_upper(char c) { return c >= 'A' && c <= 'Z'; }
static int is_digit(char c) { return c >= '0' && c <= '9'; }

/* `^[a-z_][a-z0-9_]*$` ($ is the end of the text in Go's RE2 without (?m)) */
int t_lower_ident(sr_str s)
{
	if (s.n == 0 || !(is_lower(s.p[0]) || s.p[0] == '_'))
		return 0;
	for (size_t i = 1; i < s.n; i++)
		if (!(is_lower(s.p[i]) || is_digit(s.p[i]) || s.p[i] == '_'))
			return 0;
	return 1;
}

/* `^[A-Za-z_][A-Za-z0-9_]*$` */
int t_tp_ident(sr_str s)
{
	if (s.n == 0 || !(is_lower(s.p[0]) || is_upper(s.p[0]) || s.p[0] == '_'))
		return 0;
	for (size_t i = 1; i < s.n; i++)
		if (!(is_lower(s.p[i]) || is_upper(s.p[i]) || is_digit(s.p[i]) || s.p[i] == '_'))
			return 0;
	return 1;
}

/* `^_pad[0-9]+$` */
int t_pad_name(sr_str s)
{
	if (s.n < 5 || memcmp(s.p, "_pad", 4) != 0)
		return 0;
	for (size_t i = 4; i < s.n; i++)
		if (!is_digit(s.p[i]))
			return 0;
	return 1;
}

static int is_word(char c) { return is_lower(c) || is_upper(c) || is_digit(c) || c == '_'; }

/* `^\s*(require_relative|load)\b` — Go's \s is [\t\n\f\r ]; the alternation is tried left first (both alternatives end in a word
 * character, so \b needs a non-word character or the end after them). */
int t_rel_require(sr_str s, size_t *g0, size_t *g1)
{
	size_t i = 0;
	while (i < s.n && (s.p[i] == '\t' || s.p[i] == '\n' || s.p[i] == '\f' || s.p[i] == '\r' || s.p[i] == ' '))
		i++;
	static const char *const alts[] = {"require_relative", "load"};
	for (int k = 0; k < 2; k++) {
		size_t l = strlen(alts[k]);
		if (s.n - i >= l && memcmp(s.p + i, alts[k], l) == 0 && (i + l == s.n || !is_word(s.p[i + l]))) {
			*g0 = i;
			*g1 = i + l;
			return 1;
		}
	}
	return 0;
}

/* ---- fixed tables ---- */
int t_record_type(sr_str t, int64_t *bits, int *is_signed)
{
	static const struct {
		const char *n;
		int64_t b;
		int s;
	} rt[] = {{"u8", 8, 0}, {"u16", 16, 0}, {"u32", 32, 0}, {"u64", 64, 0}, {"i8", 8, 1}, {"i16", 16, 1}, {"i32", 32, 1}, {"i64", 64, 1}};
	for (size_t i = 0; i < sizeof rt / sizeof rt[0]; i++)
		if (sr_eqc(t, rt[i].n)) {
			*bits = rt[i].b;
			*is_signed = rt[i].s;
			return 1;
		}
	return 0;
}

int t_int_type(sr_str t, int64_t *bits, int *is_signed)
{
	if (!sr_eqc(t, "u32") && !sr_eqc(t, "u64") && !sr_eqc(t, "i32") && !sr_eqc(t, "i64"))
		return 0;
	return t_record_type(t, bits, is_signed);
}

int t_in(sr_str s, const char *const *list)
{
	for (; *list; list++)
		if (sr_eqc(s, *list))
			return 1;
	return 0;
}

static const char *const ctx_class[][2] = {
    {"xdp", "XdpMd"}, {"fentry", "FentryCtx"}, {"fexit", "FexitCtx"}, {"kprobe", "KprobeCtx"}, {"kretprobe", "KretprobeCtx"},
    {"uretprobe", "UretprobeCtx"}, {"sched_cls", "SkBuff"}, {"uprobe", "UprobeCtx"}, {"tp_btf", "TpBtfCtx"}, {"raw_tp", "RawTpCtx"},
    {"socket_filter", "SocketFilterCtx"}, {"cgroup_skb", "CgroupSkb"}, {"tracepoint", "TracepointCtx"}, {"ksyscall", "KsyscallCtx"},
    {"netfilter", "NfCtx"}, {"flow_dissector", "FlowCtx"}, {"sk_lookup", "SkLookupCtx"}, {"fmod_ret", "FmodRetCtx"},
    {"struct_ops", "StructOpsCtx"}};

/* ctxClass; NULL for a kind it lacks (Go's zero value "") */
const char *t_ctx_class(sr_str kind)
{
	for (size_t i = 0; i < sizeof ctx_class / sizeof ctx_class[0]; i++)
		if (sr_eqc(kind, ctx_class[i][0]))
			return ctx_class[i][1];
	return NULL;
}

static const char *const root_kinds[] = {"xdp", "fentry", "fexit", "kprobe", "tcx", "uprobe", "tp_btf", "kretprobe", "uretprobe",
					 "raw_tp", "socket_filter", "cgroup_skb", "tracepoint", "ksyscall", "netfilter",
					 "flow_dissector", "sk_lookup", "fmod_ret", NULL};

int t_root_kind(sr_str name) { return t_in(name, root_kinds); }

const char *const t_lib_names[] = {"BPF", "ArrayMap", "MapRef", "XdpMd", "Window", "RecordMap", "RecordRef", "RingBuf", "HashMap",
				   "LruHashMap", "RecordHashMap", "LruRecordHashMap", "PerCpuArrayMap", "PerCpuRecordMap",
				   "PerCpuHashMap", "PerCpuRecordHashMap", "LpmTrieMap", "DevMap", "SockMap", NULL};
const char *const t_builtin_reopen[] = {"Integer", "Object", "Kernel", "BasicObject", "Comparable", "Module", "Class", "NilClass",
					"TrueClass", "FalseClass", "Symbol", "String", "Array", "Hash", "Numeric", NULL};
const char *const t_dynamic_defs[] = {"method_missing", "respond_to_missing?", NULL};
const char *const t_dynamic_calls[] = {"send", "public_send", "__send__", "define_method", "instance_eval", "class_eval",
				       "module_eval", "instance_exec", "class_exec", "eval", "method", "instance_variable_get",
				       "instance_variable_set", "const_get", "const_set", "prepend", "include", "extend",
				       "refine", "using", "alias_method", "remove_method", "undef_method", NULL};
const char *const t_thread_consts[] = {"Thread", "Mutex", "Queue", "SizedQueue", "ConditionVariable", "Monitor", "Ractor", NULL};
const char *const t_ruby_keywords[] = {"BEGIN", "END", "alias", "and", "begin", "break", "case", "class", "def", "defined?",
				       "do", "else", "elsif", "end", "ensure", "false", "for", "if", "in", "module", "next",
				       "nil", "not", "or", "redo", "rescue", "retry", "return", "self", "super", "then",
				       "true", "undef", "unless", "until", "when", "while", "yield", NULL};

/* ---- strings ---- */
sr_str t_s(const char *s) { return sr_cstr(s); }

sr_str t_cat(sr_str a, sr_str b)
{
	sr_buf o = {0};
	sr_putstr(&o, a);
	sr_putstr(&o, b);
	return sr_bufstr(&o);
}

sr_str t_join(const sr_str *v, size_t n, const char *sep)
{
	sr_buf o = {0};
	for (size_t i = 0; i < n; i++) {
		if (i > 0)
			sr_puts(&o, sep);
		sr_putstr(&o, v[i]);
	}
	return sr_bufstr(&o);
}

/* ---- name tables (Go map[string]*T / map[string]bool) ---- */
static fe_name_entry *find(const fe_name_table *t, sr_str key)
{
	for (size_t i = 0; i < t->n; i++)
		if (sr_eq(t->e[i].key, key))
			return &t->e[i];
	return NULL;
}

void *fe_name_get(const fe_name_table *t, sr_str key)
{
	fe_name_entry *e = find(t, key);
	return e && !e->removed ? e->val : NULL;
}

int fe_name_has(const fe_name_table *t, sr_str key)
{
	fe_name_entry *e = find(t, key);
	return e && !e->removed;
}

void fe_name_set(fe_name_table *t, sr_str key, void *val)
{
	fe_name_entry *e = find(t, key);
	if (e) {
		e->val = val;
		e->removed = 0;
		return;
	}
	if (t->n == t->cap) {
		size_t nc = t->cap ? t->cap * 2 : 8;
		t->e = sr_grow(t->e, t->cap * sizeof *t->e, nc * sizeof *t->e);
		t->cap = nc;
	}
	t->e[t->n++] = (fe_name_entry){key, val, 0};
}

void fe_name_delete(fe_name_table *t, sr_str key)
{
	fe_name_entry *e = find(t, key);
	if (e)
		e->removed = 1;
}

t_struct_info *t_structs_get(const t_structs *s, sr_str key)
{
	t_struct_info *r = NULL;
	for (size_t i = 0; i < s->n; i++)
		if (sr_eq(s->e[i].key, key))
			r = s->e[i].val; /* Go: structs[name] = si — the last assignment wins */
	return r;
}
