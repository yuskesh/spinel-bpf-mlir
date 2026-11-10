/* topdecl_probe.c — tracepoint.go tracepointDecl / tpArrayField, uprobe.go uprobeDecl, fmodret.go fmodRetDecl. */
#include "top_int.h"

#include <bml/build.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static sr_str node_name(const sr_node *n) { return t_str(n, "name"); }

/* the integer literal as int64 (Go: literal ok && IsInt64); the literal's diagnostics are added as in Go */
static int lit64(t_ctx *c, const sr_node *x, int64_t *v)
{
	bigint nb = {0};
	int ok = t_literal(c->z, c->a, x, &nb);
	int fits = ok && t_big_int64(&nb, v);
	bigint_free(&nb);
	return fits;
}

/* Go's int64 addition wraps; C's signed overflow is undefined, so add as uint64 */
static int64_t wrap_add(int64_t x, int64_t y) { return (int64_t)((uint64_t)x + (uint64_t)y); }

/* ---- tracepoint.go ---- */
#define TP_MAX_CTX 8192
static const char tracepoint_shape[] = "`BPF.tracepoint :name, \"category/event\", fields: {name => [offset, :type], …}`";

static int tp_array_field(t_ctx *c, const sr_node *n, sr_str name, t_nodes els, fe_tp_field *out)
{
	const sr_ast *a = c->a;
	t_nodes ae = t_arr(a, els.v[1], "elements");
	if (ae.n != 2 || !t_is(ae.v[0], "SymbolNode") || !t_is(ae.v[1], "IntegerNode") ||
	    (!sr_eqc(t_str(ae.v[0], "value"), "u8") && !sr_eqc(t_str(ae.v[0], "value"), "i8")))
		BAD("field %s: a byte array is `%s: [offset, [:u8, N]]` (or :i8) with an Integer literal N of 1..64 — the tracefs "
		    "format's `__u8 %s[N]`",
		    name, name, name);
	int64_t nn;
	if (!lit64(c, ae.v[1], &nn) || nn < 1 || nn > 64)
		BAD("field %s: a byte array is `%s: [offset, [:u8, N]]` (or :i8) with an Integer literal N of 1..64 — the tracefs "
		    "format's `__u8 %s[N]`",
		    name, name, name);
	int64_t o;
	if (!lit64(c, els.v[0], &o) || o < 8 || wrap_add(o, nn) > TP_MAX_CTX)
		BAD("field %s: the offset is an Integer ≥ 8 (the first 8 bytes are not readable from BPF) and offset + %d ≤ %d", name,
		    nn, (int64_t)TP_MAX_CTX);
	*out = (fe_tp_field){name, o, t_str(ae.v[0], "value"), nn};
	return 1;
}

typedef struct {
	sr_str *names;
	size_t n_names;
	int64_t *offs;
	size_t n_offs;
} tp_seen;

static int seen_name(const tp_seen *s, sr_str x)
{
	for (size_t i = 0; i < s->n_names; i++)
		if (sr_eq(s->names[i], x))
			return 1;
	return 0;
}

static int seen_off(const tp_seen *s, int64_t o)
{
	for (size_t i = 0; i < s->n_offs; i++)
		if (s->offs[i] == o)
			return 1;
	return 0;
}

int t_tracepoint_decl(t_ctx *c, const sr_node *n, t_nodes as, fe_root_decl *r)
{
	const sr_ast *a = c->a;
	if (as.n != 3 || !t_is(as.v[0], "SymbolNode") || !t_is(as.v[1], "StringNode") || !t_is(as.v[2], "KeywordHashNode"))
		BAD("a tracepoint program is declared as %S — the event's fields it reads, with the offset and type from the tracefs "
		    "format",
		    tracepoint_shape);
	sr_str tp = t_str(as.v[1], "content");
	size_t slashes = 0, cut = tp.n;
	for (size_t i = 0; i < tp.n; i++)
		if (tp.p[i] == '/') {
			if (slashes == 0)
				cut = i;
			slashes++;
		}
	sr_str cat = {tp.p, cut}, ev = cut < tp.n ? (sr_str){tp.p + cut + 1, tp.n - cut - 1} : t_s("");
	if (slashes != 1 || !t_tp_ident(cat) || !t_tp_ident(ev))
		BAD("the target of %S is a tracefs event `category/event` (two C identifiers and one `/`), got %q", tracepoint_shape, tp);
	const sr_node *hv = NULL;
	t_nodes els = t_arr(a, as.v[2], "elements");
	for (size_t i = 0; i < els.n; i++) {
		const sr_node *e = els.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !t_is(k, "SymbolNode") || !sr_eqc(t_str(k, "value"), "fields") || hv)
			BAD("the options of %S are exactly `fields:`", tracepoint_shape);
		hv = v;
	}
	if (!hv || !t_is(hv, "HashNode") || t_arr(a, hv, "elements").n == 0)
		BAD("%S needs `fields:` with a non-empty Hash literal of field name => [offset, :type]", tracepoint_shape);
	*r = (fe_root_decl){.name = t_str(as.v[0], "value"), .kind = t_s("tracepoint"), .pos = t_pos(c, n), .target = tp, .params_nil = 1,
			    .targs_nil = 1, .tfields_nil = 1};
	tp_seen s = {0};
	t_nodes he = t_arr(a, hv, "elements");
	for (size_t i = 0; i < he.n; i++) {
		const sr_node *e = he.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !t_is(k, "SymbolNode") || !v || !t_is(v, "ArrayNode"))
			BAD("each tracepoint field is `name: [offset, :type]` — a Symbol name and a two-element Array literal");
		sr_str name = t_str(k, "value");
		t_nodes fe = t_arr(a, v, "elements");
		if (fe.n == 2 && t_is(fe.v[0], "IntegerNode") && t_is(fe.v[1], "ArrayNode")) {
			fe_tp_field f;
			if (!tp_array_field(c, n, name, fe, &f))
				return 0;
			if (!t_tp_ident(name) || seen_name(&s, name) || seen_off(&s, f.offset))
				BAD("field %s at offset %d: field names are C identifiers and neither a name nor an offset appears twice", name,
				    f.offset);
			T_PUSH(s.names, s.n_names, name);
			T_PUSH(s.offs, s.n_offs, f.offset);
			T_PUSH(r->tfields, r->n_tfields, f);
			r->tfields_nil = 0;
			continue;
		}
		if (fe.n != 2 || !t_is(fe.v[0], "IntegerNode") || !t_is(fe.v[1], "SymbolNode"))
			BAD("field %s: write `%s: [offset, :type]` — an Integer literal offset and a type Symbol :i8 … :u64", name, name);
		sr_str ty = t_str(fe.v[1], "value");
		int64_t bits = 0;
		int sg;
		int ok = t_record_type(ty, &bits, &sg);
		if (sr_eqc(ty, "user_str") || sr_eqc(ty, "user_str_array")) {
			bits = 64;
			ok = 1;
		}
		if (!ok)
			BAD("field %s: the type is one of :i8 … :i64 / :u8 … :u64 (the format's size and signed) or :user_str (a `char *` "
			    "field — read with ctx.str_field), got :%s",
			    name, ty);
		int64_t o = 0;
		int fits = lit64(c, fe.v[0], &o);
		int64_t w = bits / 8;
		if (!fits || o < 8 || o % w != 0 || wrap_add(o, w) > TP_MAX_CTX)
			BAD("field %s: the offset is an Integer ≥ 8 (the first 8 bytes are not readable from BPF), a multiple of the field's "
			    "%d bytes, and offset + size ≤ %d",
			    name, w, (int64_t)TP_MAX_CTX);
		if (!t_tp_ident(name) || seen_name(&s, name) || seen_off(&s, o))
			BAD("field %s at offset %d: field names are C identifiers and neither a name nor an offset appears twice", name, o);
		T_PUSH(s.names, s.n_names, name);
		T_PUSH(s.offs, s.n_offs, o);
		/* Go: mutation("tpfield-shift") — the user path takes the plain offset */
		T_PUSH(r->tfields, r->n_tfields, ((fe_tp_field){name, o, ty, 0}));
		r->tfields_nil = 0;
	}
	return 1;
}

/* ---- uprobe.go ---- */
static const char uprobe_shape[] = "`BPF.uprobe :name, \"target/binary\", \"symbol\", params: {1 => :user_str, 2 => :i32}`";
static const char uretprobe_shape[] = "`BPF.uretprobe :name, \"target/binary\", \"symbol\", ret: :i64`";

/* reads the regular file at path: 1 and the contents; 0 when os.Stat fails or it is not regular; -1 when the read fails after a
 * successful stat (Go then prints the os error, whose text the C does not reproduce — a not-ported stop) */
static int read_regular(sr_str path, unsigned char **data, size_t *len)
{
	char *p = sr_alloc(path.n + 1);
	if (path.n > 0) /* an empty path may have a NULL p */
		memcpy(p, path.p, path.n);
	if (path.n > 0 && memchr(path.p, '\0', path.n))
		return 0; /* Go's os.Stat refuses a NUL byte (EINVAL) */
	struct stat st;
	if (stat(p, &st) != 0 || !S_ISREG(st.st_mode))
		return 0;
	FILE *f = fopen(p, "rb");
	if (!f)
		return -1;
	size_t cap = (size_t)st.st_size + 1, n = 0;
	unsigned char *b = malloc(cap);
	if (!b) {
		fclose(f);
		return -1;
	}
	for (;;) {
		if (n == cap) {
			unsigned char *nb = realloc(b, cap * 2);
			if (!nb) {
				free(b);
				fclose(f);
				return -1;
			}
			b = nb;
			cap *= 2;
		}
		size_t got = fread(b + n, 1, cap - n, f);
		n += got;
		if (got == 0)
			break;
	}
	int err = ferror(f);
	fclose(f);
	if (err) {
		free(b);
		return -1;
	}
	*data = b;
	*len = n;
	return 1;
}

int t_uprobe_decl(t_ctx *c, const sr_node *n, t_nodes as, fe_root_decl *r)
{
	const sr_ast *a = c->a;
	int ret = sr_eqc(node_name(n), "uretprobe");
	if (as.n != 4 || !t_is(as.v[0], "SymbolNode") || !t_is(as.v[1], "StringNode") || !t_is(as.v[2], "StringNode") ||
	    !t_is(as.v[3], "KeywordHashNode") || t_str(as.v[1], "content").n == 0 || t_str(as.v[2], "content").n == 0) {
		if (ret)
			BAD("a uretprobe program is declared as %S — a Symbol, the target binary's path and symbol as non-empty String "
			    "literals, and `ret:`",
			    uretprobe_shape);
		BAD("a uprobe program is declared as %S — a Symbol, the target binary's path and symbol as non-empty String literals, and "
		    "`params:`",
		    uprobe_shape);
	}
	sr_str path = t_str(as.v[1], "content");
	sr_str clean = fe_path_clean(path);
	sr_str elems[2] = {c->z->src_dir, clean};
	sr_str full = fe_path_join(elems, 2);
	int abs = path.n > 0 && path.p[0] == '/';
	if (abs) {
		if (!sr_eq(clean, path))
			BAD("the uprobe target %q must be a clean absolute path (no `.`, `..` or repeated `/`) or a path relative to the "
			    "source's directory — the build reads it and puts only its SHA-256 in the schema",
			    path);
		full = path;
	} else if (sr_eqc(clean, "..") || (clean.n >= 3 && memcmp(clean.p, "../", 3) == 0)) {
		BAD("the uprobe target %q must be a path relative to the source's directory that stays inside it (no `..` out of it) or a "
		    "clean absolute path — the build reads it and puts only its SHA-256 in the schema",
		    path);
	}
	unsigned char *data = NULL;
	size_t len = 0;
	int rr = read_regular(full, &data, &len);
	if (rr == 0)
		BAD("the uprobe target %q is not a readable regular file — the build needs it to compute binary_sha256", path);
	if (rr < 0) {
		fe_not_ported(c->z, "uprobe target read error after a successful stat (Go prints the os error text)");
		return 0;
	}
	char hex[65];
	bml_build_sha256_hex(data, len, hex);
	free(data);
	sr_str kind = node_name(n);
	*r = (fe_root_decl){.name = t_str(as.v[0], "value"), .kind = kind, .pos = t_pos(c, n), .target = t_str(as.v[2], "content"),
			    .binary_sha = sr_dup(hex, 64), .binary_path = full, .params_nil = 1, .targs_nil = 1, .tfields_nil = 1};
	if (abs)
		r->sys_target = path;
	if (ret) {
		const sr_node *rv = NULL;
		t_nodes els = t_arr(a, as.v[3], "elements");
		for (size_t i = 0; i < els.n; i++) {
			const sr_node *e = els.v[i];
			const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
			if (!t_is(e, "AssocNode") || !k || !t_is(k, "SymbolNode") || !sr_eqc(t_str(k, "value"), "ret") || rv)
				BAD("the options of %S are exactly `ret:`", uretprobe_shape);
			rv = v;
		}
		if (!rv || !t_is(rv, "SymbolNode"))
			BAD("%S needs `ret:` (a Symbol :i8 … :u64 — the kernel does not check it; the value is the return register cut to "
			    "this width)",
			    uretprobe_shape);
		int64_t b;
		int sg;
		if (!t_record_type(t_str(rv, "value"), &b, &sg))
			BAD("`ret:` of %S is one of :i8 … :i64 / :u8 … :u64", uretprobe_shape);
		r->ret = t_str(rv, "value");
		return 1;
	}
	const sr_node *pv = NULL;
	t_nodes els = t_arr(a, as.v[3], "elements");
	for (size_t i = 0; i < els.n; i++) {
		const sr_node *e = els.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !t_is(k, "SymbolNode") || !sr_eqc(t_str(k, "value"), "params") || pv)
			BAD("the options of %S are exactly `params:`", uprobe_shape);
		pv = v;
	}
	if (!pv || !t_is(pv, "HashNode"))
		BAD("%S needs `params:` with a Hash literal of argument number (1..6) => type", uprobe_shape);
	int seen[7] = {0};
	t_nodes pe = t_arr(a, pv, "elements");
	for (size_t i = 0; i < pe.n; i++) {
		const sr_node *e = pe.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !t_is(k, "IntegerNode"))
			BAD("each uprobe parameter is `n => :type` with n an Integer literal 1..6");
		int64_t pn;
		if (!lit64(c, k, &pn) || pn < 1 || pn > 6 || seen[pn])
			BAD("a uprobe parameter number is 1..6 (the x86_64 argument registers, 1-origin like the schema's n) and appears "
			    "once");
		sr_str ty = t_s("");
		if (v && t_is(v, "SymbolNode"))
			ty = t_str(v, "value");
		int64_t b;
		int sg;
		if (!t_record_type(ty, &b, &sg) && !sr_eqc(ty, "user_str") && !sr_eqc(ty, "ptr") && !sr_eqc(ty, "user_buf"))
			BAD("a uprobe parameter type is one of :i8 … :i64 / :u8 … :u64, :user_str (a `const char *` — read with "
			    "ctx.str_arg(n)), :ptr (a pointer's raw value as i64 — read with ctx.arg(n)) or :user_buf (a buffer — read with "
			    "ctx.buf_arg(n) in R.output_buf)");
		seen[pn] = 1;
		T_PUSH(r->params, r->n_params, ((fe_kparam){pn, ty}));
		r->params_nil = 0;
	}
	return 1;
}

/* ---- fmodret.go ---- */
int t_fmod_ret_decl(t_ctx *c, const sr_node *n, t_nodes as, fe_root_decl *r)
{
	const sr_ast *a = c->a;
	const char *shape = "`BPF.fmod_ret :name, \"kernel_function\", nargs: N, args: {0 => :i32}`";
	if (as.n != 3 || !t_is(as.v[0], "SymbolNode") || !t_is(as.v[1], "StringNode") || t_str(as.v[1], "content").n == 0 ||
	    !t_is(as.v[2], "KeywordHashNode"))
		BAD("a fmod_ret program is declared as %S — a Symbol, a non-empty String literal and `nargs:`", shape);
	*r = (fe_root_decl){.name = t_str(as.v[0], "value"), .kind = t_s("fmod_ret"), .pos = t_pos(c, n), .target = t_str(as.v[1], "content"),
			    .nargs = -1, .ret = t_s("i32"), .params_nil = 1, .targs_nil = 1, .tfields_nil = 1};
	const sr_node *hv = NULL;
	t_nodes els = t_arr(a, as.v[2], "elements");
	for (size_t i = 0; i < els.n; i++) {
		const sr_node *e = els.v[i];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !v || !t_is(k, "SymbolNode"))
			BAD("the options of %S are `nargs:` and `args:`", shape);
		sr_str kv = t_str(k, "value");
		if (sr_eqc(kv, "nargs")) {
			int64_t nv = 0;
			int fits = lit64(c, v, &nv); /* Go calls z.literal before testing the node type */
			if (!t_is(v, "IntegerNode") || !fits || nv < 0 || nv > 12 || r->nargs >= 0)
				BAD("`nargs:` of %S is the target function's argument count, an Integer literal 0..12, given once", shape);
			r->nargs = nv;
		} else if (sr_eqc(kv, "args")) {
			if (hv)
				BAD("`args:` of %S is given once", shape);
			hv = v;
		} else {
			BAD("the options of %S are `nargs:` and `args:` — the return type is i32", shape);
		}
	}
	if (r->nargs < 0)
		BAD("%S needs `nargs:` — the target function's argument count", shape);
	if (!hv)
		return 1;
#define ARGBAD(...)                                                                                                                \
	do {                                                                                                                       \
		t_add(c->z, FE_REJECTED, FE_SB033, t_pos(c, n), __VA_ARGS__);                                                      \
		return 0;                                                                                                          \
	} while (0)
	if (!t_is(hv, "HashNode") || t_arr(a, hv, "elements").n == 0)
		ARGBAD("`args:` of %S is a non-empty Hash literal of argument index => integer type", shape);
	int seen[13] = {0};
	t_nodes he = t_arr(a, hv, "elements");
	for (size_t j = 0; j < he.n; j++) {
		const sr_node *e = he.v[j];
		const sr_node *k = t_ref(a, e, "key"), *v = t_ref(a, e, "value");
		if (!t_is(e, "AssocNode") || !k || !t_is(k, "IntegerNode") || !v)
			ARGBAD("each fmod_ret argument is `i => :i32` with i an Integer literal");
		int64_t i = 0;
		if (!lit64(c, k, &i) || i < 0 || i >= r->nargs || seen[i])
			ARGBAD("a fmod_ret argument index is 0..nargs−1 (%d) and appears once", r->nargs - 1);
		seen[i] = 1;
		if (!t_is(v, "SymbolNode"))
			ARGBAD("argument %d: a fmod_ret argument is an integer type Symbol (:i8 … :u64) — bpf-mlir's fmod_ret reads integer "
			       "arguments only (IntArgs)",
			       i);
		int64_t b;
		int sg;
		if (!t_record_type(t_str(v, "value"), &b, &sg))
			ARGBAD("argument %d: an integer argument's type is one of :i8 … :i64 / :u8 … :u64", i);
		T_PUSH(r->targs, r->n_targs, ((fe_tp_arg){.idx = i, .type = t_str(v, "value")}));
		r->targs_nil = 0;
	}
#undef ARGBAD
	return 1;
}
