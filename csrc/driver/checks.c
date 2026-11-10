/* csrc/driver/checks.c - see checks.h. */
#include "checks.h"

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bml/build.h"
#include "jsonv.h"

/* ---- text ---- */

/* The length of the Unicode white-space rune at s (unicode.IsSpace), or 0. */
static size_t space_at(const unsigned char *s, size_t n)
{
	if (n >= 1 && (s[0] == ' ' || (s[0] >= '\t' && s[0] <= '\r')))
		return 1;
	if (n >= 2 && s[0] == 0xc2 && (s[1] == 0x85 || s[1] == 0xa0))
		return 2;
	if (n >= 3 && s[0] == 0xe1 && s[1] == 0x9a && s[2] == 0x80) /* U+1680 */
		return 3;
	if (n >= 3 && s[0] == 0xe2 && s[1] == 0x80 && ((s[2] >= 0x80 && s[2] <= 0x8a) || s[2] == 0xa8 || s[2] == 0xa9 || s[2] == 0xaf))
		return 3; /* U+2000..U+200A, U+2028, U+2029, U+202F */
	if (n >= 3 && s[0] == 0xe2 && s[1] == 0x81 && s[2] == 0x9f) /* U+205F */
		return 3;
	if (n >= 3 && s[0] == 0xe3 && s[1] == 0x80 && s[2] == 0x80) /* U+3000 */
		return 3;
	return 0;
}

/* The start of the white-space rune that ends s[0..n), or n when s does not end with one. */
static size_t space_end(const unsigned char *s, size_t n)
{
	for (size_t k = 1; k <= 3 && k <= n; k++)
		if (space_at(s + n - k, k) == k)
			return n - k;
	return n;
}

char *go_trim_space(const char *s, size_t n)
{
	const unsigned char *u = (const unsigned char *)s;
	size_t a = 0, k;
	while (a < n && (k = space_at(u + a, n - a)))
		a += k;
	size_t b = n;
	while (b > a) {
		size_t e = space_end(u + a, b - a);
		if (e == b - a)
			break;
		b = a + e;
	}
	return xstrndup(s + a, b - a);
}

/* `^loc\("([^"]+)":(\d+):(\d+)\): (.*)$` (toolchain.diagLoc). file excludes `/` when noslash (budgetMsg's `[^"/]+`). */
struct loc {
	char *file;
	long long line, col;
	const char *rest;
};

static int digits(const char **p, long long *v)
{
	const char *s = *p;
	long long x = 0;
	while (**p >= '0' && **p <= '9')
		x = x * 10 + (*(*p)++ - '0');
	*v = x;
	return *p > s;
}

static int match_loc(const char *line, int noslash, struct loc *l)
{
	if (strncmp(line, "loc(\"", 5))
		return 0;
	const char *p = line + 5, *f = p;
	while (*p && *p != '"') {
		if (noslash && *p == '/')
			return 0;
		p++;
	}
	if (*p != '"' || p == f)
		return 0;
	l->file = xstrndup(f, (size_t)(p - f));
	p++;
	if (*p++ != ':' || !digits(&p, &l->line) || *p++ != ':' || !digits(&p, &l->col) || strncmp(p, "): ", 3))
		return 0;
	l->rest = p + 3;
	return 1;
}

/* strings.Split into a list (no limit). */
static struct strv split(const char *s, size_t n, char sep)
{
	struct strv l = {0};
	size_t a = 0;
	for (size_t i = 0; i <= n; i++)
		if (i == n || s[i] == sep) {
			strv_push(&l, xstrndup(s + a, i - a));
			a = i + 1;
		}
	return l;
}

char *rewrite_locs(const char *output)
{
	size_t n = strlen(output);
	while (n > 0 && output[n - 1] == '\n')
		n--;
	struct strv lines = split(output, n, '\n');
	struct sb b = {0};
	for (size_t i = 0; i < lines.n; i++) {
		struct loc l;
		if (match_loc(lines.v[i], 0, &l) && !fp_is_abs(l.file)) {
			sb_printf(&b, "%s:%lld:%lld: ebpf-compile: %s\n", l.file, l.line, l.col, l.rest);
			continue;
		}
		sb_puts(&b, lines.v[i]);
		sb_putc(&b, '\n');
	}
	return sb_take(&b);
}

/* budgetMsg: loc("F":L:C): error: 'ebpf.loop' op (unrolling a body of .* is estimated at more than the limit of \d+ op\(s\)
 * this compiler supports)$, with F free of `"` and `/`. */
int unroll_budget(const char *stderr_text, struct diag *d)
{
	static const char head[] = "error: 'ebpf.loop' op ", body[] = "unrolling a body of ",
			  mid[] = " is estimated at more than the limit of ", tail[] = " op(s) this compiler supports";
	struct strv lines = split(stderr_text, strlen(stderr_text), '\n');
	for (size_t i = 0; i < lines.n; i++) {
		struct loc l;
		if (!match_loc(lines.v[i], 1, &l) || strncmp(l.rest, head, sizeof head - 1))
			continue;
		const char *m = l.rest + sizeof head - 1;
		size_t ml = strlen(m);
		if (ml < sizeof body - 1 + sizeof mid - 1 + 1 + sizeof tail - 1 || strncmp(m, body, sizeof body - 1) ||
		    strcmp(m + ml - (sizeof tail - 1), tail))
			continue;
		size_t e = ml - (sizeof tail - 1), s = e;
		while (s > 0 && m[s - 1] >= '0' && m[s - 1] <= '9')
			s--;
		if (s == e || s < sizeof body - 1 + sizeof mid - 1 || strncmp(m + s - (sizeof mid - 1), mid, sizeof mid - 1))
			continue;
		memset(d, 0, sizeof *d);
		d->verdict = V_REJECTED;
		d->code = "SB030";
		d->pos = (struct pos){l.file, l.line, l.col};
		d->msg = xasprintf("ebpf-compile: %s — the unrolled loop is too large for bpf-mlir: fewer iterations, a smaller body, or "
				   "split the work over two loops",
				   m);
		return 1;
	}
	return 0;
}

static const char compile_warning_fixes[] =
	" — known fixes (bpf-mlir): keep a constant default out of the index, e.g. put the ref.index inside the present region; "
	"leave room after a record array up to the next power of two";

static err_t unknown_output(const char *what, const char *line)
{
	char *q = go_quote(line, strlen(line));
	if (!q)
		not_ported("%%q of a non-ASCII ebpf-compile output line");
	return errf("ebpf-compile exited 0 with %s — a new output shape of ebpf-compile; update spinelbpf's reader: %s", what, q);
}

err_t add_compile_warnings(struct diags *ds, const char *so, const char *se)
{
	if (*so) {
		size_t n = strlen(so);
		while (n > 0 && so[n - 1] == '\n')
			n--;
		char *t = xstrndup(so, n);
		return unknown_output("output on stdout", t);
	}
	if (!*se)
		return NULL;
	size_t n = strlen(se);
	if (se[n - 1] == '\n')
		n--;
	struct strv lines = split(se, n, '\n');
	struct diags ws = {0};
	struct sb *msg = NULL;
	struct sb *msgs = xmalloc((lines.n ? lines.n : 1) * sizeof *msgs);
	for (size_t i = 0; i < lines.n; i++) {
		struct loc l;
		if (!match_loc(lines.v[i], 0, &l) || fp_is_abs(l.file))
			return unknown_output("a stderr line that is not loc(\"<relative file>\":L:C): warning|note: …", lines.v[i]);
		if (!strncmp(l.rest, "warning: ", 9)) {
			struct diag d = {.verdict = V_CONDITIONAL, .code = "SB021", .pos = {l.file, l.line, l.col}};
			diags_push(&ws, d);
			msg = &msgs[ws.n - 1];
			memset(msg, 0, sizeof *msg);
			sb_printf(msg, "ebpf-compile: %s", l.rest + 9);
		} else if (!strncmp(l.rest, "note: ", 6)) {
			if (!msg)
				return unknown_output("a note before any warning", lines.v[i]);
			sb_printf(msg, " (note at %s:%lld:%lld: %s)", l.file, l.line, l.col, l.rest + 6);
		} else {
			return unknown_output("a diagnostic that is neither a warning nor a note", lines.v[i]);
		}
	}
	for (size_t i = 0; i < ws.n; i++) {
		sb_puts(&msgs[i], compile_warning_fixes);
		ws.v[i].msg = sb_take(&msgs[i]);
		diags_push(ds, ws.v[i]);
	}
	return NULL;
}

/* ---- strictUnmarshal (requirements.DecodeStrictJSON, then the lenient partial read) ---- */

static err_t strict_doc(const char *data, size_t len, struct jv **out)
{
	struct bml_build_error e = {0};
	int rc = bml_build_json_check_any(data, len, &e);
	if (rc == BML_BUILD_NOMEM)
		return errf("out of memory");
	if (rc == BML_BUILD_UNSUPPORTED)
		not_ported("strict JSON reading: %s", e.text ? e.text : "");
	if (rc != BML_BUILD_OK)
		return errf("%s", e.text ? e.text : "unknown JSON error");
	*out = jv_parse(data, len);
	if (!*out)
		not_ported("a JSON document bml accepted but the driver's reader could not walk");
	return NULL;
}

static const struct jv *core_part(const struct jv *doc, const char *key)
{
	const struct jv *core = jv_obj(doc, "core", "schema");
	return core ? jv_arr(core, key, "schema.core") : NULL;
}

/* ---- checkMapSymbols / checkSchemaSHA ---- */

/* so_sym_type names an ELF symbol type as the struct_ops check prints it (Go: soSymType). */
static char *so_sym_type(int t)
{
	switch (t) {
	case STT_OBJECT: return xstrdup("OBJECT");
	case STT_FUNC: return xstrdup("FUNC");
	case STT_NOTYPE: return xstrdup("NOTYPE");
	case STT_SECTION: return xstrdup("SECTION");
	case STT_FILE: return xstrdup("FILE");
	case STT_COMMON: return xstrdup("COMMON");
	case STT_TLS: return xstrdup("TLS");
	}
	return xasprintf("type %d", t);
}

/* checkStructOpsSymbols (build.go), the struct_ops symbol rule: each struct_ops map of the schema is exactly one symbol of
 * its name, of any type, and that symbol is an OBJECT in .struct_ops.link; .struct_ops.link holds no other symbol of any type.
 * Go reads .symtab with debug/elf (Symbols: the null symbol left out); a section index of 0 is "(undefined)", one past the
 * section count "(special)". */
static err_t check_struct_ops_symbols(const char *elf, size_t elf_len, const struct strv *want)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return errf("reading the ELF for its struct_ops symbols: libelf: %s", elf_errmsg(-1));
	Elf *e = elf_memory((char *)elf, elf_len);
	size_t shstr, shnum;
	if (!e || elf_getshdrstrndx(e, &shstr) != 0 || elf_getshdrnum(e, &shnum) != 0)
		return errf("reading the ELF for its struct_ops symbols: %s", elf_errmsg(-1));
	struct strv names = {0}, types = {0}, secs = {0};
	for (Elf_Scn *scn = NULL; (scn = elf_nextscn(e, scn));) {
		GElf_Shdr sh;
		if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_SYMTAB)
			continue;
		Elf_Data *d = elf_getdata(scn, NULL);
		size_t n = sh.sh_entsize ? sh.sh_size / sh.sh_entsize : 0;
		for (size_t i = 1; d && i < n; i++) {
			GElf_Sym sym;
			if (!gelf_getsym(d, (int)i, &sym))
				continue;
			const char *nm = elf_strptr(e, sh.sh_link, sym.st_name);
			const char *sec = "(undefined)";
			if (sym.st_shndx >= shnum) {
				sec = "(special)";
			} else if (sym.st_shndx > 0) {
				GElf_Shdr ts;
				Elf_Scn *t = elf_getscn(e, sym.st_shndx);
				sec = t && gelf_getshdr(t, &ts) ? elf_strptr(e, shstr, ts.sh_name) : NULL;
			}
			if (!sec) {
				elf_end(e);
				return errf("reading the ELF symbols: a section name: %s", elf_errmsg(-1));
			}
			strv_push(&names, xstrdup(nm ? nm : ""));
			strv_push(&types, so_sym_type(GELF_ST_TYPE(sym.st_info)));
			strv_push(&secs, xstrdup(sec));
		}
		break; /* Go's Symbols reads the first SHT_SYMTAB */
	}
	elf_end(e);
	for (size_t w = 0; w < want->n; w++) {
		struct strv found = {0}; /* "<TYPE> in <section>" */
		size_t at = 0;
		for (size_t i = 0; i < names.n; i++)
			if (!strcmp(names.v[i], want->v[w])) {
				strv_push(&found, xasprintf("%s in %s", types.v[i], secs.v[i]));
				at = i;
			}
		if (found.n == 0)
			return errf("the struct_ops map %s is absent from the ELF (want one OBJECT symbol in .struct_ops.link)", want->v[w]);
		if (found.n > 1) {
			strv_sort(&found);
			size_t len = 1;
			for (size_t i = 0; i < found.n; i++)
				len += strlen(found.v[i]) + 2;
			char *j = xmalloc(len);
			j[0] = 0;
			for (size_t i = 0; i < found.n; i++) {
				if (i)
					strcat(j, ", ");
				strcat(j, found.v[i]);
			}
			return errf("the struct_ops map %s has %zu symbols (want one OBJECT symbol in .struct_ops.link): %s", want->v[w], found.n, j);
		}
		if (strcmp(types.v[at], "OBJECT"))
			return errf("the struct_ops map %s is a %s symbol in %s (want one OBJECT symbol in .struct_ops.link)", want->v[w], types.v[at], secs.v[at]);
		if (strcmp(secs.v[at], ".struct_ops.link"))
			return errf("the struct_ops map %s is in %s, not .struct_ops.link", want->v[w], secs.v[at]);
	}
	struct strv extra = {0};
	for (size_t i = 0; i < names.n; i++) {
		if (strcmp(secs.v[i], ".struct_ops.link"))
			continue;
		int declared = 0;
		for (size_t w = 0; w < want->n; w++)
			declared = declared || !strcmp(names.v[i], want->v[w]);
		if (declared)
			continue;
		if (!names.v[i][0]) {
			strv_push(&extra, xasprintf("an unnamed %s symbol", types.v[i]));
		} else {
			strv_push(&extra, xstrdup(names.v[i]));
		}
	}
	strv_sort(&extra);
	if (extra.n > 0)
		return errf(".struct_ops.link holds %s, which is not a struct_ops map of the schema", extra.v[0]);
	return NULL;
}

err_t check_map_symbols(const char *elf_path, const char *schema, size_t schema_len)
{
	char *elf;
	size_t elf_len;
	err_t e = read_file(elf_path, &elf, &elf_len);
	if (e)
		return e;
	char **names;
	size_t nn;
	struct bml_build_error be = {0};
	int rc = bml_build_map_symbols(elf, elf_len, &names, &nn, &be);
	if (rc == BML_BUILD_UNSUPPORTED)
		not_ported("layout.MapSymbols: %s", be.text ? be.text : "");
	if (rc != BML_BUILD_OK)
		return errf("reading the map symbols of %s: %s", elf_path, be.text ? be.text : "out of memory");
	struct jv *doc;
	if ((e = strict_doc(schema, schema_len, &doc)))
		return e;
	struct strv syms = {0}, want = {0}, so = {0};
	for (size_t i = 0; i < nn; i++)
		strv_push(&syms, names[i]);
	const struct jv *maps = core_part(doc, "maps");
	for (size_t i = 0; maps && i < maps->n; i++) {
		const char *sym = jv_str(&maps->items[i], "symbol", "schema.core.maps[]");
		if (!strcmp(jv_str(&maps->items[i], "kind", "schema.core.maps[]"), "struct_ops")) /* rule 2, below */
			strv_push(&so, xstrdup(sym));
		else
			strv_push(&want, xstrdup(sym));
	}
	strv_sort(&syms);
	strv_sort(&want);
	int same = syms.n == want.n;
	for (size_t i = 0; same && i < syms.n; i++)
		same = !strcmp(syms.v[i], want.v[i]);
	/* Go compares strings.Join(…, ","): two lists with a comma inside a name could join equal; map names have no comma */
	if (!same)
		return errf("the ELF's map symbols %s differ from the schema's maps %s", strv_go(&syms), strv_go(&want));
	return check_struct_ops_symbols(elf, elf_len, &so);
}

err_t check_schema_sha(const char *elf_path, const char *schema, size_t schema_len, char sha_out[65])
{
	char *elf;
	size_t elf_len;
	err_t e = read_file(elf_path, &elf, &elf_len);
	if (e)
		return e;
	char got[65];
	struct bml_build_error be = {0};
	int rc = bml_build_schema_sha256(elf, elf_len, got, &be);
	if (rc == BML_BUILD_UNSUPPORTED)
		not_ported("bindrt.Parse: %s", be.text ? be.text : "");
	if (rc != BML_BUILD_OK)
		return errf("reading the requirements of %s: %s", elf_path, be.text ? be.text : "out of memory");
	sha256_hex(schema, schema_len, sha_out);
	if (strcmp(got, sha_out))
		return errf("the ELF's requirements carry schema sha256 %s but the schema file is %s", got, sha_out);
	return NULL;
}

/* ---- checkRecordsTable ---- */

/* A small string map with Go's overwrite-on-set semantics. */
struct smap {
	struct strv k, v;
};

static char **smap_slot(struct smap *m, const char *k)
{
	for (size_t i = 0; i < m->k.n; i++)
		if (!strcmp(m->k.v[i], k))
			return &m->v.v[i];
	return NULL;
}

static void smap_set(struct smap *m, const char *k, char *v)
{
	char **s = smap_slot(m, k);
	if (s) {
		*s = v;
		return;
	}
	strv_push(&m->k, xstrdup(k));
	strv_push(&m->v, v);
}

static const char *smap_get(struct smap *m, const char *k)
{
	char **s = smap_slot(m, k);
	return s ? *s : "";
}

/* json.Unmarshal(raw, &struct{Kind, Symbol string}) == nil && Kind == "record_ref": the symbol, or NULL. */
static const char *record_ref(const struct jv *v)
{
	if (!v || v->t == JV_NULL)
		return NULL; /* absent: Unmarshal of empty input fails; null: Kind stays "" */
	if (v->t != JV_OBJ)
		return NULL;
	const struct jv *k = jv_get(v, "kind"), *s = jv_get(v, "symbol");
	if ((k && k->t != JV_STR && k->t != JV_NULL) || (s && s->t != JV_STR && s->t != JV_NULL))
		return NULL;
	if (!k || k->t != JV_STR || strcmp(k->s, "record_ref"))
		return NULL;
	return s && s->t == JV_STR ? s->s : "";
}

static void want_line(struct smap *want, const struct jv *records, const char *row, const char *sym)
{
	for (size_t i = 0; records && i < records->n; i++) {
		const struct jv *r = &records->items[i];
		if (strcmp(jv_str(r, "symbol", "schema.core.records[]"), sym))
			continue;
		struct sb l = {0};
		sb_printf(&l, "%s|%s|size=%lld;", row, jv_str(r, "symbol", "schema.core.records[]"),
			  (long long)jv_int(r, "size", "schema.core.records[]"));
		const struct jv *fields = jv_arr(r, "fields", "schema.core.records[]");
		for (size_t j = 0; fields && j < fields->n; j++) {
			const struct jv *f = &fields->items[j];
			const char *where = "schema.core.records[].fields[]";
			const struct jv *t = jv_obj(f, "type", where);
			const char *name = jv_str(f, "name", where);
			long long off = jv_int(f, "offset", where);
			const char *kind = jv_str(t, "kind", "type");
			if (!strcmp(kind, "array")) {
				const struct jv *el = jv_obj(t, "element", "type");
				const char *ts = jv_bool(el, "signed", "type.element") ? "i" : "u";
				long long bits = jv_int(el, "bits", "type.element"), count = jv_int(t, "count", "type");
				for (long long k = 0; k < count; k++)
					sb_printf(&l, "%s[%lld]:%lld:%s%lld;", name, k, off + k * bits / 8, ts, bits);
				continue;
			}
			sb_printf(&l, "%s:%lld:%s%lld;", name, off, jv_bool(t, "signed", "type") ? "i" : "u",
				  (long long)jv_int(t, "bits", "type"));
		}
		smap_set(want, row, sb_take(&l));
	}
}

err_t check_records_table(const char *schema, size_t schema_len, const char *table)
{
	struct jv *doc;
	err_t e = strict_doc(schema, schema_len, &doc);
	if (e)
		return errf("reading the schema for the record table: %s", e);
	const struct jv *records = core_part(doc, "records"), *globals = core_part(doc, "globals"), *maps = core_part(doc, "maps");
	struct smap want = {0}, wantG = {0}, got = {0};
	struct strv gotG = {0};
	for (size_t i = 0; maps && i < maps->n; i++) {
		const struct jv *m = &maps->items[i];
		const char *mkind = jv_str(m, "kind", "schema.core.maps[]"), *msym = jv_str(m, "symbol", "schema.core.maps[]");
		const char *ks = NULL;
		if (strcmp(mkind, "ringbuf") && (ks = record_ref(jv_get(m, "key"))))
			want_line(&want, records, xasprintf("%s:key", msym), ks);
		const char *vs;
		if (!strcmp(mkind, "ringbuf"))
			vs = jv_str(m, "record", "schema.core.maps[]");
		else if (!(vs = record_ref(jv_get(m, "value"))))
			continue;
		want_line(&want, records, msym, vs);
	}
	for (size_t i = 0; globals && i < globals->n; i++) {
		if (!strcmp(jv_str(&globals->items[i], "section", "schema.core.globals[]"), "data"))
			continue; /* a .data record global (BPF::ExitInfo) has no G row */
		const struct jv *g = &globals->items[i], *t = jv_obj(g, "type", "schema.core.globals[]");
		const char *name = jv_str(g, "name", "schema.core.globals[]");
		smap_set(&wantG, name, xasprintf("G|%s|%s|%s%lld", name, jv_str(g, "section", "schema.core.globals[]"),
						 jv_bool(t, "signed", "type") ? "i" : "u", (long long)jv_int(t, "bits", "type")));
	}
	size_t tn = strlen(table);
	if (tn > 0 && table[tn - 1] == '\n')
		tn--;
	struct strv lines = split(table, tn, '\n');
	for (size_t i = 0; i < lines.n; i++) {
		const char *l = lines.v[i];
		if (!*l)
			continue;
		if (!strncmp(l, "G|", 2)) {
			struct strv p = split(l, strlen(l), '|');
			int bad = p.n != 5;
			if (!bad) {
				char *j = xasprintf("%s|%s|%s|%s", p.v[0], p.v[1], p.v[2], p.v[3]);
				int seen = 0;
				for (size_t k = 0; k < gotG.n; k++)
					seen |= !strcmp(gotG.v[k], p.v[1]);
				bad = (strcmp(p.v[4], "0") && strcmp(p.v[4], "1")) || (!strcmp(p.v[4], "1") && strcmp(p.v[2], "rodata")) ||
				      strcmp(smap_get(&wantG, p.v[1]), j) || seen;
			}
			if (bad) {
				const char *w = smap_get(&wantG, p.v[1]);
				char *ql = go_quote(l, strlen(l)), *qw = go_quote(w, strlen(w));
				if (!ql || !qw)
					not_ported("%%q of a non-ASCII records table row");
				return errf("the embedded global row %s does not match the schema's core.globals (%s)", ql, qw);
			}
			strv_push(&gotG, p.v[1]);
			continue;
		}
		const char *b1 = strchr(l, '|'), *b2 = b1 ? strchr(b1 + 1, '|') : NULL;
		if (!b2) {
			char *q = go_quote(l, strlen(l));
			if (!q)
				not_ported("%%q of a non-ASCII records table line");
			return errf("the record layout table has a malformed line %s", q);
		}
		char *row = xstrndup(l, (size_t)(b1 - l));
		struct sb named = {0};
		sb_put(&named, l, (size_t)(b2 - l) + 1);
		const char *rest = b2 + 1;
		size_t rl = strlen(rest);
		if (rl > 0 && rest[rl - 1] == ';')
			rl--;
		struct strv xs = split(rest, rl, ';');
		for (size_t k = 0; k < xs.n; k++) {
			if (k > 0 && !strncmp(xs.v[k], "_pad", 4))
				continue;
			sb_puts(&named, xs.v[k]);
			sb_putc(&named, ';');
		}
		smap_set(&got, row, sb_take(&named));
	}
	if (gotG.n != wantG.k.n)
		return errf("the embedded table has %zu global rows but the schema has %zu globals", gotG.n, wantG.k.n);
	if (got.k.n != want.k.n)
		return errf("the record layout table has %zu record maps but the schema has %zu — the table and the schema come from "
			    "different builds",
			    got.k.n, want.k.n);
	/* Go ranges over a map here (random order); with more than one differing map, Go may name another one */
	for (size_t i = 0; i < want.k.n; i++) {
		const char *g = smap_get(&got, want.k.v[i]);
		if (strcmp(g, want.v.v[i]))
			return errf("the record layout table differs from the schema for map %s:\n  table:  %s\n  schema: %s", want.k.v[i], g,
				    want.v.v[i]);
	}
	return NULL;
}

/* ---- CheckNeeded ---- */

err_t check_needed(const char *exe, const char *allow_path)
{
	char *data;
	size_t len;
	err_t e = read_file(allow_path, &data, &len);
	if (e)
		return e;
	struct strv allow = {0};
	struct strv lines = split(data, len, '\n');
	for (size_t i = 0; i < lines.n; i++) {
		char *t = go_trim_space(lines.v[i], strlen(lines.v[i]));
		if (*t && *t != '#')
			strv_push(&allow, t);
	}
	if (elf_version(EV_CURRENT) == EV_NONE)
		not_ported("libelf: %s", elf_errmsg(-1));
	int fd = open(exe, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return path_error("open", exe, errno);
	Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf || elf_kind(elf) != ELF_K_ELF)
		not_ported("reading %s as ELF with libelf (Go's debug/elf error texts are not ported)", exe);
	struct strv needed = {0}, runpath = {0}, rpath = {0};
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr sh;
		if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_DYNAMIC)
			continue;
		Elf_Data *d = elf_getdata(scn, NULL);
		size_t n = sh.sh_entsize ? sh.sh_size / sh.sh_entsize : 0;
		for (size_t i = 0; d && i < n; i++) {
			GElf_Dyn dyn;
			if (!gelf_getdyn(d, (int)i, &dyn))
				break;
			if (dyn.d_tag == DT_NULL)
				break;
			struct strv *to = dyn.d_tag == DT_NEEDED ? &needed : dyn.d_tag == DT_RUNPATH ? &runpath : dyn.d_tag == DT_RPATH ? &rpath : NULL;
			if (!to)
				continue;
			const char *s = elf_strptr(elf, sh.sh_link, dyn.d_un.d_val);
			strv_push(to, xstrdup(s ? s : ""));
		}
	}
	elf_end(elf);
	close(fd);
	struct strv bad = {0};
	for (size_t i = 0; i < needed.n; i++) {
		int ok = 0;
		for (size_t k = 0; k < allow.n; k++)
			ok |= !strcmp(allow.v[k], needed.v[i]);
		if (!ok)
			strv_push(&bad, needed.v[i]);
	}
	if (bad.n > 0)
		return errf("%s needs shared libraries outside packaging/needed.allow: %s (all: %s)", exe, strv_go(&bad), strv_go(&needed));
	if (runpath.n > 0)
		return errf("%s has DT_RUNPATH %s — the executable must not depend on a search path", exe, strv_go(&runpath));
	if (rpath.n > 0)
		return errf("%s has DT_RPATH %s — the executable must not depend on a search path", exe, strv_go(&rpath));
	return NULL;
}

/* ---- UprobeBuildCheckFiles ---- */

/* internal/frontend/uprobecheck.go UprobeBuildKinds and UprobeBuildIgnored. A gate test compares these with Go's. */
static const char *const build_kinds[] = {
	"binary", "binary_unknown", "uprobe_symbol", "uprobearg", "uprobearg_unknown", "uprobearg_abi", "uprobearg_abi_unknown",
	"uretprobe_abi", "uretprobe_abi_unknown", "usdt_probe", "usdtarg", "usdtarg_unknown", "uprobe_debug_build_id",
	"uprobe_debug_crc", NULL,
};
static const char *const build_ignored[] = {
	"arena_loader", "arena_loader_unknown", "attach_netkit_unknown", "coreenum", "coreenum_unknown", "datakptr_loader",
	"datakptr_loader_unknown", "enumval", "enumval_unknown", "fibflags", "fibflags_unknown", "funcret", "funcret_unknown",
	"helper_target", "helper_target_unknown", "kconfig", "kconfig_loader", "kconfig_loader_unknown", "kconfig_type",
	"kconfig_unknown", "kstructsize", "kstructsize_unknown", "ksymvar", "ksymvar_unknown", "sleepable_type",
	"sleepable_type_unknown", "typed_ksym_loader", "typed_ksym_loader_unknown", "program_type", "helper", "helper_unknown",
	"attach", "attach_tcx_unknown", "retsig_unknown", "farg", "farg_unknown", "attach_func_unknown", "arg_nullable_unknown",
	"arg_nullable", "arg_nullable_mark_unknown", "kfield", "attach_unknown", "kfield_unknown", "btf_feature",
	"btf_feature_unknown", "btf_rewrite", "arg_tag", "arg_tag_unknown", "map_type", "arch", "arch_unknown", "ctxfield",
	"ctxfield_unknown", "attach_symbol_unknown", "attach_alias", "attach_alias_unknown", "kprobearg", "kprobearg_unknown",
	"map_field", "map_field_unknown", "attach_target", "attach_target_unknown", "attach_type", "attach_type_unknown",
	"ctx_access", "ctx_access_unknown", "ext_target", "ext_target_unknown", "kfunc_allowed", "kfunc_allowed_unknown",
	"kfunc_sig", "kfunc_sig_unknown", "structop", "structop_unknown", "sysarg", "sysarg_unknown", "tpfield",
	"tpfield_unknown", "fsession_loader", "fsession_loader_unknown", "ksyscall_loader", "ksyscall_loader_unknown",
	"lsm_cgroup_loader", "lsm_cgroup_loader_unknown", "usdt_loader", "usdt_loader_unknown", NULL,
};

static int in(const char *const *set, const char *s)
{
	for (; *set; set++)
		if (!strcmp(*set, s))
			return 1;
	return 0;
}

/* The tables, for the gate's comparison with Go (driver_tool). */
const char *const *uprobe_build_kinds(void) { return build_kinds; }
const char *const *uprobe_build_ignored(void) { return build_ignored; }

err_t uprobe_build_check(const char *elf, size_t elf_len, const struct uprobe_target *t, size_t n, struct diags *refused)
{
	if (n == 0)
		return NULL;
	/* bindrt.Parse first: its failure has its own wrapping in Go */
	char sha[65];
	struct bml_build_error be = {0};
	int rc = bml_build_schema_sha256(elf, elf_len, sha, &be);
	if (rc == BML_BUILD_UNSUPPORTED)
		not_ported("bindrt.Parse: %s", be.text ? be.text : "");
	if (rc != BML_BUILD_OK)
		return errf("the build-time uprobe check could not read the ELF: %s", be.text ? be.text : "out of memory");
	struct bml_build_target *tg = xmalloc(n * sizeof *tg);
	for (size_t i = 0; i < n; i++) {
		char *data = NULL;
		size_t len = 0;
		err_t e = read_file(t[i].path, &data, &len);
		tg[i] = (struct bml_build_target){t[i].program, e ? NULL : data, len, e};
	}
	struct bml_build_unmet *us = NULL;
	size_t nu = 0;
	memset(&be, 0, sizeof be);
	rc = bml_build_check_offline(elf, elf_len, tg, n, "/usr/lib/debug", &us, &nu, &be);
	if (rc == BML_BUILD_UNSUPPORTED)
		not_ported("bindrt.CheckTarget: %s", be.text ? be.text : "");
	if (rc != BML_BUILD_OK)
		return errf("the build-time uprobe check failed: %s", be.text ? be.text : "out of memory");
	struct strv order = {0};
	struct sb *lines = xmalloc((nu ? nu : 1) * sizeof *lines);
	memset(lines, 0, (nu ? nu : 1) * sizeof *lines);
	for (size_t i = 0; i < nu; i++) {
		if (in(build_ignored, us[i].kind))
			continue;
		size_t k = 0;
		while (k < order.n && strcmp(order.v[k], us[i].program))
			k++;
		if (k == order.n)
			strv_push(&order, us[i].program);
		if (lines[k].n)
			sb_puts(&lines[k], "; ");
		sb_printf(&lines[k], "%s %s: %s", us[i].kind, us[i].name, us[i].detail);
		if (!in(build_kinds, us[i].kind))
			sb_puts(&lines[k], " (an Unmet kind the build-time check does not classify — stopping, fail closed; classify it in "
					   "UprobeBuildKinds or UprobeBuildIgnored)");
	}
	for (size_t k = 0; k < order.n; k++) {
		struct pos p = {"", 0, 0};
		for (size_t i = 0; i < n; i++)
			if (!strcmp(t[i].program, order.v[k]))
				p = t[i].decl;
		struct diag d = {.verdict = V_REJECTED, .code = "SB032", .pos = p};
		d.msg = xasprintf("the uprobe target fails bpf-mlir's check before load: %s (the build checks the file it read; the load "
				  "checks the running target again)",
				  lines[k].p ? lines[k].p : "");
		diags_push(refused, d);
	}
	return NULL;
}
