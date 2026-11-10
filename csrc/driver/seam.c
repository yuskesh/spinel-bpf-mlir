/* csrc/driver/seam.c - see seam.h. Messages equal seam.go's ("seam: …"). */
#include "seam.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bml/build.h"
#include "jsonv.h"

static err_t seam_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static err_t seam_err(const char *fmt, ...)
{
	struct sb b = {0};
	sb_puts(&b, "seam: ");
	va_list ap;
	va_start(ap, fmt);
	sb_vprintf(&b, fmt, ap);
	va_end(ap);
	return sb_take(&b);
}

static char *q(const char *s)
{
	char *r = go_quote(s, strlen(s));
	if (!r)
		not_ported("%%q of non-ASCII text in a seam manifest");
	return r;
}

static int is_hex(const char *s, size_t n)
{
	if (strlen(s) != n)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
			return 0;
	return 1;
}

/* requireKeys: raw must be a JSON object (null counts as one without keys, as Unmarshal into a map) holding every key, exactly. */
static err_t require_keys(const struct jv *raw, const char *where, const char *const *keys)
{
	if (!raw)
		return seam_err("%s is not a JSON object: unexpected end of JSON input", where);
	if (raw->t != JV_OBJ && raw->t != JV_NULL)
		not_ported("requireKeys on a %s that is not an object or null (json.Unmarshal's type error text)", where);
	for (; *keys; keys++) {
		int found = 0;
		for (size_t i = 0; raw->t == JV_OBJ && i < raw->n; i++)
			found |= !strcmp(raw->keys[i], *keys);
		if (!found)
			return seam_err("%s has no key %s", where, q(*keys));
	}
	return NULL;
}

/* A raw member with exactly this key (Go's map[string]json.RawMessage lookup), or NULL. The last one wins (duplicates were
 * already refused by the strict reading). */
static const struct jv *raw_get(const struct jv *o, const char *key)
{
	const struct jv *hit = NULL;
	for (size_t i = 0; o && o->t == JV_OBJ && i < o->n; i++)
		if (!strcmp(o->keys[i], key))
			hit = &o->items[i];
	return hit;
}

/* ---- shapes of seam.go's types for the strict reading ---- */

static const struct bml_build_shape s_str = {BML_BUILD_SHAPE_STRING, 0, NULL, NULL, 0};
static const struct bml_build_shape s_int = {BML_BUILD_SHAPE_INT, 64, NULL, NULL, 0};
static const struct bml_build_shape s_bool = {BML_BUILD_SHAPE_BOOL, 0, NULL, NULL, 0};
static const struct bml_build_field f_file[] = {{"path", &s_str}, {"sha256", &s_str}};
static const struct bml_build_shape s_file = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_file, 2};
static const struct bml_build_field f_spinel[] = {
	{"commit", &s_str}, {"producer_revision", &s_str}, {"producer_source", &s_str}, {"binary_sha256", &s_str}};
static const struct bml_build_shape s_spinel = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_spinel, 4};
static const struct bml_build_field f_consumer[] = {{"commit", &s_str}, {"dirty", &s_bool}};
static const struct bml_build_shape s_consumer = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_consumer, 2};
static const struct bml_build_field f_bpf[] = {{"commit", &s_str}};
static const struct bml_build_shape s_bpf = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_bpf, 1};
static const struct bml_build_field f_pins[] = {{"spinel", &s_spinel}, {"consumer", &s_consumer}, {"bpf_mlir", &s_bpf}};
static const struct bml_build_shape s_pins = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_pins, 3};
static const struct bml_build_field f_result[] = {{"rc", &s_int}, {"domain_produced", &s_bool}, {"failure_stage", &s_str}};
static const struct bml_build_shape s_result = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_result, 3};
static const struct bml_build_shape s_outputs = {BML_BUILD_SHAPE_MAP, 0, &s_file, NULL, 0};
static const struct bml_build_field f_manifest[] = {{"version", &s_int},     {"source", &s_file}, {"facts", &s_file},
						    {"execution", &s_str},   {"pins", &s_pins},   {"result", &s_result},
						    {"outputs", &s_outputs}};
static const struct bml_build_shape s_manifest = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_manifest, 7};

static const struct bml_build_field f_decl[] = {{"file", &s_str}, {"line", &s_int}, {"col", &s_int}};
static const struct bml_build_shape s_decl = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_decl, 3};
static const struct bml_build_field f_prog[] = {{"name", &s_str}, {"kind", &s_str}, {"binary_path", &s_str}, {"decl", &s_decl}};
static const struct bml_build_shape s_prog = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_prog, 4};
static const struct bml_build_shape s_progs = {BML_BUILD_SHAPE_ARRAY, 0, &s_prog, NULL, 0};
static const struct bml_build_field f_targets[] = {{"version", &s_int}, {"programs", &s_progs}};
static const struct bml_build_shape s_targets = {BML_BUILD_SHAPE_STRUCT, 0, NULL, f_targets, 2};

/* ---- tree reads (Go's zero values for absent or null members) ---- */

static const struct bml_build_json_node *node(const struct bml_build_json_node *o, const char *key)
{
	if (!o || bml_build_json_type(o) != BML_BUILD_JSON_OBJECT)
		return NULL;
	const struct bml_build_json_node *v = bml_build_json_get(o, key, strlen(key));
	return v && bml_build_json_type(v) != BML_BUILD_JSON_NULL ? v : NULL;
}

static char *nstr(const struct bml_build_json_node *o, const char *key)
{
	const struct bml_build_json_node *v = node(o, key);
	size_t l;
	const char *s = v ? bml_build_json_string_value(v, &l) : NULL;
	return s ? xstrndup(s, l) : xstrdup("");
}

static long long nint(const struct bml_build_json_node *o, const char *key)
{
	const struct bml_build_json_node *v = node(o, key);
	int64_t x = 0;
	if (v)
		bml_build_json_int64(v, &x);
	return x;
}

static int nbool(const struct bml_build_json_node *o, const char *key)
{
	const struct bml_build_json_node *v = node(o, key);
	return v ? bml_build_json_bool(v) : 0;
}

static err_t decode(const char *data, size_t len, const struct bml_build_shape *shape, struct bml_build_json **doc)
{
	struct bml_build_error e = {0};
	int rc = bml_build_json_decode(data, len, shape, doc, &e);
	if (rc == BML_BUILD_NOMEM)
		return errf("out of memory");
	if (rc == BML_BUILD_UNSUPPORTED && !strcmp(e.rule, "unknown_key") && e.detail) {
		/* Go's json.Decoder reads the whole top-level value before it decodes, so its InputOffset for the first unknown
		 * field is the end of that value: the length without trailing white space (the scan step already refused other
		 * trailing data). Measured on go1.27.0; TestE175Seam compares it with Go. */
		size_t end = len;
		while (end > 0 && (data[end - 1] == ' ' || data[end - 1] == '\t' || data[end - 1] == '\n' || data[end - 1] == '\r'))
			end--;
		return errf("json: unknown_key at byte %zu: %s", end, e.detail);
	}
	if (rc == BML_BUILD_UNSUPPORTED)
		not_ported("strict JSON reading: %s", e.text ? e.text : "");
	if (rc != BML_BUILD_OK)
		return errf("%s", e.text ? e.text : "unknown JSON error");
	return NULL;
}

/* ---- readSeamManifest ---- */

struct manifest {
	char *source_sha, *execution, *producer_source, *bpf_commit;
	int has_facts, has_binary, domain_produced;
	char *facts_sha, *binary_sha, *failure_stage; /* failure_stage NULL when absent or null */
	long long version, rc;
	struct strv out_keys, out_shas;
};

static err_t read_manifest(const char *path, struct manifest *m, char **bytes, size_t *blen)
{
	char *b;
	size_t n;
	err_t e = read_file(path, &b, &n);
	if (e)
		return seam_err("reading the inspection manifest: %s", e);
	struct bml_build_json *doc;
	if ((e = decode(b, n, &s_manifest, &doc)))
		return seam_err("%s: %s", path, e);
	const struct bml_build_json_node *top = bml_build_json_root(doc);
	m->version = nint(top, "version");
	if (m->version != 1)
		return seam_err("%s: manifest version %lld (this spinelbpf reads version 1)", path, m->version);
	struct jv *raw = jv_parse(b, n);
	if (!raw)
		not_ported("a manifest bml accepted but the driver's reader could not walk");
	static const char *const k_top[] = {"version", "source", "facts", "execution", "pins", "result", "outputs", NULL};
	static const char *const k_source[] = {"path", "sha256", NULL};
	static const char *const k_pins[] = {"spinel", "consumer", "bpf_mlir", NULL};
	static const char *const k_result[] = {"rc", "domain_produced", NULL};
	if ((e = require_keys(raw, "the manifest", k_top)) || (e = require_keys(raw_get(raw, "source"), "source", k_source)) ||
	    (e = require_keys(raw_get(raw, "pins"), "pins", k_pins)) || (e = require_keys(raw_get(raw, "result"), "result", k_result)))
		return e;
	/* Go ranges over a map of the three pins here (random order); C checks spinel, consumer, bpf_mlir */
	static const char *const k_spinel[] = {"commit", "producer_revision", "producer_source", NULL};
	static const char *const k_consumer[] = {"commit", "dirty", NULL};
	static const char *const k_bpf[] = {"commit", NULL};
	const struct jv *pins = raw_get(raw, "pins");
	if ((e = require_keys(raw_get(pins, "spinel"), "pins.spinel", k_spinel)) ||
	    (e = require_keys(raw_get(pins, "consumer"), "pins.consumer", k_consumer)) ||
	    (e = require_keys(raw_get(pins, "bpf_mlir"), "pins.bpf_mlir", k_bpf)))
		return e;
	const struct bml_build_json_node *src = node(top, "source"), *facts = node(top, "facts"), *pn = node(top, "pins"),
					 *sp = node(pn, "spinel"), *res = node(top, "result"), *outs = node(top, "outputs");
	m->source_sha = nstr(src, "sha256");
	m->execution = nstr(top, "execution");
	m->has_facts = facts != NULL;
	m->facts_sha = nstr(facts, "sha256");
	m->producer_source = nstr(sp, "producer_source");
	m->has_binary = node(sp, "binary_sha256") != NULL;
	m->binary_sha = nstr(sp, "binary_sha256");
	m->bpf_commit = nstr(node(pn, "bpf_mlir"), "commit");
	m->rc = nint(res, "rc");
	m->domain_produced = nbool(res, "domain_produced");
	m->failure_stage = node(res, "failure_stage") ? nstr(res, "failure_stage") : NULL;
	for (size_t i = 0; outs && i < bml_build_json_count(outs); i++) {
		size_t kl;
		const struct bml_build_json_node *v;
		const char *k = bml_build_json_member(outs, i, &kl, &v);
		strv_push(&m->out_keys, xstrndup(k, kl));
		strv_push(&m->out_shas, nstr(v, "sha256"));
	}
	if (!is_hex(m->source_sha, 64))
		return seam_err("source.sha256 %s is not 64 hex digits", q(m->source_sha));
	if (!strcmp(m->execution, "consumer")) {
		if (!m->has_facts || !is_hex(m->facts_sha, 64))
			return seam_err("execution consumer needs facts {path, sha256} with a 64-hex sha256");
		if (strcmp(m->producer_source, "facts") || m->has_binary)
			return seam_err("execution consumer needs pins.spinel.producer_source \"facts\" and no binary_sha256, got %s",
					q(m->producer_source));
	} else if (!strcmp(m->execution, "source_pipeline")) {
		if (m->has_facts)
			return seam_err("execution source_pipeline needs facts null");
		if (strcmp(m->producer_source, "metadata") || !m->has_binary || !is_hex(m->binary_sha, 64))
			return seam_err("execution source_pipeline needs pins.spinel.producer_source \"metadata\" with a 64-hex binary_sha256");
	} else {
		return seam_err("unknown execution %s (consumer or source_pipeline)", q(m->execution));
	}
	if (!is_hex(m->bpf_commit, 40))
		return seam_err("pins.bpf_mlir.commit %s is not a 40-hex commit", q(m->bpf_commit));
	/* Go ranges over the outputs map (random order); C checks them in the manifest's order */
	for (size_t i = 0; i < m->out_keys.n; i++)
		if (!is_hex(m->out_shas.v[i], 64))
			return seam_err("outputs.%s.sha256 %s is not 64 hex digits", m->out_keys.v[i], q(m->out_shas.v[i]));
	bml_build_json_free(doc);
	*bytes = b;
	*blen = n;
	return NULL;
}

/* ---- readSeam ---- */

static const struct {
	const char *key;
	int inspect;
	const char *ext;
} outputs[] = {
	{"mlir", 0, ".mlir"}, {"schema", 0, ".schema.json"}, {"maps", 0, ".maps.json"},
	{"records", 0, ".records.txt"}, {"uprobe_targets", 0, ".uprobe_targets.json"}, {"domain", 1, ".domain.json"},
};
#define N_OUTPUTS (sizeof outputs / sizeof outputs[0])

static int records_ok(const char *r, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		char c = r[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr("_|=:;[]\n", c) != NULL) ||
		    c == 0)
			return 0;
	}
	return 1;
}

static int pos_eq(const struct pos *a, const struct pos *b)
{
	return !strcmp(a->file, b->file) && a->line == b->line && a->col == b->col;
}

static err_t seam_uprobes(const char *b, size_t n, const struct roots *roots, struct seam_input *in)
{
	struct bml_build_json *doc;
	err_t e = decode(b, n, &s_targets, &doc);
	if (e)
		return seam_err("outputs.uprobe_targets: %s", e);
	struct jv *raw = jv_parse(b, n);
	if (!raw)
		not_ported("uprobe_targets bml accepted but the driver's reader could not walk");
	static const char *const k[] = {"version", "programs", NULL};
	if ((e = require_keys(raw, "uprobe_targets", k)))
		return e;
	const struct bml_build_json_node *top = bml_build_json_root(doc);
	long long version = nint(top, "version");
	if (version != 1)
		return seam_err("outputs.uprobe_targets: version %lld (this spinelbpf reads version 1)", version);
	const struct bml_build_json_node *progs = node(top, "programs");
	size_t np = progs ? bml_build_json_count(progs) : 0;
	in->uprobes = xmalloc((np ? np : 1) * sizeof *in->uprobes);
	for (size_t i = 0; i < np; i++) {
		const struct bml_build_json_node *p = bml_build_json_index(progs, i), *d = node(p, "decl");
		char *name = nstr(p, "name"), *kind = nstr(p, "kind"), *bin = nstr(p, "binary_path");
		struct pos pos = {nstr(d, "file"), nint(d, "line"), nint(d, "col")};
		const struct root *r = NULL;
		for (size_t k2 = 0; k2 < roots->n; k2++)
			if ((!strcmp(roots->v[k2].kind, "uprobe") || !strcmp(roots->v[k2].kind, "uretprobe")) && !strcmp(roots->v[k2].name, name))
				r = &roots->v[k2]; /* Go's map: the last root of that name */
		if (!r || strcmp(r->kind, kind) || !pos_eq(&r->decl, &pos) || !*bin)
			return seam_err("outputs.uprobe_targets: program %s (%s at %s, binary %s) does not match a uprobe / uretprobe root "
					"of the domain",
					name, kind, pos_str(&pos), q(bin));
		for (size_t k2 = 0; k2 < in->n_uprobes; k2++)
			if (!strcmp(in->uprobes[k2].program, name))
				return seam_err("outputs.uprobe_targets: program %s appears twice", name);
		in->uprobes[in->n_uprobes++] = (struct uprobe_target){name, bin, pos};
	}
	/* Go ranges over a map of the roots (random order); C checks the domain's order */
	for (size_t k2 = 0; k2 < roots->n; k2++) {
		const struct root *r = &roots->v[k2];
		if (strcmp(r->kind, "uprobe") && strcmp(r->kind, "uretprobe"))
			continue;
		int found = 0;
		for (size_t i = 0; i < in->n_uprobes; i++)
			found |= !strcmp(in->uprobes[i].program, r->name);
		if (!found)
			return seam_err("outputs.uprobe_targets: the domain's %s root %s has no target", r->kind, r->name);
	}
	bml_build_json_free(doc);
	return NULL;
}

err_t read_seam(const char *emit_dir, const char *inspect_dir, const char *abs, const char *name, const char *bpf_commit,
		struct seam_input **inp, int *refused)
{
	*inp = NULL;
	*refused = 0;
	struct manifest m = {0};
	char *mb = NULL;
	size_t ml = 0;
	char *mpath = fp_join(inspect_dir, xasprintf("%s.inspect-manifest.json", name));
	err_t e = read_manifest(mpath, &m, &mb, &ml);
	if (e)
		return e;
	char *src;
	size_t sl;
	if ((e = read_file(abs, &src, &sl)))
		return e;
	char got[65];
	sha256_hex(src, sl, got);
	if (strcmp(got, m.source_sha))
		return seam_err("%s has sha256 %s but the manifest's source.sha256 is %s — the consumer's output was not made from this "
				"source",
				fp_base(abs), got, m.source_sha);
	if (bpf_commit && strcmp(m.bpf_commit, bpf_commit))
		return seam_err("the manifest's pins.bpf_mlir.commit is %s but this spinelbpf's bpf-mlir is %s", m.bpf_commit, bpf_commit);
	struct strv want = {0};
	if (m.failure_stage)
		return seam_err("the consumer failed at stage %s (manifest result.rc %lld) — see the consumer's stderr", m.failure_stage, m.rc);
	if (m.rc == 0) {
		for (size_t i = 0; i < N_OUTPUTS; i++)
			strv_push(&want, xstrdup(outputs[i].key));
	} else if (m.rc == 1) {
		strv_push(&want, xstrdup("domain"));
	} else {
		return seam_err("manifest result.rc %lld (0 or 1)", m.rc);
	}
	if (!m.domain_produced)
		return seam_err("manifest result.domain_produced is false — the consumer produced no domain");
	struct strv keys = {0};
	for (size_t i = 0; i < m.out_keys.n; i++)
		strv_push(&keys, m.out_keys.v[i]);
	strv_sort(&keys);
	strv_sort(&want);
	int same = keys.n == want.n;
	for (size_t i = 0; same && i < keys.n; i++)
		same = !strcmp(keys.v[i], want.v[i]);
	if (!same) {
		struct sb w = {0}, g = {0};
		for (size_t i = 0; i < want.n; i++)
			sb_printf(&w, "%s%s", i ? ", " : "", want.v[i]);
		for (size_t i = 0; i < keys.n; i++)
			sb_printf(&g, "%s%s", i ? ", " : "", keys.v[i]);
		return seam_err("manifest result.rc %lld needs outputs {%s}, got {%s}", m.rc, w.p ? w.p : "", g.p ? g.p : "");
	}
	char *data[N_OUTPUTS] = {0};
	size_t dlen[N_OUTPUTS] = {0};
	for (size_t i = 0; i < N_OUTPUTS; i++) {
		size_t k;
		for (k = 0; k < m.out_keys.n && strcmp(m.out_keys.v[k], outputs[i].key); k++)
			;
		if (k == m.out_keys.n)
			continue;
		char *p = fp_join(outputs[i].inspect ? inspect_dir : emit_dir, xasprintf("%s%s", name, outputs[i].ext));
		if ((e = read_file(p, &data[i], &dlen[i])))
			return seam_err("outputs.%s: %s", outputs[i].key, e);
		char h[65];
		sha256_hex(data[i], dlen[i], h);
		if (strcmp(h, m.out_shas.v[k]))
			return seam_err("outputs.%s: %s has sha256 %s but the manifest says %s", outputs[i].key, p, h, m.out_shas.v[k]);
	}
	struct seam_input *in = xmalloc(sizeof *in);
	memset(in, 0, sizeof *in);
	struct roots roots = {0};
	if ((e = read_domain(data[5], dlen[5], &roots, &in->diags)))
		return seam_err("outputs.domain: %s", e);
	in->domain = data[5];
	in->domain_len = dlen[5];
	in->manifest = mb;
	in->manifest_len = ml;
	*inp = in;
	if (m.rc == 1) {
		if (!diags_blocking(&in->diags))
			return seam_err("the consumer refused (manifest result.rc 1) but the domain has no blocking diagnostic — see the "
					"consumer's stderr");
		*refused = 1;
		return NULL;
	}
	if (diags_blocking(&in->diags))
		return seam_err("manifest result.rc 0 but the domain has a blocking diagnostic");
	struct bml_build_error be = {0};
	int rc = bml_build_map_decls_validate(data[2], dlen[2], &be);
	if (rc == BML_BUILD_UNSUPPORTED)
		not_ported("bindrt.ParseMapDecls: %s", be.text ? be.text : "");
	if (rc != BML_BUILD_OK)
		return seam_err("outputs.maps: %s", be.text ? be.text : "out of memory");
	if (!records_ok(data[3], dlen[3]))
		return seam_err("outputs.records: a character outside the embedded records table's alphabet");
	in->mlir = data[0];
	in->mlir_len = dlen[0];
	in->schema = data[1];
	in->schema_len = dlen[1];
	in->maps = data[2];
	in->maps_len = dlen[2];
	in->records = data[3];
	in->records_len = dlen[3];
	return seam_uprobes(data[4], dlen[4], &roots, in);
}
