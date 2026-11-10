/* csrc/driver/cfront.c - see cfront.h. It follows the removed Go frontend command's generate over frontend.Generate
 * (internal/frontend/generate.go), with the C frontend of csrc/frontend: fe_analyze, fe_domain_graph, fe_lower and
 * the three writers of schema_out. */
#include "cfront.h"

#include <string.h>

#include "pins.h"
#include "util.h"

#include "../frontend/dump.h"
#include "../frontend/jsonout.h"
#include "../frontend/lower.h"
#include "../frontend/schema_out.h"

#ifndef SPINELBPF_COMMIT_STAMP
#define SPINELBPF_COMMIT_STAMP "unknown"
#endif

struct outs {
	const char *key[6], *path[6];
	char sha[6][65];
	int n;
};

/* put: writes name+ext in dir and records it under key in the manifest's outputs (main.go put) */
static err_t put(struct outs *o, const char *key, const char *dir, const char *name, const char *ext, const void *b, size_t n)
{
	char *p = fp_join(dir, xasprintf("%s%s", name, ext));
	err_t e = write_file(p, b, n);
	if (e)
		return e;
	o->key[o->n] = key;
	o->path[o->n] = p;
	sha256_hex(b, n, o->sha[o->n]);
	o->n++;
	return NULL;
}


/* the uprobe targets document: json.MarshalIndent of {version 1, programs [{name, kind, binary_path, decl {file, line, col}}]}
 * for the uprobe and uretprobe programs, without a trailing newline (main.go) */
static void uprobe_targets(sr_buf *b, const fe_result *r)
{
	fe_jw w;
	fe_jw_init(&w, b);
	fe_jw_obj_begin(&w);
	fe_jw_keyc(&w, "version");
	fe_jw_i64(&w, 1);
	fe_jw_keyc(&w, "programs");
	fe_jw_arr_begin(&w);
	for (size_t i = 0; i < r->n_programs; i++) {
		const fe_program *p = r->programs[i];
		if (!p || !(sr_eqc(p->kind, "uprobe") || sr_eqc(p->kind, "uretprobe")))
			continue;
		fe_jw_obj_begin(&w);
		fe_jw_keyc(&w, "name");
		fe_jw_str(&w, p->name);
		fe_jw_keyc(&w, "kind");
		fe_jw_str(&w, p->kind);
		fe_jw_keyc(&w, "binary_path");
		fe_jw_str(&w, p->binary_path);
		fe_jw_keyc(&w, "decl");
		fe_jw_obj_begin(&w);
		fe_jw_keyc(&w, "file");
		fe_jw_str(&w, p->decl_pos.file);
		fe_jw_keyc(&w, "line");
		fe_jw_i64(&w, p->decl_pos.line);
		fe_jw_keyc(&w, "col");
		fe_jw_i64(&w, p->decl_pos.col);
		fe_jw_obj_end(&w);
		fe_jw_obj_end(&w);
	}
	fe_jw_arr_end(&w);
	fe_jw_obj_end(&w);
}

static void kv_str(fe_jw *w, const char *k, const char *v)
{
	fe_jw_keyc(w, k);
	fe_jw_strc(w, v);
}

/* the inspection manifest (version 1, execution source_pipeline): main.go's map[string]any, so every object's keys are in Go's
 * sorted order, and a newline at the end */
static void manifest(sr_buf *b, const char *abs, const char *src_sha, const char *spinel_sha, const struct outs *o, int rc)
{
	const char *stamp = SPINELBPF_COMMIT_STAMP;
	size_t sl = strlen(stamp);
	int dirty = sl > 6 && !strcmp(stamp + sl - 6, "+dirty");
	char *commit = xstrndup(stamp, dirty ? sl - 6 : sl);
	fe_jw w;
	fe_jw_init(&w, b);
	fe_jw_obj_begin(&w);
	kv_str(&w, "execution", "source_pipeline");
	fe_jw_keyc(&w, "facts");
	fe_jw_null(&w);
	fe_jw_keyc(&w, "outputs");
	fe_jw_obj_begin(&w);
	int order[6];
	for (int i = 0; i < o->n; i++)
		order[i] = i;
	for (int i = 1; i < o->n; i++) /* sorted keys */
		for (int j = i; j > 0 && strcmp(o->key[order[j]], o->key[order[j - 1]]) < 0; j--) {
			int t = order[j];
			order[j] = order[j - 1];
			order[j - 1] = t;
		}
	for (int i = 0; i < o->n; i++) {
		fe_jw_keyc(&w, o->key[order[i]]);
		fe_jw_obj_begin(&w);
		kv_str(&w, "path", o->path[order[i]]);
		kv_str(&w, "sha256", o->sha[order[i]]);
		fe_jw_obj_end(&w);
	}
	fe_jw_obj_end(&w);
	fe_jw_keyc(&w, "pins");
	fe_jw_obj_begin(&w);
	fe_jw_keyc(&w, "bpf_mlir");
	fe_jw_obj_begin(&w);
	kv_str(&w, "commit", PIN_COMPILER_COMMIT); /* the compiler commit of this build's pin (Go: toolchain.PinnedCompilerCommit) */
	fe_jw_obj_end(&w);
	fe_jw_keyc(&w, "consumer");
	fe_jw_obj_begin(&w);
	kv_str(&w, "commit", commit);
	fe_jw_keyc(&w, "dirty");
	fe_jw_bool(&w, dirty);
	fe_jw_obj_end(&w);
	fe_jw_keyc(&w, "spinel");
	fe_jw_obj_begin(&w);
	kv_str(&w, "binary_sha256", spinel_sha);
	kv_str(&w, "commit", PIN_SPINEL_COMMIT);
	kv_str(&w, "producer_revision", "spinelbpf");
	kv_str(&w, "producer_source", "metadata");
	fe_jw_obj_end(&w);
	fe_jw_obj_end(&w);
	fe_jw_keyc(&w, "result");
	fe_jw_obj_begin(&w);
	fe_jw_keyc(&w, "domain_produced");
	fe_jw_bool(&w, 1);
	fe_jw_keyc(&w, "rc");
	fe_jw_i64(&w, rc);
	fe_jw_obj_end(&w);
	fe_jw_keyc(&w, "source");
	fe_jw_obj_begin(&w);
	kv_str(&w, "path", abs);
	kv_str(&w, "sha256", src_sha);
	fe_jw_obj_end(&w);
	fe_jw_keyc(&w, "version");
	fe_jw_i64(&w, 1);
	fe_jw_obj_end(&w);
	sr_putc(b, '\n');
}

static int not_ported_rc(const char *where, sr_str np, char **text)
{
	*text = xasprintf("the C frontend cannot build this input yet (%s is not ported): %.*s", where, (int)np.n, np.p);
	return 3;
}

int c_frontend_generate(const char *repo, const char *spinel, const char *emit, const char *inspect, const char *work,
			const char *abs, char **text)
{
	err_t e;
	const char *base = strrchr(abs, '/') ? strrchr(abs, '/') + 1 : abs;
	size_t bl = strlen(base);
	char *name = bl >= 3 && !strcmp(base + bl - 3, ".rb") ? xstrndup(base, bl - 3) : xstrdup(base);
	if ((e = remove_all(work)))
		return *text = e, 3;
	char *src;
	size_t src_len;
	if ((e = read_file(abs, &src, &src_len))) /* Generate's os.ReadFile */
		return *text = e, 3;
	char *lib = fp_join(repo, "ruby/lib");
	sr_spinel sp = {spinel, lib};
	fe_z z;
	memset(&z, 0, sizeof z);
	fe_result res;
	memset(&res, 0, sizeof res);
	sr_result r = fe_z_init(&z, sr_cstr(abs), (sr_str){src, src_len}, sr_cstr(lib));
	if (r.kind == SR_OK)
		r = fe_analyze(&z, &sp, work, sr_cstr(""), &res);
	if (r.kind == SR_NOT_PORTED)
		return not_ported_rc("the analysis", r.text, text);
	if (r.kind != SR_OK)
		return *text = xstrndup(r.text.p, r.text.n), 3;

	struct outs o = {0};
	sr_buf dom = {0};
	fe_domain_graph(&dom, &res);
	if ((e = put(&o, "domain", inspect, name, ".domain.json", dom.p, dom.n)))
		return *text = e, 3;
	int rc = 0;
	if (fe_diags_blocking(&res.diags)) {
		rc = 1;
	} else if (res.n_programs == 0) {
		*text = xstrdup("internal: no program and no blocking diagnostic");
		return 3;
	} else {
		sr_buf m = {0};
		sr_result lr = fe_lower(&z, &res, &m);
		if (lr.kind == SR_NOT_PORTED)
			return not_ported_rc("Lower", lr.text, text);
		if (lr.kind != SR_OK) {
			/* Generate: &Error{Diags{{Rejected, SB017InternalEmitter, Pos{File: res.Source}, err.Error()}}}, printed as is */
			fe_diags ds = {0};
			fe_diag d = {0};
			d.verdict = FE_REJECTED;
			d.code = FE_SB017;
			d.pos.file = res.source;
			d.msg = lr.text;
			fe_diags_push(&ds, d);
			sr_buf eb = {0};
			fe_error_string(&eb, &ds);
			*text = xstrndup(eb.p ? eb.p : "", eb.n);
			return 5;
		}
		sr_buf sc = {0}, mp = {0}, rec = {0}, up = {0};
		fe_schema_json(&sc, &res);
		fe_maps_json(&mp, &res);
		fe_records_table(&rec, &res);
		uprobe_targets(&up, &res);
		if ((e = put(&o, "mlir", emit, name, ".mlir", m.p, m.n)) || (e = put(&o, "schema", emit, name, ".schema.json", sc.p, sc.n)) ||
		    (e = put(&o, "maps", emit, name, ".maps.json", mp.p, mp.n)) ||
		    (e = put(&o, "records", emit, name, ".records.txt", rec.p, rec.n)) ||
		    (e = put(&o, "uprobe_targets", emit, name, ".uprobe_targets.json", up.p, up.n)))
			return *text = e, 3;
	}
	char src_sha[65], spinel_sha[65];
	sha256_hex(src, src_len, src_sha);
	char *spb;
	size_t spl;
	if ((e = read_file(spinel, &spb, &spl)))
		return *text = e, 3;
	sha256_hex(spb, spl, spinel_sha);
	sr_buf mf = {0};
	manifest(&mf, abs, src_sha, spinel_sha, &o, rc);
	if ((e = write_file(fp_join(inspect, xasprintf("%s.inspect-manifest.json", name)), mf.p, mf.n)))
		return *text = e, 3;
	return rc;
}
