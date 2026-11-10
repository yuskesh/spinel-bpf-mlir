/* csrc/driver/main.c - the C driver's command line (cmd/spinelbpf/main.go run), with the Go flag package's parsing and texts.
 *
 *	spinelbpf build [--line-info=auto|off] [--emit=domain-graph] [--seam-emit E --seam-inspect I] [-o exe] x.rb
 *	spinelbpf --version
 *
 * The frontend is the C frontend in this process (cfront.c); the whole binary is C (an earlier C driver ran the Go frontend
 * as a subprocess). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "build.h"
#include "checks.h"
#include "pin.h"

static void usage(FILE *w)
{
	fputs("usage: spinelbpf build [--line-info=auto|off] [--emit=domain-graph] [--seam-emit E --seam-inspect I] [-o exe] x.rb\n"
	      "       spinelbpf --version\n",
	      w);
}

/* ecVersion: the `bpf-mlir …` line of `ebpf-compile --version`, or "" when there is none or it does not run. */
static char *ec_version(void)
{
	struct config c;
	if (default_config(&c))
		return "";
	char *argv[] = {c.ebpf_compile, "--version", NULL};
	struct run_out o = {0};
	if (run_cmd(argv, NULL, NULL, 0, &o))
		return "";
	const char *p = o.out.p ? o.out.p : "";
	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t n = nl ? (size_t)(nl - p) : strlen(p);
		if (n >= 9 && !strncmp(p, "bpf-mlir ", 9))
			return go_trim_space(p, n);
		p += n + (nl ? 1 : 0);
	}
	return "";
}

/* ---- the Go flag package (FlagSet "build", ContinueOnError, output stderr), for the five string flags ---- */

struct flag {
	const char *name, *usage, *def;
	const char **val;
	int set;
};

static void flag_defaults(FILE *w, struct flag *f, size_t n)
{
	/* PrintDefaults: sorted by name (the table is in order); a string flag prints " string"; a non-empty default (default %q) */
	fputs("Usage of build:\n", w);
	for (size_t i = 0; i < n; i++) {
		fprintf(w, "  -%s string", f[i].name);
		fprintf(w, "\n    \t%s", f[i].usage);
		if (*f[i].def) {
			char *q = go_quote(f[i].def, strlen(f[i].def));
			fprintf(w, " (default %s)", q);
		}
		fputc('\n', w);
	}
}

/* FlagSet.Parse: returns the index of the first argument after the flags, or -1 after printing Go's error and the usage. */
static int flag_parse(char **args, int nargs, struct flag *f, size_t nf)
{
	int i = 0;
	while (i < nargs) {
		const char *s = args[i];
		if (strlen(s) < 2 || s[0] != '-')
			break;
		int minuses = 1;
		if (s[1] == '-') {
			minuses++;
			if (s[2] == 0) {
				i++;
				break;
			}
		}
		const char *name = s + minuses;
		if (!*name || *name == '-' || *name == '=') {
			fprintf(stderr, "bad flag syntax: %s\n", s);
			flag_defaults(stderr, f, nf);
			return -1;
		}
		i++;
		const char *eq = strchr(name, '='), *value = NULL;
		char *nm = eq ? xstrndup(name, (size_t)(eq - name)) : xstrdup(name);
		if (eq)
			value = eq + 1;
		struct flag *fl = NULL;
		for (size_t k = 0; k < nf; k++)
			if (!strcmp(f[k].name, nm))
				fl = &f[k];
		if (!fl) {
			if (!strcmp(nm, "help") || !strcmp(nm, "h")) {
				flag_defaults(stderr, f, nf);
				return -1;
			}
			fprintf(stderr, "flag provided but not defined: -%s\n", nm);
			flag_defaults(stderr, f, nf);
			return -1;
		}
		if (!eq) {
			if (i >= nargs) {
				fprintf(stderr, "flag needs an argument: -%s\n", nm);
				flag_defaults(stderr, f, nf);
				return -1;
			}
			value = args[i++];
		}
		*fl->val = value;
		fl->set = 1;
	}
	return i;
}

int main(int argc, char **argv)
{
	char **args = argv + 1;
	int nargs = argc - 1;
	if (nargs == 1 && (!strcmp(args[0], "--version") || !strcmp(args[0], "version"))) {
		fputs(pin_version_text(ec_version()), stdout);
		return 0;
	}
	if (nargs == 0 || strcmp(args[0], "build")) {
		usage(stderr);
		return 2;
	}
	const char *line_info = "auto", *emit = "", *out = "", *seam_emit = "", *seam_inspect = "";
	struct flag flags[] = {
	    {"emit", "also print a stage artefact to stdout: domain-graph", "", &emit, 0},
	    {"line-info", "ebpf-compile --line-info (auto | off)", "auto", &line_info, 0},
	    {"o", "link the executable (the program + the loader + the embedded ELF)", "", &out, 0},
	    {"seam-emit", "read the eBPF side from spinel-mlir's consumer output: its emit dir (with --seam-inspect)", "", &seam_emit, 0},
	    {"seam-inspect", "the consumer's inspection dir (domain and inspect-manifest \xe2\x80\x94 with --seam-emit)", "", &seam_inspect, 0},
	};
	size_t nf = sizeof flags / sizeof flags[0];
	int first = flag_parse(args + 1, nargs - 1, flags, nf);
	if (first < 0)
		return 2;
	int se = flags[3].set, si = flags[4].set;
	if (se != si || (se && (!*seam_emit || !*seam_inspect))) {
		fputs("spinelbpf: --seam-emit and --seam-inspect go together, each with a directory\n", stderr);
		return 2;
	}
	if (nargs - 1 - first != 1) {
		usage(stderr);
		return 2;
	}
	const char *source = args[1 + first];
	if (strcmp(line_info, "auto") && strcmp(line_info, "off")) {
		char *q = go_quote(line_info, strlen(line_info));
		if (!q)
			not_ported("%%q of a non-ASCII --line-info value");
		fprintf(stderr, "spinelbpf: --line-info must be auto or off, got %s\n", q);
		return 2;
	}
	if (*emit && strcmp(emit, "domain-graph")) {
		char *q = go_quote(emit, strlen(emit));
		if (!q)
			not_ported("%%q of a non-ASCII --emit value");
		fprintf(stderr, "spinelbpf: --emit must be domain-graph, got %s\n", q);
		return 2;
	}
	struct config cfg;
	err_t e = default_config(&cfg);
	if (e) {
		fprintf(stderr, "spinelbpf: %s\n", e);
		return 1;
	}
	cfg.line_info = line_info;
	cfg.seam_emit = *seam_emit ? seam_emit : NULL;
	cfg.seam_inspect = *seam_inspect ? seam_inspect : NULL;
	struct build_result r;
	struct diags refusal = {0};
	int refused = 0;
	e = build(&cfg, source, &r, &refused, &refusal);
	if (!strcmp(emit, "domain-graph") && r.has_output && r.domain) {
		fwrite(r.domain, 1, r.domain_len, stdout);
		fflush(stdout);
	}
	if (refused) {
		if (r.refusal_text)
			fprintf(stderr, "%s\n", r.refusal_text);
		else
			fprintf(stderr, "%s\n", diags_error(&refusal));
		return 1;
	}
	if (e) {
		fprintf(stderr, "spinelbpf: %s\n", e);
		return 1;
	}
	diags_sort(&r.diags);
	for (size_t i = 0; i < r.diags.n; i++)
		if (r.diags.v[i].verdict == V_CONDITIONAL)
			fprintf(stderr, "spinelbpf: warning: %s\n", diag_str(&r.diags.v[i]));
#if defined(E175_MUT) && E175_MUT == 1
	/* mutation control ("stderr", which the differential against the Go driver must catch): one changed byte in the first wrote
	 * line, the last byte of its path (the "wrote" prefix and the _embed.o line stay, so the record stays classifiable and only
	 * the stderr comparison sees it); never in a default build */
	if (r.files.n > 0) {
		char *p = r.files.v[0];
		p[strlen(p) - 1] = 'X';
	}
#endif
	for (size_t i = 0; i < r.files.n; i++)
		fprintf(stderr, "spinelbpf: wrote %s\n", r.files.v[i]);
	if (r.reused)
		fputs("spinelbpf: ebpf-compile is not available \xe2\x80\x94 using the committed ELF and embedding (the regenerated .mlir / "
		      "schema / maps.json are identical)\n",
		      stderr);
	if (*out) {
		if ((e = link_exe(&cfg, source, out))) {
			fprintf(stderr, "spinelbpf: %s\n", e);
			return 1;
		}
		fprintf(stderr, "spinelbpf: linked %s\n", out);
	}
	return 0;
}
