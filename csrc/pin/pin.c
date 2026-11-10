/* csrc/pin/pin.c - the pin and version checks of the C build path. See pin.h.
 *
 * Each function names the Go function it ports. The messages are Go's, byte for byte (the Go tests build this file and
 * compare). The Go regular expressions of internal/toolchain become hand-written matchers; each Go pattern is quoted next to
 * its matcher. Go's \s is [\t\n\f\r ] and \S is its complement (RE2, ASCII).
 *
 * Test builds may define PIN_MUTANT="<name>" to remove exactly one check (see MUT). The product build never does. */
#define _GNU_SOURCE
#include "pin.h"
#include "pins.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bml/bml.h"

#ifdef PIN_MUTANT
#define MUT(n) (strcmp(PIN_MUTANT, (n)) == 0)
#else
#define MUT(n) 0
#endif

#ifndef SPINELBPF_COMMIT_STAMP
#define SPINELBPF_COMMIT_STAMP "unknown"
#endif

/* ---- small helpers ---------------------------------------------------------------------------------------------- */

static int fail(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (err && errlen) vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
	return 1;
}

/* The inside of Go's %q on s[0,n) for ASCII text: \a \b \f \n \r \t \v, other controls and DEL as \xNN, quote and backslash escaped.
 * Bytes >= 0x80 pass through (a known difference: Go's %q escapes invalid UTF-8 and non-printable runes). Caller frees. */
static char *qesc(const char *s, size_t n)
{
	char *o = malloc(n * 4 + 1), *w = o;
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		const char *e = c == 7 ? "\\a" : c == 8 ? "\\b" : c == 12 ? "\\f" : c == 10 ? "\\n" : c == 13 ? "\\r" : c == 9 ? "\\t" : c == 11 ? "\\v" : c == 34 ? "\\\"" : c == 92 ? "\\\\" : NULL;
		if (e) w += sprintf(w, "%s", e);
		else if (c < 32 || c == 127) w += sprintf(w, "\\x%02x", c);
		else *w++ = (char)c;
	}
	*w = 0;
	return o;
}

static int fail_q(char *err, size_t errlen, const char *pre, const char *s, size_t n, const char *post)
{
	char *q = qesc(s, n);
	fail(err, errlen, "%s\"%s\"%s", pre, q, post);
	free(q);
	return 1;
}

static int is_s(int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'; } /* RE2 \s */
static int is_hex_lower(int c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

/* Go strings.TrimSpace: Unicode White_Space. Returns the trimmed [*b, *e). */
static size_t ws_len(const unsigned char *p, const unsigned char *end)
{
	if (p >= end) return 0;
	if (*p == ' ' || (*p >= '\t' && *p <= '\r')) return 1; /* \t \n \v \f \r and space */
	if (end - p >= 2 && p[0] == 0xc2 && (p[1] == 0x85 || p[1] == 0xa0)) return 2;
	if (end - p >= 3) {
		unsigned c = ((unsigned)p[0] << 16) | ((unsigned)p[1] << 8) | p[2];
		if (c == 0xe19a80 || (c >= 0xe28080 && c <= 0xe2808a) || c == 0xe280a8 || c == 0xe280a9 || c == 0xe280af || c == 0xe2819f ||
		    c == 0xe38080)
			return 3;
	}
	return 0;
}

static void trim_space(const char *s, size_t n, const char **b, const char **e)
{
	const unsigned char *p = (const unsigned char *)s, *end = p + n;
	for (size_t w; (w = ws_len(p, end)) != 0;) p += w;
	/* trailing: find the last position q such that [q,end) is whitespace; scan runes from the left is simplest. */
	const unsigned char *q = p, *last = p;
	while (q < end) {
		size_t w = ws_len(q, end);
		if (w) {
			q += w;
		} else {
			/* advance one UTF-8 rune */
			q++;
			while (q < end && (*q & 0xc0) == 0x80) q++;
			last = q;
		}
	}
	*b = (const char *)p;
	*e = (const char *)last;
}

/* ---- running a command (Go exec.Command(...).CombinedOutput / Output) ---------------------------------------------- */

typedef struct {
	char *data;
	size_t len;
} buf_t;

static void buf_free(buf_t *b)
{
	free(b->data);
	b->data = NULL;
	b->len = 0;
}

static int buf_add(buf_t *b, const char *p, size_t n)
{
	char *d = realloc(b->data, b->len + n + 1);
	if (!d) return 1;
	b->data = d;
	memcpy(b->data + b->len, p, n);
	b->len += n;
	b->data[b->len] = 0;
	return 0;
}

/* Go exec.LookPath for a name without a slash: search PATH for a regular file with an execute bit. */
static int look_path(const char *name, char *out, size_t outlen)
{
	if (strchr(name, '/')) {
		snprintf(out, outlen, "%s", name);
		return 0;
	}
	const char *path = getenv("PATH");
	if (!path) path = "";
	const char *p = path;
	for (;;) {
		const char *q = strchr(p, ':');
		size_t n = q ? (size_t)(q - p) : strlen(p);
		char cand[4096];
		if (n == 0)
			snprintf(cand, sizeof cand, "./%s", name);
		else
			snprintf(cand, sizeof cand, "%.*s/%s", (int)n, p, name);
		struct stat st;
		if (stat(cand, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0111)) {
			snprintf(out, outlen, "%s", cand);
			return 0;
		}
		if (!q) break;
		p = q + 1;
	}
	return 1;
}

static const char *go_errno(int e)
{
	switch (e) {
	case ENOENT: return "no such file or directory";
	case EACCES: return "permission denied";
	case ENOEXEC: return "exec format error";
	case ENOTDIR: return "not a directory";
	default: return strerror(e); /* Go's table is the lower-cased strerror for the rest; not claimed here (Go may word it differently) */
	}
}

/* Runs argv; captures stdout (and stderr too when both). On failure writes Go's error text to msg and returns 1. */
static int run_cmd(char *const argv[], int both, buf_t *out, char *msg, size_t msglen)
{
	char path[4096];
	if (look_path(argv[0], path, sizeof path)) {
		snprintf(msg, msglen, "exec: \"%s\": executable file not found in $PATH", argv[0]);
		return 1;
	}
	int po[2], pe[2];
	if (pipe2(po, O_CLOEXEC) || pipe2(pe, O_CLOEXEC)) {
		snprintf(msg, msglen, "pipe: %s", strerror(errno));
		return 1;
	}
	pid_t pid = fork();
	if (pid < 0) {
		snprintf(msg, msglen, "fork: %s", strerror(errno));
		return 1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);
		dup2(devnull, 0);
		dup2(po[1], 1);
		if (both)
			dup2(po[1], 2);
		else
			dup2(devnull, 2);
		execv(path, argv);
		int e = errno;
		ssize_t w = write(pe[1], &e, sizeof e);
		(void)w;
		_exit(127);
	}
	close(po[1]);
	close(pe[1]);
	char tmp[4096];
	ssize_t n;
	while ((n = read(po[0], tmp, sizeof tmp)) > 0)
		if (buf_add(out, tmp, (size_t)n)) break;
	close(po[0]);
	int e = 0;
	ssize_t r = read(pe[0], &e, sizeof e);
	close(pe[0]);
	int st = 0;
	waitpid(pid, &st, 0);
	if (r == (ssize_t)sizeof e) {
		snprintf(msg, msglen, "fork/exec %s: %s", path, go_errno(e));
		return 1;
	}
	if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
		if (!out->data) buf_add(out, "", 0);
		return 0;
	}
	if (WIFEXITED(st))
		snprintf(msg, msglen, "exit status %d", WEXITSTATUS(st));
	else
		snprintf(msg, msglen, "signal: %s", WIFSIGNALED(st) ? strsignal(WTERMSIG(st)) : "unknown");
	return 1;
}

/* ---- pin forms ----------------------------------------------------------------------------------------------------- */

#ifndef SPINELBPF_PUBLIC
#define COMPILER_FIX \
	"rebuild ebpf-compile from bpf-mlir commit " PIN_COMPILER_COMMIT " (scripts/setup.sh in spinel-bpf-mlir), or point EBPF_COMPILE at a build of that exact commit"
#define SUBMODULE_WHAT "third_party/bpf-mlir is at"
#else
#define COMPILER_FIX \
	"build ebpf-compile from the bpf-mlir " PIN_COMPILER_VERSION " source release (commit " PIN_COMPILER_COMMIT ") and point EBPF_COMPILE at it"
#define SUBMODULE_WHAT "third_party/bpf-mlir/SOURCE_VERSION has source_commit"
#endif

/* ---- headOf (toolchain.headOf) ------------------------------------------------------------------------------------ */

/* repo/third_party/<name> HEAD into out (41 bytes); out is "" when repo is empty or the submodule has no .git. */
static int head_of(const char *repo, const char *name, char out[64], char *err, size_t errlen)
{
	out[0] = 0;
	if (!repo || !repo[0]) return 0;
	char sub[4096], gitp[4200];
	snprintf(sub, sizeof sub, "%s/third_party/%s", repo, name);
	snprintf(gitp, sizeof gitp, "%s/.git", sub);
	struct stat st;
	if (stat(gitp, &st) != 0) return 0;
	char *argv[] = {"git", "-C", sub, "rev-parse", "HEAD", NULL};
	buf_t o = {0};
	char msg[8192];
	if (run_cmd(argv, 0, &o, msg, sizeof msg)) {
		buf_free(&o);
		return fail(err, errlen, "reading the commit of %s: %s", sub, msg);
	}
	const char *b, *e;
	trim_space(o.data, o.len, &b, &e);
	size_t n = (size_t)(e - b);
	if (n >= 64) n = 63;
	memcpy(out, b, n);
	out[n] = 0;
	buf_free(&o);
	return 0;
}

/* ---- ParseSourceVersion / releaseSource (toolchain) ---------------------------------------------------------------- */

/* `^[0-9]+\.[0-9]+\.[0-9]+$` on s[0,n) */
static int match_semver(const char *s, size_t n)
{
	size_t i = 0;
	for (int part = 0; part < 3; part++) {
		size_t j = i;
		while (j < n && s[j] >= '0' && s[j] <= '9') j++;
		if (j == i) return 0;
		i = j;
		if (part < 2) {
			if (i >= n || s[i] != '.') return 0;
			i++;
		}
	}
	return i == n;
}

/* `^[0-9a-f]{40}$` on s[0,n) */
static int match_hex40(const char *s, size_t n)
{
	if (n != 40) return 0;
	for (int i = 0; i < 40; i++)
		if (!is_hex_lower((unsigned char)s[i])) return 0;
	return 1;
}

/* Go strings.CutPrefix on s[0,n): the rest, or NULL */
static const char *cut_prefix(const char *s, size_t n, const char *prefix, size_t *rest_n)
{
	size_t pl = strlen(prefix);
	if (n < pl || memcmp(s, prefix, pl) != 0) return NULL;
	*rest_n = n - pl;
	return s + pl;
}

int pin_parse_source_version(const char *b, size_t blen, const char **version, size_t *version_len, char commit[41], char *err, size_t errlen)
{
	/* ParseSourceVersion: exactly 3 lines, format=1, version=N.N.N, source_commit=40hex; one final \n allowed. */
	for (size_t i = 0; i < blen; i++)
		if (b[i] == '\r') return fail(err, errlen, "SOURCE_VERSION has a carriage return");
	size_t n = blen;
	if (n > 0 && b[n - 1] == '\n') n--; /* strings.TrimSuffix(s, "\n") */
	size_t nl = 1; /* strings.Split(s, "\n") */
	for (size_t i = 0; i < n; i++)
		if (b[i] == '\n') nl++;
	if (nl != 3) return fail(err, errlen, "SOURCE_VERSION has %zu lines, want exactly 3 (format=, version= and source_commit=)", nl);
	const char *ls[3];
	size_t ln[3];
	size_t li = 0, start = 0;
	for (size_t i = 0; i <= n; i++) {
		if (i == n || b[i] == '\n') {
			ls[li] = b + start;
			ln[li] = i - start;
			li++;
			start = i + 1;
		}
	}
	if (!(ln[0] == 8 && memcmp(ls[0], "format=1", 8) == 0)) return fail_q(err, errlen, "SOURCE_VERSION line 1 is ", ls[0], ln[0], ", want format=1");
	size_t vn = 0, cn = 0;
	const char *v = cut_prefix(ls[1], ln[1], "version=", &vn);
	if (!v || !match_semver(v, vn))
		return fail_q(err, errlen, "SOURCE_VERSION line 2 is ", ls[1], ln[1], ", want version=<major>.<minor>.<patch>");
	const char *c = cut_prefix(ls[2], ln[2], "source_commit=", &cn);
	if (!c || !match_hex40(c, cn))
		return fail_q(err, errlen, "SOURCE_VERSION line 3 is ", ls[2], ln[2], ", want source_commit=<40 lowercase hex digits>");
	*version = v;
	*version_len = vn;
	snprintf(commit, 41, "%.40s", c);
	return 0;
}

/* releaseSource(repo, want): repo/third_party/bpf-mlir/SOURCE_VERSION's source_commit; "" when there is no repo or the submodule
 * is not checked out. The Go %q verbs of its messages print ASCII paths here (a known difference: a path with bytes Go's %q escapes
 * differs). */
int pin_release_source(const char *repo, const char *want, char out[64], char *err, size_t errlen)
{
	out[0] = 0;
	if (!repo || !repo[0]) return 0;
	char sub[4096], path[4200];
	snprintf(sub, sizeof sub, "%s/third_party/bpf-mlir", repo);
	snprintf(path, sizeof path, "%s/SOURCE_VERSION", sub);
	FILE *f = fopen(path, "rb");
	if (!f) {
		if (errno == ENOENT) {
			char gitp[4300];
			struct stat st;
			snprintf(gitp, sizeof gitp, "%s/.git", sub);
			if (stat(gitp, &st) != 0) return 0;
			return fail(err, errlen,
			            "%s is checked out but has no SOURCE_VERSION — spinelbpf checks ebpf-compile against the source_commit of the bpf-mlir %s source release",
			            sub, want);
		}
		return fail(err, errlen, "reading %s: open %s: %s", path, path, go_errno(errno));
	}
	buf_t b = {0};
	char tmp[4096];
	size_t n;
	while ((n = fread(tmp, 1, sizeof tmp, f)) > 0) buf_add(&b, tmp, n);
	fclose(f);
	char com[41], msg[8192];
	const char *ver = NULL;
	size_t vl = 0;
	if (pin_parse_source_version(b.data ? b.data : "", b.len, &ver, &vl, com, msg, sizeof msg)) {
		buf_free(&b);
		return fail(err, errlen, "%s: %s", path, msg);
	}
	/* "v"+ver == want, on the full length (ver points into b) */
	int same = strlen(want) == vl + 1 && want[0] == 'v' && memcmp(want + 1, ver, vl) == 0;
	if (!same) {
		fail(err, errlen, "%s says version %.*s, but spinelbpf needs the bpf-mlir %s source release", path, (int)vl, ver, want);
		buf_free(&b);
		return 1;
	}
	buf_free(&b);
	snprintf(out, 64, "%s", com);
	return 0;
}

/* submoduleSource: dev = third_party/bpf-mlir HEAD; public = SOURCE_VERSION's source_commit. */
static int submodule_source(const char *repo, char out[64], char *err, size_t errlen)
{
#ifndef SPINELBPF_PUBLIC
	return head_of(repo, "bpf-mlir", out, err, errlen);
#else
	return pin_release_source(repo, PIN_COMPILER_VERSION, out, err, errlen);
#endif
}

/* ---- Verify (toolchain.Verify without the Go-module step) --------------------------------------------------------- */

/* `(?m)^\s*bpf-mlir (\S+) \(commit (\S+)\)\s*$`: the first line that is, after trimming \s at both ends, `bpf-mlir <T> (commit <U>)`,
 * T and U non-empty runs of non-\s bytes, U ending in the closing parenthesis (so U is the token minus its last byte). */
static int match_version_line(const char *text, size_t n, const char **desc, size_t *desc_len, const char **commit, size_t *commit_len)
{
	const char *p = text, *end = text + n;
	while (p < end) {
		const char *nlp = memchr(p, '\n', (size_t)(end - p));
		size_t ll = nlp ? (size_t)(nlp - p) : (size_t)(end - p);
		const char *b = p, *e = p + ll;
		while (b < e && is_s((unsigned char)*b)) b++;
		while (e > b && is_s((unsigned char)e[-1])) e--;
		if ((size_t)(e - b) > 9 && memcmp(b, "bpf-mlir ", 9) == 0) {
			const char *d = b + 9, *de = d;
			while (de < e && !is_s((unsigned char)*de)) de++;
			if (de > d && (size_t)(e - de) > 9 && memcmp(de, " (commit ", 9) == 0) {
				const char *c = de + 9, *ce = c;
				while (ce < e && !is_s((unsigned char)*ce)) ce++;
				if (ce == e && ce - c >= 2 && ce[-1] == ')') {
					*desc = d;
					*desc_len = (size_t)(de - d);
					*commit = c;
					*commit_len = (size_t)(ce - 1 - c);
					return 1;
				}
			}
		}
		if (!nlp) break;
		p = nlp + 1;
	}
	return 0;
}

static int span_is(const char *s, size_t n, const char *lit)
{
	return strlen(lit) == n && memcmp(s, lit, n) == 0;
}

static int span_has_suffix(const char *s, size_t n, const char *suf)
{
	size_t b = strlen(suf);
	return n >= b && memcmp(s + n - b, suf, b) == 0;
}

/* The text is a (pointer, length) pair: it may hold NUL bytes, which Go's regexp reads as ordinary bytes, and a describe or a commit
 * of any length (Go's messages print them in full). desc_out / commit_out are informational copies, cut to their size. */
int pin_verify_compiler_hook_n(const char *text, size_t n, const char *submodule_commit, const pin_module_hook *h, char desc_out[256], char commit_out[128], char *err, size_t errlen)
{
	const char *d = NULL, *c = NULL;
	size_t dl = 0, cl = 0;
	desc_out[0] = commit_out[0] = 0;
	if (!match_version_line(text, n, &d, &dl, &c, &cl))
		return fail(err, errlen, "ebpf-compile --version has no `bpf-mlir <version> (commit <sha>)` line — spinelbpf needs bpf-mlir commit %s; %s",
		            PIN_COMPILER_COMMIT, COMPILER_FIX);
	snprintf(desc_out, 256, "%.*s", (int)dl, d);
	snprintf(commit_out, 128, "%.*s", (int)cl, c);
	if (!MUT("compiler_commit") && !span_is(c, cl, PIN_COMPILER_COMMIT))
		return fail(err, errlen, "ebpf-compile is bpf-mlir %.*s (commit %.*s), but spinelbpf needs exactly bpf-mlir commit %s; %s", (int)dl, d, (int)cl, c,
		            PIN_COMPILER_COMMIT, COMPILER_FIX);
	if (!MUT("compiler_dirty") && (span_has_suffix(d, dl, "-dirty") || span_is(d, dl, "unknown")))
	{
		char *q = qesc(d, dl);
		fail(err, errlen, "ebpf-compile is bpf-mlir \"%s\" (commit %.*s), a build from modified or unidentified source: spinelbpf refuses it; %s", q, (int)cl, c, COMPILER_FIX);
		free(q);
		return 1;
	}
	if (h && h->compare && h->compare(h->ctx, err, errlen)) return 1; /* toolchain.Verify's module-version step: after dirty, before the submodule */
	if (!MUT("compiler_submodule") && submodule_commit && submodule_commit[0] && !span_is(c, cl, submodule_commit))
		return fail(err, errlen, "ebpf-compile was built from bpf-mlir commit %.*s but %s %s — rebuild with scripts/setup.sh", (int)cl, c, SUBMODULE_WHAT,
		            submodule_commit);
	return 0;
}

int pin_verify_compiler_hook(const char *version_output, const char *submodule_commit, const pin_module_hook *h, char desc_out[256], char commit_out[128], char *err, size_t errlen)
{
	return pin_verify_compiler_hook_n(version_output, strlen(version_output), submodule_commit, h, desc_out, commit_out, err, errlen);
}

int pin_verify_compiler_n(const char *text, size_t n, const char *submodule_commit, char desc_out[256], char commit_out[128], char *err, size_t errlen)
{
	return pin_verify_compiler_hook_n(text, n, submodule_commit, NULL, desc_out, commit_out, err, errlen);
}

int pin_verify_compiler(const char *version_output, const char *submodule_commit, char desc_out[256], char commit_out[128], char *err, size_t errlen)
{
	return pin_verify_compiler_hook(version_output, submodule_commit, NULL, desc_out, commit_out, err, errlen);
}

int pin_check_compiler_hook(const char *ebpf_compile, const char *repo, char out_commit[41], const pin_module_hook *h, char *err, size_t errlen)
{
	char *argv[] = {(char *)ebpf_compile, "--version", NULL};
	buf_t o = {0};
	char msg[8192];
	if (run_cmd(argv, 1, &o, msg, sizeof msg)) {
		buf_free(&o);
		return fail(err, errlen, "running %s --version: %s", ebpf_compile, msg);
	}
	if (h && h->fetch && h->fetch(h->ctx, err, errlen)) { /* toolchain.Check's ModuleVersion step: after --version, before the submodule */
		buf_free(&o);
		return 1;
	}
	char sub[64];
	if (submodule_source(repo, sub, err, errlen)) {
		buf_free(&o);
		return 1;
	}
	char d[256], c[128];
	int rc = pin_verify_compiler_hook_n(o.data ? o.data : "", o.len, sub, h, d, c, err, errlen);
	buf_free(&o);
	if (rc) return rc;
	snprintf(out_commit, 41, "%.40s", c);
	return 0;
}

int pin_check_compiler(const char *ebpf_compile, const char *repo, char out_commit[41], char *err, size_t errlen)
{
	return pin_check_compiler_hook(ebpf_compile, repo, out_commit, NULL, err, errlen);
}

/* ---- VerifySpinel / CheckSpinel ---------------------------------------------------------------------------------- */

/* `^spinel \S+ \(([0-9a-f]{7,40})\)` on strings.TrimSpace(output) (no `$`: text after the closing parenthesis is allowed). */
static int match_spinel_line(const char *s, size_t n, char commit[64])
{
	if (n < 8 || memcmp(s, "spinel ", 7) != 0) return 0;
	size_t i = 7, j = i;
	while (j < n && !is_s((unsigned char)s[j])) j++;
	if (j == i) return 0;
	/* \S+ is greedy and may contain " (" only if no space — it cannot; so the token ends at the first \s */
	if (j + 2 > n || s[j] != ' ' || s[j + 1] != '(') return 0;
	size_t k = j + 2, h = k;
	while (k < n && is_hex_lower((unsigned char)s[k]) && k - h < 40) k++;
	size_t hl = k - h;
	if (hl < 7 || k >= n || s[k] != ')') return 0;
	memcpy(commit, s + h, hl);
	commit[hl] = 0;
	return 1;
}

int pin_verify_spinel_n(const char *text, size_t tn, const char *submodule_head, char commit_out[64], char *err, size_t errlen)
{
	const char *fixfmt = "build Spinel " PIN_SPINEL_COMMIT " (scripts/setup.sh in spinel-bpf-mlir), or point SPINEL at a build of that commit";
	const char *b, *e;
	trim_space(text, tn, &b, &e);
	char c[64];
	commit_out[0] = 0;
	if (!match_spinel_line(b, (size_t)(e - b), c)) {
		/* Go's %q of the trimmed output: ASCII without escapes only (a known difference) */
		char *q = qesc(b, (size_t)(e - b));
		fail(err, errlen, "spinel --version has no `spinel <version> (<commit>)` line (\"%s\"); %s", q, fixfmt);
		free(q);
		return 1;
	}
	snprintf(commit_out, 64, "%s", c);
	size_t cl = strlen(c), pl = strlen(PIN_SPINEL_COMMIT);
	int prefix_a = strncmp(c, PIN_SPINEL_COMMIT, pl < cl ? pl : cl) == 0; /* HasPrefix(c, pin) || HasPrefix(pin, c) */
	if (!MUT("spinel_pin") && !prefix_a)
		return fail(err, errlen,
		            "spinel is commit %s but spinelbpf is pinned to %s — the frontend reads Spinel's AST and types, whose shape is only checked for that commit; %s", c,
		            PIN_SPINEL_COMMIT, fixfmt);
	if (!MUT("spinel_submodule") && submodule_head && submodule_head[0] && strncmp(submodule_head, c, cl) != 0)
		return fail(err, errlen, "spinel was built from commit %s but third_party/spinel is at %s — rebuild with scripts/setup.sh", c, submodule_head);
	return 0;
}

int pin_verify_spinel(const char *version_output, const char *submodule_head, char commit_out[64], char *err, size_t errlen)
{
	return pin_verify_spinel_n(version_output, strlen(version_output), submodule_head, commit_out, err, errlen);
}

int pin_check_spinel(const char *spinel, const char *repo, char *err, size_t errlen)
{
	char *argv[] = {(char *)spinel, "--version", NULL};
	buf_t o = {0};
	char msg[8192];
	if (run_cmd(argv, 1, &o, msg, sizeof msg)) {
		buf_free(&o);
		return fail(err, errlen, "running %s --version: %s", spinel, msg);
	}
	char head[64], c[64];
	if (head_of(repo, "spinel", head, err, errlen)) {
		buf_free(&o);
		return 1;
	}
	int rc = pin_verify_spinel_n(o.data ? o.data : "", o.len, head, c, err, errlen);
	buf_free(&o);
	return rc;
}

/* ---- the linked bml (replaces cmd/spinelbpf/bml.go checkBMLVersions) ----------------------------------------------- */

/* The bpf-mlir source's own policy version and format limit: `const PolicyVersion = N` and `const MaxFormatVersion = N` in
 * go/requirements/spec.go of the pinned source (dev form with a repo that has the file); otherwise the pinned constants. */
#ifndef SPINELBPF_PUBLIC
static int const_in_source(const char *text, const char *name, long *out)
{
	char key[64];
	snprintf(key, sizeof key, "const %s = ", name);
	const char *p = text;
	size_t kl = strlen(key);
	while (p && *p) {
		if (strncmp(p, key, kl) == 0) {
			const char *q = p + kl;
			if (*q < '0' || *q > '9') return 0;
			*out = strtol(q, NULL, 10);
			return 1;
		}
		p = strchr(p, '\n');
		if (p) p++;
	}
	return 0;
}
#endif

static int source_numbers(const char *repo, long *policy, long *format, char *err, size_t errlen)
{
	*policy = PIN_POLICY_VERSION;
	*format = PIN_MAX_FORMAT;
#ifndef SPINELBPF_PUBLIC
	if (!repo || !repo[0]) return 0;
	char path[4300];
	snprintf(path, sizeof path, "%s/third_party/bpf-mlir/go/requirements/spec.go", repo);
	FILE *f = fopen(path, "rb");
	if (!f) {
		if (errno == ENOENT) return 0; /* submodule not checked out: the pinned constants */
		return fail(err, errlen, "reading %s: open %s: %s", path, path, go_errno(errno));
	}
	buf_t b = {0};
	char tmp[4096];
	size_t n;
	while ((n = fread(tmp, 1, sizeof tmp, f)) > 0) buf_add(&b, tmp, n);
	fclose(f);
	const char *t = b.data ? b.data : "";
	if (!const_in_source(t, "PolicyVersion", policy) || !const_in_source(t, "MaxFormatVersion", format)) {
		buf_free(&b);
		return fail(err, errlen, "%s has no `const PolicyVersion = N` / `const MaxFormatVersion = N` — the pinned bpf-mlir source changed shape", path);
	}
	buf_free(&b);
#else
	(void)repo;
	(void)err;
	(void)errlen;
#endif
	return 0;
}

int pin_check_bml_facts(const pin_bml_facts *f, const char *repo, char *err, size_t errlen)
{
	long policy, format;
	if (source_numbers(repo, &policy, &format, err, errlen)) return 1;
	if (!MUT("bml_form_none") && strcmp(f->form, "none") == 0)
		return fail(err, errlen,
		            "the linked bml carries no version facts (source form none: built outside a git checkout and outside a source release) — its commit, dirty state and pinned bpf-mlir cannot be checked");
	if (!MUT("bml_form_unknown") && strcmp(f->form, "dev") != 0 && strcmp(f->form, "public") != 0 && strcmp(f->form, "none") != 0)
		return fail(err, errlen, "the linked bml has an unknown source form \"%s\" (want dev or public)", f->form);
	/* The whole commit must equal the full pin (PIN_BML_COMMIT_FULL, tied to the gitlink by a test): in the development form the
	 * displayed pin is a 7-digit prefix, and a commit that only starts like it (another suffix) is another bml. No checkout is needed. */
	if (!MUT("bml_commit") && strcmp(f->source_commit, PIN_BML_COMMIT_FULL) != 0)
		return fail(err, errlen, "the linked bml was built from source commit %s, but spinelbpf is pinned to bml %s — raise both pins together", f->source_commit,
		            PIN_BML_COMMIT);
	if (!MUT("bml_dirty") && f->dirty == 1)
		return fail(err, errlen, "the linked bml was built from a modified source tree (dirty) — spinelbpf refuses a bml that is not exactly its commit");
	if (!MUT("bml_dirty_unknown") && f->dirty != 0 && f->dirty != 1 && !(f->dirty == -1 && strcmp(f->form, "public") == 0))
		return fail(err, errlen, "the linked bml's dirty state is %d in form %s — only a public source release may have an unknown (-1) dirty state", f->dirty, f->form);
	if (!MUT("bml_bpf_mlir") && strcmp(f->bpf_mlir_commit, PIN_COMPILER_COMMIT) != 0)
		return fail(err, errlen, "the linked bml pins bpf-mlir commit %s, but the compiler pin is %s — raise both pins together", f->bpf_mlir_commit,
		            PIN_COMPILER_COMMIT);
	if (!MUT("bml_policy") && f->policy_version != policy)
		return fail(err, errlen, "judgement (policy) version: the pinned bpf-mlir %ld, the linked bml %ld — raise both pins together", policy, (long)f->policy_version);
	if (!MUT("bml_format") && f->max_format != format)
		return fail(err, errlen, "requirements format maximum: the pinned bpf-mlir %ld, the linked bml %ld — raise both pins together", format, (long)f->max_format);
	return 0;
}

void pin_bml_facts_read(pin_bml_facts *f)
{
	snprintf(f->form, sizeof f->form, "%s", bml_source_form());
	snprintf(f->source_commit, sizeof f->source_commit, "%s", bml_source_commit());
	f->dirty = bml_source_dirty();
	snprintf(f->bpf_mlir_commit, sizeof f->bpf_mlir_commit, "%s", bml_bpf_mlir_commit());
	f->policy_version = bml_policy_version();
	f->max_format = bml_max_format_version();
}

int pin_check_bml(const char *repo, char *err, size_t errlen)
{
	pin_bml_facts f;
	pin_bml_facts_read(&f);
	return pin_check_bml_facts(&f, repo, err, errlen);
}

/* ---- --version text (version.Text) -------------------------------------------------------------------------------- */

char *pin_version_text(const char *ec)
{
	if (!ec || !ec[0]) ec = "not found";
	size_t cap = 2048 + strlen(ec);
	char *s = malloc(cap);
	if (!s) return NULL;
	int n = snprintf(s, cap, "spinel-bpf-mlir %s (commit %s)\n", PIN_VERSION, SPINELBPF_COMMIT_STAMP);
#ifndef SPINELBPF_PUBLIC
	n += snprintf(s + n, cap - (size_t)n, "bpf-mlir go/%s (go.mod require)\n", PIN_MODULE_VERSION);
	n += snprintf(s + n, cap - (size_t)n, "bml %s\n", PIN_BML_COMMIT);
#else
	n += snprintf(s + n, cap - (size_t)n, "bpf-mlir %s (commit %.8s; Go packages %s %s, go.mod require)\n", PIN_COMPILER_VERSION, PIN_COMPILER_COMMIT,
	              PIN_MODULE, PIN_MODULE_VERSION);
	n += snprintf(s + n, cap - (size_t)n, "bml %s (commit %.7s)\n", PIN_BML_VERSION, PIN_BML_COMMIT);
#endif
	n += snprintf(s + n, cap - (size_t)n, "spinel %s\n", PIN_SPINEL_COMMIT);
	snprintf(s + n, cap - (size_t)n, "ebpf-compile: %s\n", ec);
	return s;
}
