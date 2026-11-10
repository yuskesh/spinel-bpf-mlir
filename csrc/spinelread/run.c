/* spinelread: Spinel.Analyze, UsesThreads, Version and firstLines (internal/frontend/spinel.go).
 *
 * A process is started as Go's exec.Cmd starts it here: argv as given (the binary path must contain '/', since Go's LookPath is
 * not ported), stdin from /dev/null, stdout and stderr captured, the working directory set in the child, and the environment
 * os.Environ() with TMPDIR replaced (Go keeps the last of duplicate keys). Failing to start (exec, chdir) and exiting non-zero or
 * on a signal are each "the run failed", as cmd.Run's error is for Analyze. Go's OS error texts are never reproduced: where Go
 * returns one as an error, this C stops as "not ported" (revisions 2-3). */
#define _GNU_SOURCE
#include "sr.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* os.MkdirAll: 0 on success */
static int mkdir_all(const char *path, mode_t mode)
{
	struct stat st;
	if (stat(path, &st) == 0)
		return S_ISDIR(st.st_mode) ? 0 : -1;
	size_t n = strlen(path);
	while (n > 1 && path[n - 1] == '/')
		n--;
	size_t j = n;
	while (j > 0 && path[j - 1] != '/')
		j--;
	while (j > 1 && path[j - 1] == '/')
		j--;
	if (j > 1 && mkdir_all(sr_dup(path, j).p, mode) != 0) /* the parent, path[:j], as Go's MkdirAll recurses */
		return -1;
	if (mkdir(path, mode) != 0) {
		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
			return 0;
		return -1;
	}
	return 0;
}

static char *join2(const char *dir, const char *name)
{
	sr_buf b = {0};
	sr_puts(&b, dir);
	if (strcmp(dir, "/") != 0)
		sr_putc(&b, '/');
	sr_puts(&b, name);
	return b.p;
}

/* filepath.Join cleans its result; this C takes only paths that are already clean, so its joins are the same bytes */
static int clean_abs(const char *p)
{
	if (p[0] != '/')
		return 0;
	if (strcmp(p, "/") == 0)
		return 1;
	size_t n = strlen(p);
	if (p[n - 1] == '/')
		return 0;
	for (const char *q = p; *q; q++) {
		if (*q != '/')
			continue;
		const char *c = q + 1;
		size_t len = strcspn(c, "/");
		if (len == 0 || (len == 1 && c[0] == '.') || (len == 2 && c[0] == '.' && c[1] == '.'))
			return 0;
	}
	return 1;
}

static int plain_name(const char *p)
{
	return p[0] && !strchr(p, '/') && strcmp(p, ".") != 0 && strcmp(p, "..") != 0;
}

typedef struct {
	sr_str out, err;
	int failed; /* cmd.Run's error, or s.run's MkdirAll error */
	int started;
	const char *unobserved; /* addendum 2 B2: a capture or status observation failed; the run's outcome is unknown */
} run_out;

static void close_fd(int *fd)
{
	if (*fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

/* Reads both pipes to EOF. Returns NULL, or the named observation failure (addendum 2 B2); the two descriptors are closed
 * either way. */
static const char *read_both(int fo, int fe, sr_buf *o, sr_buf *e)
{
	struct pollfd p[2] = {{fo, POLLIN, 0}, {fe, POLLIN, 0}};
	int open_n = 2;
	char tmp[65536];
	const char *fail = NULL;
	while (open_n > 0 && !fail) {
		if (poll(p, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			fail = "reading spinel's output failed (poll)";
			break;
		}
		for (int k = 0; k < 2; k++) {
			if (p[k].fd < 0 || !(p[k].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
				continue;
			ssize_t r = read(p[k].fd, tmp, sizeof tmp);
			if (r < 0 && errno == EINTR)
				continue;
			if (r < 0) {
				fail = "reading spinel's output failed (read)";
				break;
			}
			if (r == 0) {
				close_fd(&p[k].fd);
				open_n--;
				continue;
			}
			sr_put(k == 0 ? o : e, tmp, (size_t)r);
		}
	}
	close_fd(&p[0].fd);
	close_fd(&p[1].fd);
	return fail;
}

/* starts argv in cwd (NULL: inherit) with env; captures stdout and stderr */
static run_out spawn(char *const argv[], const char *cwd, char *const env[])
{
	run_out ro = {{"", 0}, {"", 0}, 1, 0, NULL};
	int po[2] = {-1, -1}, pe[2] = {-1, -1}, px[2] = {-1, -1};
	if (pipe2(po, O_CLOEXEC) || pipe2(pe, O_CLOEXEC) || pipe2(px, O_CLOEXEC)) {
		/* Go's start error: the run failed */
		for (int i = 0; i < 2; i++) {
			close_fd(&po[i]);
			close_fd(&pe[i]);
			close_fd(&px[i]);
		}
		return ro;
	}
	pid_t pid = fork();
	if (pid < 0) {
		for (int i = 0; i < 2; i++) {
			close_fd(&po[i]);
			close_fd(&pe[i]);
			close_fd(&px[i]);
		}
		return ro;
	}
	if (pid == 0) {
		int nul = open("/dev/null", O_RDONLY);
		if (nul < 0 || dup2(nul, 0) < 0 || dup2(po[1], 1) < 0 || dup2(pe[1], 2) < 0)
			goto fail;
		if (cwd && chdir(cwd) != 0)
			goto fail;
		execve(argv[0], argv, env);
	fail:;
		int e = errno;
		(void)!write(px[1], &e, sizeof e);
		_exit(127);
	}
	close_fd(&po[1]);
	close_fd(&pe[1]);
	close_fd(&px[1]);
	sr_buf o = {0}, e = {0};
	const char *fail = read_both(po[0], pe[0], &o, &e);
	int child_errno = 0;
	ssize_t got = 0;
	if (!fail) {
		/* the start-status pipe: 0 bytes (exec succeeded) or one int (the child's errno) */
		size_t have = 0;
		for (;;) {
			ssize_t r = read(px[0], (char *)&child_errno + have, sizeof child_errno - have);
			if (r < 0 && errno == EINTR)
				continue;
			if (r < 0) {
				fail = "spinel's start status could not be read";
				break;
			}
			if (r == 0)
				break;
			have += (size_t)r;
			if (have == sizeof child_errno)
				break;
		}
		if (!fail && have != 0 && have != sizeof child_errno)
			fail = "spinel's start status could not be read";
		got = (ssize_t)have;
	}
	close_fd(&px[0]);
	int st = 0;
	int reaped = 0;
	if (!fail) {
		for (;;) {
			if (waitpid(pid, &st, 0) >= 0) {
				reaped = 1;
				break;
			}
			if (errno == EINTR)
				continue;
			fail = "waiting for spinel failed";
			break;
		}
	}
	if (fail) {
		/* addendum 3: the outcome is unknown, so the child is killed and waited for once more; the text says whether the
		 * reap was seen, and an unobserved reap is never reported as done */
		int first_wait = !reaped && strcmp(fail, "waiting for spinel failed") == 0;
		kill(pid, SIGKILL);
		int seen = 0;
		for (;;) {
			int st2;
			if (waitpid(pid, &st2, 0) >= 0) {
				seen = 1;
				break;
			}
			if (errno != EINTR)
				break;
		}
		sr_buf m = {0};
		sr_puts(&m, fail);
		if (!seen)
			sr_puts(&m, "; the child was killed but its reaping is unconfirmed");
		else if (first_wait)
			sr_puts(&m, "; the child was killed and reaped");
		sr_putc(&m, '\0');
		ro.unobserved = m.p;
		return ro;
	}
	if (got == (ssize_t)sizeof child_errno) {
		/* Go's start failure: no output, the run failed */
		return ro;
	}
	ro.started = 1;
	ro.out = sr_bufstr(&o);
	ro.err = sr_bufstr(&e);
	ro.failed = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	return ro;
}

static char **env_with_tmpdir(const char *tmp)
{
	size_t n = 0;
	while (environ[n])
		n++;
	char **env = sr_alloc((n + 2) * sizeof *env);
	size_t k = 0;
	for (size_t i = 0; i < n; i++)
		if (strncmp(environ[i], "TMPDIR=", 7) != 0)
			env[k++] = environ[i];
	sr_buf b = {0};
	sr_puts(&b, "TMPDIR=");
	sr_puts(&b, tmp);
	env[k++] = b.p;
	env[k] = NULL;
	return env;
}

/* Spinel.run */
static run_out s_run(const sr_spinel *s, const char *dir, const char *const *args, size_t nargs)
{
	run_out ro = {{"", 0}, {"", 0}, 1, 0, NULL};
	char *tmp = join2(dir, "tmp");
	if (mkdir_all(tmp, 0755) != 0)
		return ro;
	char **argv = sr_alloc((nargs + 4) * sizeof *argv);
	argv[0] = (char *)s->bin;
	argv[1] = "-I";
	argv[2] = (char *)s->lib_dir;
	for (size_t i = 0; i < nargs; i++)
		argv[3 + i] = (char *)args[i];
	argv[3 + nargs] = NULL;
	return spawn(argv, dir, env_with_tmpdir(tmp));
}

sr_str sr_first_lines(sr_str b, int n)
{
	sr_str t = sr_trim_space(b);
	sr_buf o = {0};
	int k = 0;
	size_t s = 0;
	for (;;) {
		const char *nl = memchr(t.p + s, '\n', t.n - s);
		size_t e = nl ? (size_t)(nl - t.p) : t.n;
		if (k > 0)
			sr_puts(&o, " | ");
		sr_put(&o, t.p + s, e - s);
		k++;
		if (!nl || k == n)
			break;
		s = e + 1;
	}
	return sr_bufstr(&o);
}

static sr_diag sb000(sr_str file, int64_t line, int64_t col, sr_str msg)
{
	return (sr_diag){sr_cstr("SB000"), file, msg, line, col};
}

static sr_str cat(const char *a, sr_str b)
{
	sr_buf o = {0};
	sr_puts(&o, a);
	sr_putstr(&o, b);
	return sr_bufstr(&o);
}

static sr_result check_args(const sr_spinel *s, const char *dir, const char *base)
{
	if (!strchr(s->bin, '/'))
		return sr_not_ported("a Spinel binary named without '/' (Go's exec.LookPath)");
	if (!clean_abs(dir))
		return sr_not_ported("a work directory that is not an absolute clean path (Go's filepath.Join cleans it)");
	if (!plain_name(base))
		return sr_not_ported("a source name that is not a plain file name (Go's filepath.Join cleans it)");
	return sr_ok;
}

sr_result sr_analyze(const sr_spinel *s, const char *dir, const char *base, sr_str text, sr_analysis *out)
{
	memset(out, 0, sizeof *out);
	sr_result c = check_args(s, dir, base);
	if (c.kind)
		return c;
	sr_str bs = sr_cstr(base);
	if (mkdir_all(dir, 0755) != 0)
		return sr_not_ported("os.MkdirAll of the work directory failed (Go returns its error text)");
	char *src = join2(dir, base);
	int fd = open(src, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return sr_not_ported("os.WriteFile of the source failed (Go returns its error text)");
	for (size_t off = 0; off < text.n;) {
		ssize_t w = write(fd, text.p + off, text.n - off);
		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0) {
			close(fd);
			return sr_not_ported("os.WriteFile of the source failed (Go returns its error text)");
		}
		off += (size_t)w;
	}
	if (close(fd) != 0)
		return sr_not_ported("os.WriteFile of the source failed (Go returns its error text)");

	const char *a1[] = {"--dump-ast", "--emit-types", base};
	run_out r1 = s_run(s, dir, a1, 3);
	if (r1.unobserved)
		return sr_not_ported("%s", r1.unobserved);
	if (r1.failed) {
		out->diags = sr_alloc(sizeof *out->diags);
		out->diags[0] = sb000(bs, 0, 0, cat("spinel --dump-ast failed: ", sr_first_lines(r1.err, 5)));
		out->n_diags = 1;
		return sr_ok;
	}
	char *json_path = join2(dir, "types.json");
	if (unlink(json_path) != 0)
		(void)rmdir(json_path); /* os.Remove; its error is ignored */
	const char *a2[] = {"--emit-types", base, "-o", json_path};
	run_out r2 = s_run(s, dir, a2, 4);
	if (r2.unobserved)
		return sr_not_ported("%s", r2.unobserved);

	sr_buf data = {0};
	int jfd = open(json_path, O_RDONLY | O_CLOEXEC);
	int read_ok = jfd >= 0;
	if (read_ok) {
		char tmp[65536];
		for (;;) {
			ssize_t r = read(jfd, tmp, sizeof tmp);
			if (r < 0 && errno == EINTR)
				continue;
			if (r < 0) {
				read_ok = 0;
				break;
			}
			if (r == 0)
				break;
			sr_put(&data, tmp, (size_t)r);
		}
		close(jfd);
	}
	if (!read_ok) {
		out->diags = sr_alloc(sizeof *out->diags);
		out->diags[0] = sb000(bs, 0, 0, cat("spinel --emit-types wrote no JSON: ", sr_first_lines(r2.err, 5)));
		out->n_diags = 1;
		return sr_ok;
	}
	sr_ast *ast;
	sr_result e = sr_parse_ast(r1.out, &ast);
	if (e.kind)
		return e;
	sr_types *t;
	/* The types are bound to this invocation's AST, after both are decoded and before any index or span use */
	sr_type_rec *sel;
	size_t n_sel;
	e = sr_parse_types_ast(sr_bufstr(&data), ast, &t, &sel, &n_sel);
	if (e.kind)
		return e;
	size_t nd = 0;
	sr_diag *ds = sr_alloc((t->n_diags + 1) * sizeof *ds);
	for (size_t i = 0; i < t->n_diags; i++) {
		sr_diag_rec *d = &t->diags[i];
		if (!sr_eqc(d->severity, "error"))
			continue;
		ds[nd++] = sb000(d->file, d->line, d->col + 1, cat("spinel refused the program: ", d->message));
	}
	if (r2.failed && nd == 0)
		ds[nd++] = sb000(bs, 0, 0, cat("spinel --emit-types failed: ", sr_first_lines(r2.err, 5)));
	out->ast = ast;
	out->types = t;
	out->diags = ds;
	out->n_diags = nd;
	return sr_ok;
}

sr_result sr_uses_threads(const sr_spinel *s, const char *dir, const char *base, int *threads)
{
	sr_result c = check_args(s, dir, base);
	if (c.kind)
		return c;
	const char *a[] = {"--print-build", base};
	run_out r = s_run(s, dir, a, 2);
	if (r.unobserved)
		return sr_not_ported("%s", r.unobserved);
	if (r.failed) /* built byte for byte: a NUL in stderr must not end the text (addendum 2 B1) */
		return sr_err_str(cat("spinel --print-build failed: ", sr_first_lines(r.err, 5)));
	*threads = 0;
	size_t st = 0;
	for (;;) {
		const char *nl = memchr(r.out.p + st, '\n', r.out.n - st);
		size_t e = nl ? (size_t)(nl - r.out.p) : r.out.n;
		if (sr_eqc(sr_trim_space((sr_str){r.out.p + st, e - st}), "define -DSP_THREADS")) {
			*threads = 1;
			break;
		}
		if (!nl)
			break;
		st = e + 1;
	}
	return sr_ok;
}

sr_result sr_version(const sr_spinel *s, sr_str *version)
{
	if (!strchr(s->bin, '/'))
		return sr_not_ported("a Spinel binary named without '/' (Go's exec.LookPath)");
	char *argv[] = {(char *)s->bin, "--version", NULL};
	run_out r = spawn(argv, NULL, environ);
	if (r.unobserved)
		return sr_not_ported("%s", r.unobserved);
	if (r.failed)
		return sr_not_ported("spinel --version failed (Go returns the exec error)");
	*version = sr_trim_space(r.out);
	return sr_ok;
}
