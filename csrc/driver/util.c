/* csrc/driver/util.c - see util.h. */
#define _GNU_SOURCE
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bml/build.h"

extern char **environ;

static void oom(void)
{
	fputs("spinelbpf: out of memory\n", stderr);
	exit(1);
}

void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		oom();
	return p;
}

void *xrealloc(void *p, size_t n)
{
	p = realloc(p, n ? n : 1);
	if (!p)
		oom();
	return p;
}

char *xstrdup(const char *s) { return xstrndup(s, strlen(s)); }

char *xstrndup(const char *s, size_t n)
{
	char *p = xmalloc(n + 1);
	memcpy(p, s, n);
	p[n] = 0;
	return p;
}

void sb_put(struct sb *b, const void *data, size_t n)
{
	if (b->n + n + 1 > b->cap) {
		size_t c = b->cap ? b->cap : 64;
		while (c < b->n + n + 1)
			c *= 2;
		b->p = xrealloc(b->p, c);
		b->cap = c;
	}
	if (n)
		memcpy(b->p + b->n, data, n);
	b->n += n;
	b->p[b->n] = 0;
}

void sb_puts(struct sb *b, const char *s) { sb_put(b, s, strlen(s)); }
void sb_putc(struct sb *b, char c) { sb_put(b, &c, 1); }

void sb_vprintf(struct sb *b, const char *fmt, va_list ap)
{
	va_list aq;
	va_copy(aq, ap);
	int n = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);
	if (n < 0)
		oom();
	char *t = xmalloc((size_t)n + 1);
	vsnprintf(t, (size_t)n + 1, fmt, ap);
	sb_put(b, t, (size_t)n);
	free(t);
}

void sb_printf(struct sb *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	sb_vprintf(b, fmt, ap);
	va_end(ap);
}

char *sb_take(struct sb *b)
{
	if (!b->p)
		sb_put(b, "", 0);
	char *p = b->p;
	b->p = NULL;
	b->n = b->cap = 0;
	return p;
}

char *xasprintf(const char *fmt, ...)
{
	struct sb b = {0};
	va_list ap;
	va_start(ap, fmt);
	sb_vprintf(&b, fmt, ap);
	va_end(ap);
	return sb_take(&b);
}

void strv_push(struct strv *l, char *s)
{
	if (l->n == l->cap) {
		l->cap = l->cap ? l->cap * 2 : 8;
		l->v = xrealloc(l->v, l->cap * sizeof *l->v);
	}
	l->v[l->n++] = s;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

void strv_sort(struct strv *l)
{
	if (l->n > 1)
		qsort(l->v, l->n, sizeof *l->v, cmp_str);
}

char *strv_go(const struct strv *l)
{
	struct sb b = {0};
	sb_putc(&b, '[');
	for (size_t i = 0; i < l->n; i++) {
		if (i)
			sb_putc(&b, ' ');
		sb_puts(&b, l->v[i]);
	}
	sb_putc(&b, ']');
	return sb_take(&b);
}

/* strconv.Quote for ASCII: \a \b \f \n \r \t \v \\ \" escaped, other control bytes and DEL as \xNN. */
char *go_quote(const char *s, size_t n)
{
	struct sb b = {0};
	sb_putc(&b, '"');
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c >= 0x80) {
			free(b.p);
			return NULL;
		}
		switch (c) {
		case '\a': sb_puts(&b, "\\a"); break;
		case '\b': sb_puts(&b, "\\b"); break;
		case '\f': sb_puts(&b, "\\f"); break;
		case '\n': sb_puts(&b, "\\n"); break;
		case '\r': sb_puts(&b, "\\r"); break;
		case '\t': sb_puts(&b, "\\t"); break;
		case '\v': sb_puts(&b, "\\v"); break;
		case '\\': sb_puts(&b, "\\\\"); break;
		case '"': sb_puts(&b, "\\\""); break;
		default:
			if (c < 0x20 || c == 0x7f)
				sb_printf(&b, "\\x%02x", c);
			else
				sb_putc(&b, (char)c);
		}
	}
	sb_putc(&b, '"');
	return sb_take(&b);
}

err_t errf(const char *fmt, ...)
{
	struct sb b = {0};
	va_list ap;
	va_start(ap, fmt);
	sb_vprintf(&b, fmt, ap);
	va_end(ap);
	return sb_take(&b);
}

/* Go's syscall error strings for linux/amd64 (zerrors_linux_amd64.go), for the errnos a build can meet on files and exec. */
static const struct {
	int e;
	const char *s;
} errnos[] = {
	{EPERM, "operation not permitted"},
	{ENOENT, "no such file or directory"},
	{EIO, "input/output error"},
	{E2BIG, "argument list too long"},
	{ENOEXEC, "exec format error"},
	{ENOMEM, "cannot allocate memory"},
	{EACCES, "permission denied"},
	{EBUSY, "device or resource busy"},
	{EEXIST, "file exists"},
	{ENOTDIR, "not a directory"},
	{EISDIR, "is a directory"},
	{EINVAL, "invalid argument"},
	{EMFILE, "too many open files"},
	{ETXTBSY, "text file busy"},
	{ENOSPC, "no space left on device"},
	{EROFS, "read-only file system"},
	{ENAMETOOLONG, "file name too long"},
	{ENOTEMPTY, "directory not empty"},
	{ELOOP, "too many levels of symbolic links"},
};

const char *go_errno(int e)
{
	for (size_t i = 0; i < sizeof errnos / sizeof errnos[0]; i++)
		if (errnos[i].e == e)
			return errnos[i].s;
	return NULL;
}

err_t path_error(const char *op, const char *path, int e)
{
	const char *s = go_errno(e);
	if (!s)
		return errf("not ported: errno %d (%s) on %s %s has no Go text in the driver's table", e, strerror(e), op, path);
	return errf("%s %s: %s", op, path, s);
}

/* ---- path/filepath (Unix) ---- */

char *fp_clean(const char *p)
{
	size_t n = strlen(p);
	if (n == 0)
		return xstrdup(".");
	int rooted = p[0] == '/';
	char *out = xmalloc(n + 2);
	size_t w = 0, r = 0, dotdot = 0;
	if (rooted) {
		out[w++] = '/';
		r = 1;
		dotdot = 1;
	}
	while (r < n) {
		if (p[r] == '/') {
			r++;
		} else if (p[r] == '.' && (r + 1 == n || p[r + 1] == '/')) {
			r++;
		} else if (p[r] == '.' && p[r + 1] == '.' && (r + 2 == n || p[r + 2] == '/')) {
			r += 2;
			if (w > dotdot) {
				w--;
				while (w > dotdot && out[w] != '/')
					w--;
			} else if (!rooted) {
				if (w > 0)
					out[w++] = '/';
				out[w++] = '.';
				out[w++] = '.';
				dotdot = w;
			}
		} else {
			if ((rooted && w != 1) || (!rooted && w != 0))
				out[w++] = '/';
			for (; r < n && p[r] != '/'; r++)
				out[w++] = p[r];
		}
	}
	if (w == 0)
		out[w++] = '.';
	out[w] = 0;
	return out;
}

char *fp_join(const char *a, const char *b)
{
	if (!*a && !*b)
		return xstrdup("");
	if (!*a)
		return fp_clean(b);
	if (!*b)
		return fp_clean(a);
	char *t = xasprintf("%s/%s", a, b);
	char *c = fp_clean(t);
	free(t);
	return c;
}

char *fp_dir(const char *p)
{
	const char *s = strrchr(p, '/');
	size_t n = s ? (size_t)(s - p) + 1 : 0;
	char *d = xstrndup(p, n);
	char *c = fp_clean(d);
	free(d);
	return c;
}

char *fp_base(const char *p)
{
	if (!*p)
		return xstrdup(".");
	size_t n = strlen(p);
	while (n > 0 && p[n - 1] == '/')
		n--;
	if (n == 0)
		return xstrdup("/");
	size_t i = n;
	while (i > 0 && p[i - 1] != '/')
		i--;
	return xstrndup(p + i, n - i);
}

int fp_is_abs(const char *p) { return p[0] == '/'; }

/* os.Getwd: $PWD when it is absolute and names the current directory, else getcwd. */
static err_t go_getwd(char **out)
{
	const char *pwd = getenv("PWD");
	struct stat a, b;
	if (pwd && pwd[0] == '/' && stat(pwd, &a) == 0 && stat(".", &b) == 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino) {
		*out = xstrdup(pwd);
		return NULL;
	}
	char *c = getcwd(NULL, 0);
	if (!c)
		return path_error("getwd", ".", errno);
	*out = c;
	return NULL;
}

err_t fp_abs(const char *p, char **out)
{
	if (fp_is_abs(p)) {
		*out = fp_clean(p);
		return NULL;
	}
	char *wd;
	err_t e = go_getwd(&wd);
	if (e)
		return e;
	*out = fp_join(wd, p);
	return NULL;
}

/* ---- files ---- */

err_t read_file(const char *path, char **data, size_t *len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return path_error("open", path, errno);
	struct sb b = {0};
	char buf[65536];
	for (;;) {
		ssize_t r = read(fd, buf, sizeof buf);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			int e = errno;
			close(fd);
			return path_error("read", path, e);
		}
		if (r == 0)
			break;
		sb_put(&b, buf, (size_t)r);
	}
	close(fd);
	*len = b.n;
	*data = sb_take(&b);
	return NULL;
}

err_t write_file(const char *path, const void *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return path_error("open", path, errno);
	const char *p = data;
	while (len > 0) {
		ssize_t w = write(fd, p, len);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			int e = errno;
			close(fd);
			return path_error("write", path, e);
		}
		p += w;
		len -= (size_t)w;
	}
	if (close(fd) != 0)
		return path_error("close", path, errno);
	return NULL;
}

int path_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

err_t remove_all(const char *path)
{
	struct stat st;
	if (lstat(path, &st) != 0)
		return errno == ENOENT ? NULL : path_error("unlinkat", path, errno);
	if (S_ISDIR(st.st_mode)) {
		DIR *d = opendir(path);
		if (!d)
			return path_error("open", path, errno);
		struct dirent *de;
		while ((de = readdir(d))) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			char *c = fp_join(path, de->d_name);
			err_t e = remove_all(c);
			free(c);
			if (e) {
				closedir(d);
				return e;
			}
		}
		closedir(d);
		if (rmdir(path) != 0 && errno != ENOENT)
			return path_error("unlinkat", path, errno);
		return NULL;
	}
	if (unlink(path) != 0 && errno != ENOENT)
		return path_error("unlinkat", path, errno);
	return NULL;
}

err_t mkdir_all(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return NULL;
		return path_error("mkdir", path, ENOTDIR);
	}
	char *parent = fp_dir(path);
	if (strcmp(parent, path) != 0) {
		err_t e = mkdir_all(parent);
		if (e) {
			free(parent);
			return e;
		}
	}
	free(parent);
	if (mkdir(path, 0755) != 0 && errno != EEXIST)
		return path_error("mkdir", path, errno);
	return NULL;
}

/* ---- child processes ---- */

/* Go's signal names (syscall signal table, linux). */
static const char *go_signal(int s)
{
	switch (s) {
	case SIGHUP: return "hangup";
	case SIGINT: return "interrupt";
	case SIGQUIT: return "quit";
	case SIGILL: return "illegal instruction";
	case SIGTRAP: return "trace/breakpoint trap";
	case SIGABRT: return "aborted";
	case SIGBUS: return "bus error";
	case SIGFPE: return "floating point exception";
	case SIGKILL: return "killed";
	case SIGUSR1: return "user defined signal 1";
	case SIGSEGV: return "segmentation fault";
	case SIGUSR2: return "user defined signal 2";
	case SIGPIPE: return "broken pipe";
	case SIGALRM: return "alarm clock";
	case SIGTERM: return "terminated";
	}
	return NULL;
}

/* The key of an environment entry as Go's dedupEnvCase reads it (case-sensitive): up to the first '=', or up to the second when
 * the entry starts with '='; -1 when there is no '=' (the entry is kept as is). */
static ssize_t env_key_len(const char *kv)
{
	const char *q = strchr(kv, '=');
	if (q == kv) {
		const char *r = strchr(kv + 1, '=');
		q = r ? r : kv; /* Go: strings.Index(kv[1:], "=") + 1, which is 0 when there is no second '=' */
	}
	return q ? q - kv : -1;
}

/* Go's dedupEnv: the last occurrence of each key, in the order of those occurrences; empty entries are dropped. */
static void dedup_env(struct strv *in, struct strv *out)
{
	size_t n = in->n;
	char **keep = xmalloc((n ? n : 1) * sizeof *keep);
	size_t k = 0;
	for (size_t i = n; i > 0; i--) {
		char *kv = in->v[i - 1];
		ssize_t l = env_key_len(kv);
		if (l < 0) {
			if (*kv)
				keep[k++] = kv;
			continue;
		}
		int seen = 0;
		for (size_t j = 0; j < k && !seen; j++) {
			ssize_t lj = env_key_len(keep[j]);
			seen = lj == l && memcmp(keep[j], kv, (size_t)l) == 0;
		}
		if (!seen)
			keep[k++] = kv;
	}
	for (size_t i = k; i > 0; i--)
		strv_push(out, keep[i - 1]);
	free(keep);
}

err_t run_cmd(char *const argv[], const char *dir, char *const extra_env[], int combined, struct run_out *o)
{
	/* the environment as exec.Cmd.environ builds it: os.Environ() plus extra_env, or, with a dir and no extra_env (Go's Env nil),
	 * os.Environ() plus PWD=<abs dir>; then dedupEnv (the last value of each key wins) */
	struct strv raw = {0}, env = {0};
	for (char **e = environ; *e; e++)
		strv_push(&raw, *e);
	if (extra_env) {
		for (char *const *e = extra_env; *e; e++)
			strv_push(&raw, *e);
	} else if (dir) {
		char *a;
		err_t ae = fp_abs(dir, &a);
		if (ae)
			return ae;
		strv_push(&raw, xasprintf("PWD=%s", a));
	}
	dedup_env(&raw, &env);
	strv_push(&env, NULL);
	/* os.StartProcess stats the directory in the parent and reports its error as chdir; a failure in the child (chdir or exec) is
	 * fork/exec of the program */
	if (dir) {
		struct stat st;
		if (stat(dir, &st) != 0)
			return path_error("chdir", dir, errno);
	}

	int po[2], pe[2], px[2];
	if (pipe2(po, O_CLOEXEC) || pipe2(pe, O_CLOEXEC) || pipe2(px, O_CLOEXEC))
		return errf("pipe: %s", go_errno(errno) ? go_errno(errno) : strerror(errno));
	pid_t pid = fork();
	if (pid < 0)
		return path_error("fork/exec", argv[0], errno);
	if (pid == 0) {
		int nul = open("/dev/null", O_RDONLY);
		if (nul >= 0)
			dup2(nul, 0);
		dup2(po[1], 1);
		dup2(combined ? po[1] : pe[1], 2);
		if (dir && chdir(dir) != 0) {
			int e = errno;
			(void)!write(px[1], &e, sizeof e);
			_exit(127);
		}
		execve(argv[0], argv, env.v);
		int e = errno;
		(void)!write(px[1], &e, sizeof e);
		_exit(127);
	}
	close(po[1]);
	close(pe[1]);
	close(px[1]);
	int xe = 0;
	ssize_t xr;
	do
		xr = read(px[0], &xe, sizeof xe);
	while (xr < 0 && errno == EINTR);
	close(px[0]);
	struct pollfd fds[2] = {{po[0], POLLIN, 0}, {pe[0], POLLIN, 0}};
	int open_fds = 2;
	char buf[65536];
	while (open_fds > 0) {
		if (poll(fds, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (int i = 0; i < 2; i++) {
			if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
			ssize_t r = read(fds[i].fd, buf, sizeof buf);
			if (r > 0) {
				if (o)
					sb_put(i == 0 ? &o->out : &o->err, buf, (size_t)r);
			} else if (r == 0 || errno != EINTR) {
				close(fds[i].fd);
				fds[i].fd = -1;
				open_fds--;
			}
		}
	}
	int st;
	while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
		;
	if (xr == (ssize_t)sizeof xe)
		return path_error("fork/exec", argv[0], xe);
	if (WIFEXITED(st)) {
		if (WEXITSTATUS(st) == 0)
			return NULL;
		return errf("exit status %d", WEXITSTATUS(st));
	}
	if (WIFSIGNALED(st)) {
		const char *s = go_signal(WTERMSIG(st));
		if (!s)
			return errf("not ported: the child was stopped by signal %d, which has no Go name in the driver's table", WTERMSIG(st));
		return errf("signal: %s%s", s, WCOREDUMP(st) ? " (core dumped)" : "");
	}
	return errf("not ported: wait status %#x", st);
}

void sha256_hex(const void *data, size_t len, char out[65]) { bml_build_sha256_hex(data, len, out); }

void not_ported(const char *fmt, ...)
{
	struct sb b = {0};
	va_list ap;
	va_start(ap, fmt);
	sb_vprintf(&b, fmt, ap);
	va_end(ap);
	fprintf(stderr, "spinelbpf: not ported: %s\n", b.p);
	exit(1);
}
