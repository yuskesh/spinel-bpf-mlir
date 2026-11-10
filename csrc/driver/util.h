/* csrc/driver/util.h - small helpers of the C driver: growing strings, Go's text forms the driver prints, paths
 * with Go's path/filepath semantics, files and child processes.
 *
 * Memory: the driver runs once per build and exits, so allocations are not freed one by one; the exit frees them, as an arena
 * freed at exit would. Out of memory stops the driver with a named message. */
#ifndef SPINELBPF_DRIVER_UTIL_H
#define SPINELBPF_DRIVER_UTIL_H

#include <stdarg.h>
#include <stddef.h>

/* A growing byte string, always NUL-terminated. */
struct sb {
	char *p;
	size_t n, cap;
};
void sb_put(struct sb *b, const void *data, size_t n);
void sb_puts(struct sb *b, const char *s);
void sb_putc(struct sb *b, char c);
void sb_printf(struct sb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sb_vprintf(struct sb *b, const char *fmt, va_list ap);
char *sb_take(struct sb *b); /* the string (never NULL) */

void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
char *xasprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* A list of strings. */
struct strv {
	char **v;
	size_t n, cap;
};
void strv_push(struct strv *l, char *s);
void strv_sort(struct strv *l); /* Go's sort.Strings: byte order */
/* Go's fmt %v of a []string: "[a b c]". */
char *strv_go(const struct strv *l);

/* Go's %q (strconv.Quote) of a string. Only ASCII is ported: a byte >= 0x80 makes it return NULL, and the caller stops with
 * "not ported" (porting Go's unicode.IsPrint table was planned for the frontend port). */
char *go_quote(const char *s, size_t n);

/* An error: a heap string, or NULL for none. */
typedef char *err_t;
err_t errf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
/* Go's text of a syscall errno (syscall.Errno.Error()). NULL for an errno whose Go text is not in the table. */
const char *go_errno(int e);
/* Go's *fs.PathError text "<op> <path>: <errno text>", or a "not ported" text for an errno outside the table. */
err_t path_error(const char *op, const char *path, int e);

/* path/filepath: Clean, Join (two elements), Dir, Base, IsAbs, and Abs (Clean(Join(cwd, p)) for a relative p). */
char *fp_clean(const char *p);
char *fp_join(const char *a, const char *b);
char *fp_dir(const char *p);
char *fp_base(const char *p);
int fp_is_abs(const char *p);
err_t fp_abs(const char *p, char **out);

/* os.ReadFile / os.WriteFile (mode 0644 before the umask) / os.Stat existence / os.RemoveAll / os.MkdirAll (0755). */
err_t read_file(const char *path, char **data, size_t *len);
err_t write_file(const char *path, const void *data, size_t len);
int path_exists(const char *path); /* os.Stat succeeded */
err_t remove_all(const char *path);
err_t mkdir_all(const char *path);

/* Runs argv[0] (a path; PATH is not searched — the Go driver never names a bare tool) in dir (NULL: the current directory).
 * env NULL keeps the environment; extra_env entries are appended (Go's append(os.Environ(), …)).
 * Output: separate (out and err) or combined (both into out, in arrival order, as Go's CombinedOutput). Either may be NULL to
 * discard. Returns NULL when the child exited 0, else Go's exec error text: "exit status N", "signal: <name>[ (core dumped)]",
 * or "fork/exec <path>: <errno text>" when it could not start. */
struct run_out {
	struct sb out, err;
};
err_t run_cmd(char *const argv[], const char *dir, char *const extra_env[], int combined, struct run_out *o);

/* sha256 hex of bytes (bml_build_sha256_hex). */
void sha256_hex(const void *data, size_t len, char out[65]);

/* "not ported" stop: prints "spinelbpf: not ported: <what>" and exits 1. */
void not_ported(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));

#endif
