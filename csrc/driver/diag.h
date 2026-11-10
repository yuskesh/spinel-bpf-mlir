/* csrc/driver/diag.h - the frontend's diagnostics as the driver prints them (internal/frontend/result.go: Diag.String,
 * Diags.Sorted, Error) and the domain reader (internal/frontend/domainread.go: ReadDomainGraph). */
#ifndef SPINELBPF_DRIVER_DIAG_H
#define SPINELBPF_DRIVER_DIAG_H

#include <stddef.h>

#include "util.h"

enum verdict { V_VERIFIED, V_REJECTED, V_CONDITIONAL, V_UNKNOWN };

struct pos {
	char *file;
	long long line, col;
};

struct diag {
	enum verdict verdict;
	char *code; /* "SB021" */
	struct pos pos;
	struct strv path;
	char *msg;
};

struct diags {
	struct diag *v;
	size_t n, cap;
};

struct root {
	char *name, *kind;
	struct pos decl, def;
};

struct roots {
	struct root *v;
	size_t n;
};

void diags_push(struct diags *ds, struct diag d);
int diags_blocking(const struct diags *ds);
/* Diags.Sorted: a stable sort by file, line, column, then code (byte order of the code string). */
void diags_sort(struct diags *ds);
/* Pos.String and Diag.String. */
char *pos_str(const struct pos *p);
char *diag_str(const struct diag *d);
/* Error.Error: the sorted diagnostics, one per line, no trailing newline. */
char *diags_error(const struct diags *ds);
/* The name of a reason code, or NULL when it is not in the table. */
const char *code_name(const char *code);
/* The i-th entry of the code table (its code, and its name in *name), or NULL past the end: for the drift test. */
const char *code_at(size_t i, const char **name);

/* ReadDomainGraph: the roots and the diagnostics (in the domain's order). The error text equals Go's. */
err_t read_domain(const char *data, size_t len, struct roots *roots, struct diags *ds);

#endif
