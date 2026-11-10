/* csrc/driver/checks.h - the driver's checks around ebpf-compile (cmd/spinelbpf/build.go, link.go; internal/toolchain RewriteLocs
 * and ParseCompileOutput; internal/frontend/uprobecheck.go). Each error text equals the Go function's. */
#ifndef SPINELBPF_DRIVER_CHECKS_H
#define SPINELBPF_DRIVER_CHECKS_H

#include <stddef.h>

#include "diag.h"
#include "util.h"

/* strings.TrimSpace (Unicode white space, as Go). */
char *go_trim_space(const char *s, size_t n);

/* toolchain.RewriteLocs. */
char *rewrite_locs(const char *output);

/* unrollBudget: when a stderr line is bpf-mlir's unroll budget error, fills d (SB030 at the loop) and returns 1. */
int unroll_budget(const char *stderr_text, struct diag *d);

/* ParseCompileOutput + addCompileWarnings: appends one Conditional SB021 per warning to ds. */
err_t add_compile_warnings(struct diags *ds, const char *stdout_text, const char *stderr_text);

/* checkMapSymbols, checkSchemaSHA (sha_out gets the hex), checkRecordsTable. */
err_t check_map_symbols(const char *elf_path, const char *schema, size_t schema_len);
err_t check_schema_sha(const char *elf_path, const char *schema, size_t schema_len, char sha_out[65]);
err_t check_records_table(const char *schema, size_t schema_len, const char *table);

/* readAllow + CheckNeeded. */
err_t check_needed(const char *exe, const char *allow_path);

/* UprobeBuildCheckFiles. programs, files and decls are parallel (n entries). A refusal is returned as diagnostics in *refused
 * (rc 1, the caller prints them as a frontend error); other failures as an error text. */
struct uprobe_target {
	char *program, *path;
	struct pos decl;
};
err_t uprobe_build_check(const char *elf, size_t elf_len, const struct uprobe_target *t, size_t n, struct diags *refused);
/* The NULL-terminated kind tables of uprobe_build_check (UprobeBuildKinds, UprobeBuildIgnored): for the drift test. */
const char *const *uprobe_build_kinds(void);
const char *const *uprobe_build_ignored(void);

#endif
