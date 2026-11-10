/* csrc/driver/build.h - the build and link steps of the C driver (cmd/spinelbpf/build.go Build, link.go reuseCommitted, Link). */
#ifndef SPINELBPF_DRIVER_BUILD_H
#define SPINELBPF_DRIVER_BUILD_H

#include "diag.h"
#include "util.h"

struct config {
	char *repo, *spinel, *ebpf_compile, *schema_check, *clang, *loader_libs;
	const char *line_info;
	const char *seam_emit, *seam_inspect; /* NULL: the C frontend in this process (cfront.c) */
};

/* defaultConfig. */
err_t default_config(struct config *c);

struct build_result {
	int has_output; /* Go's r != nil && r.Output != nil */
	char *domain;   /* may be NULL */
	size_t domain_len;
	struct diags diags; /* the frontend's diagnostics plus SB021 */
	struct strv files;
	int reused;
	char *refusal_text; /* set with *refused when the refusal is the frontend's own Error() text (SB017), printed as is */
};

/* Build. Returns NULL on success. On failure: an error text (printed "spinelbpf: <text>"), or *refused set with the
 * diagnostics to print as Error.Error() in *refusal. *r is set as Go's BuildResult is (has_output 0 when Go returns r == nil). */
err_t build(const struct config *c, const char *source, struct build_result *r, int *refused, struct diags *refusal);

/* Link. */
err_t link_exe(const struct config *c, const char *source, const char *exe);

#endif
