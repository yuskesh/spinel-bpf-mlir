/* csrc/driver/seam.h - the seam reader (cmd/spinelbpf/seam.go: an emit and an inspect directory with a manifest). The C driver
 * reads both the --seam-* input and its own Go frontend subprocess's output with it. */
#ifndef SPINELBPF_DRIVER_SEAM_H
#define SPINELBPF_DRIVER_SEAM_H

#include <stddef.h>

#include "checks.h"
#include "diag.h"
#include "util.h"

struct seam_input {
	/* the domain (always set when the seam input is returned), and its diagnostics */
	char *domain;
	size_t domain_len;
	struct diags diags;
	/* rc 0 only */
	char *mlir, *schema, *maps, *records;
	size_t mlir_len, schema_len, maps_len, records_len;
	struct uprobe_target *uprobes;
	size_t n_uprobes;
	/* the manifest's bytes, written next to the outputs on success with --seam-* */
	char *manifest;
	size_t manifest_len;
};

/* readSeam. bpf_commit NULL skips the pins.bpf_mlir.commit comparison (the frontend subprocess on the reuse path, where Go runs
 * no compiler or module check). Returns:
 *   - NULL error and *in set: rc 0, generated;
 *   - a refusal: *refused set to 1, *in set, the diagnostics in in->diags (printed as Error.Error());
 *   - an error text, with *in set when Go's readSeam returns its Output with the error (the domain is then written). */
err_t read_seam(const char *emit_dir, const char *inspect_dir, const char *abs, const char *name, const char *bpf_commit,
		struct seam_input **in, int *refused);

#endif
