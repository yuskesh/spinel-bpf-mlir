/* csrc/pin/pin.h - the pin and version checks of the C build path.
 *
 * C counterparts of internal/toolchain (Check, CheckSpinel, ParseSourceVersion) and internal/version (Text), plus a check
 * of the bml actually linked (replaces cmd/spinelbpf/bml.go checkBMLVersions, which read the bml source tree).
 *
 * Every check returns 0, or nonzero with a NUL-terminated message in err (truncated at errlen - 1).
 * The public form is selected at compile time with -DSPINELBPF_PUBLIC (the C counterpart of the public Go build).
 * The driver's commit stamp is given at build time with -DSPINELBPF_COMMIT_STAMP="<12 hex>[+dirty]" (unset: "unknown"). */
#ifndef SPINELBPF_PIN_H
#define SPINELBPF_PIN_H

#include <stddef.h>

/* The Go driver proves the linked bpf-mlir module by its build info; a C driver that still runs the Go frontend as a subprocess
 * can keep the same order of checks with two hooks. toolchain.Check is: (1) run --version; (2) ModuleVersion (fetch);
 * (3) submoduleSource; (4) Verify: version line, commit, dirty, module-version compare, submodule compare. fetch runs after a
 * successful --version run and before the submodule is read; compare runs after the dirty check and before the submodule
 * compare. A hook returns 0 or nonzero with its text in err, which is returned unchanged. A NULL hook or member is skipped. */
typedef struct {
	int (*fetch)(void *ctx, char *err, size_t errlen);
	int (*compare)(void *ctx, char *err, size_t errlen);
	void *ctx;
} pin_module_hook;

/* Runs `<ebpf_compile> --version`, reads the `bpf-mlir <describe> (commit <sha>)` line and checks the commit against the pin,
 * the describe against "-dirty" / "unknown", and the commit against the third_party/bpf-mlir gitlink of repo (dev form) or
 * its SOURCE_VERSION source_commit (public form). repo may be NULL or "" (no repo check). The messages equal Go's toolchain.Check
 * except that the Go-module step does not exist here (the linked code is checked by pin_check_bml). On success out_commit
 * holds the 40-hex commit. */
int pin_check_compiler(const char *ebpf_compile, const char *repo, char out_commit[41], char *err, size_t errlen);

int pin_check_compiler_hook(const char *ebpf_compile, const char *repo, char out_commit[41], const pin_module_hook *h, char *err, size_t errlen);

/* Runs `<spinel> --version` and checks the commit against the pin and the third_party/spinel HEAD. Equals toolchain.CheckSpinel. */
int pin_check_spinel(const char *spinel, const char *repo, char *err, size_t errlen);

/* Reads the version facts of the libbml.a linked into this process (bml_source_form, bml_source_commit, bml_source_dirty,
 * bml_bpf_mlir_commit, bml_policy_version, bml_max_format_version) and checks them against the pins. Its messages are new
 * (named per check), not the Go ones. The source commit must equal the whole pinned commit (PIN_BML_COMMIT_FULL) whether or not a
 * repo is given. repo is used in the dev form to read the pinned bpf-mlir source's policy version and
 * format limit; NULL or "" uses the pinned constants. */
int pin_check_bml(const char *repo, char *err, size_t errlen);

/* Lower-level entry points (the tests call them; the driver does not need them). */
int pin_release_source(const char *repo, const char *want, char out[64], char *err, size_t errlen);
int pin_verify_compiler_hook(const char *version_output, const char *submodule_commit, const pin_module_hook *h, char desc_out[256], char commit_out[128], char *err, size_t errlen);
int pin_verify_compiler(const char *version_output, const char *submodule_commit, char desc_out[256], char commit_out[128], char *err, size_t errlen);
int pin_verify_spinel(const char *version_output, const char *submodule_head, char commit_out[64], char *err, size_t errlen);
/* version points into b (not copied: it may be of any length); commit is 40 hex plus NUL. */
int pin_parse_source_version(const char *b, size_t blen, const char **version, size_t *version_len, char commit[41], char *err, size_t errlen);
/* Length-aware forms: the text may hold NUL bytes (Go's regexp reads them as ordinary bytes); the non-_n forms use strlen. */
int pin_verify_compiler_hook_n(const char *text, size_t n, const char *submodule_commit, const pin_module_hook *h, char desc_out[256], char commit_out[128], char *err, size_t errlen);
int pin_verify_compiler_n(const char *text, size_t n, const char *submodule_commit, char desc_out[256], char commit_out[128], char *err, size_t errlen);
int pin_verify_spinel_n(const char *text, size_t n, const char *submodule_head, char commit_out[64], char *err, size_t errlen);

/* The facts of a bml (read from the linked libbml.a by pin_bml_facts_read) and the check on them. */
typedef struct {
	char form[16];
	char source_commit[64];
	int dirty;
	char bpf_mlir_commit[64];
	long policy_version;
	long max_format;
} pin_bml_facts;
void pin_bml_facts_read(pin_bml_facts *f);
int pin_check_bml_facts(const pin_bml_facts *f, const char *repo, char *err, size_t errlen);

/* The text of `spinelbpf --version` (malloc'd, caller frees). ec_version_line is the first `bpf-mlir ...` line of
 * `ebpf-compile --version` or NULL / "" for "not found". All five lines equal Go's version.Text from a go build
 * binary in the development form (line 1 from the build stamp, line 2 from the pinned module version). In the public form line 2 is
 * compared with Go's bpfMLIRLine on a synthetic BuildInfo only — partial evidence (no binary was built from the real public tree). */
char *pin_version_text(const char *ec_version_line);

#endif
