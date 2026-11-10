/* csrc/driver/cfront.h - the C frontend in the driver's process. It replaces the Go frontend subprocess (a temporary Go
 * command, removed when the C frontend became the default) and keeps its contract: it writes the same seam layout, read by read_seam.
 *   E: x.mlir, x.schema.json, x.maps.json, x.records.txt, x.uprobe_targets.json (generated only)
 *   I: x.domain.json (whenever the analysis made a domain), x.inspect-manifest.json (rc 0 and 1)
 * Return codes, as the subprocess's exit codes:
 *   0  generated
 *   1  a refusal whose diagnostics are the domain's (read_seam reads them)
 *   3  any other error; *text is Go's err.Error() text (the driver prints "spinelbpf: <text>")
 *   5  a refusal that is not the domain's (SB017, Lower failed); *text is the refusal's Error() text, printed as is
 * An input the C frontend cannot reproduce Go's bytes for (a not-ported stop) is rc 3 with a text that names it: loud, and never
 * a fallback to another frontend. */
#ifndef SPINELBPF_DRIVER_CFRONT_H
#define SPINELBPF_DRIVER_CFRONT_H

int c_frontend_generate(const char *repo, const char *spinel, const char *emit, const char *inspect, const char *work,
			const char *abs, char **text);

#endif
