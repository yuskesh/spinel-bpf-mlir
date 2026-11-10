/* dump_read — a reader of the canonical dump (internal/frontend/e178_dump_test.go holds the format, csrc/frontend/dump.c
 * prints it) back into a fe_result, so the C writers of schema.json, maps.json and records.txt can run on a Go Result.
 *
 * Scope: every line is read and checked against the path the dumper prints at that place, in the
 * dumper's order. Every field is stored except the statement and expression subtrees of a program, Body, FRet, RedirKey and
 * FmodVal: the three writers do not read them, so they are consumed by path (every line at or below the subtree's path) and left
 * nil. The domain line must be a quoted string; its text is not stored (fe_domain_graph rebuilds it from the Result).
 *
 * Pointers: a declaration is created for each "decl <kind>:<Const>" line before anything is read, so a reference may come before
 * its block (two passes). "&<kind>:<Const>" is the registered object, "anon <kind>" a new one read in full at that path. Errors are
 * loud: a line that is not the expected path, a malformed value, a reference to an id with no decl block, two decl blocks with
 * one id, a reference of the wrong kind, an error dump, and anything left after the Result. */
#ifndef FRONTEND_DUMP_READ_H
#define FRONTEND_DUMP_READ_H

#include "body.h"

/* Reads `text` into *out (zeroed first). sr_ok, or an error naming the 1-based line and what was wrong. */
sr_result fe_read_dump(sr_str text, fe_result *out);

/* The restricted-c3 filter: `dump` without the lines at or below a program's Body, FRet, RedirKey or FmodVal (the paths the reader
 * does not store). Applied to the original dump and to fe_result_dump of what the reader read, the two must be equal. */
void fe_dump_restrict(sr_buf *out, sr_str dump);

#endif
