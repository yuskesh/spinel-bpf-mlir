/* csrc/driver/driver_tool.c - test-side tool (never in a product): runs one check of the C driver on files, for the Go test
 * cmd/spinelbpf/e175_test.go, which compares the texts with the Go function's on the same files (refusal branches no corpus input reaches).
 *
 *	driver_tool codes                       the reason code table, "<code> <name>" per line
 *	driver_tool uprobe-kinds                UprobeBuildKinds, then a "--" line, then UprobeBuildIgnored
 *	driver_tool mapsyms <elf> <schema>      checkMapSymbols
 *	driver_tool schemasha <elf> <schema>    checkSchemaSHA (prints the sha on success)
 *	driver_tool records <schema> <table>    checkRecordsTable
 *	driver_tool needed <exe> <allow>        readAllow + CheckNeeded
 *	driver_tool run <dir|-> <exe> [-- env…] run_cmd (exec.Cmd with Dir and Env = os.Environ() + env, or Env nil without "--")
 *
 * A check's error is printed on stdout as "error: <text>" with exit code 0; "ok" (or the sha) when it passes. Exit 2 is usage. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "diag.h"
#include "util.h"

static char *slurp(const char *p, size_t *n)
{
	char *d;
	err_t e = read_file(p, &d, n);
	if (e) {
		printf("error: %s\n", e);
		return NULL;
	}
	return d;
}

static int report(err_t e, const char *ok)
{
	if (e)
		printf("error: %s\n", e);
	else
		printf("%s\n", ok);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "codes")) {
		const char *name, *code;
		for (size_t i = 0; (code = code_at(i, &name)); i++)
			printf("%s %s\n", code, name);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "uprobe-kinds")) {
		for (const char *const *k = uprobe_build_kinds(); *k; k++)
			printf("%s\n", *k);
		printf("--\n");
		for (const char *const *k = uprobe_build_ignored(); *k; k++)
			printf("%s\n", *k);
		return 0;
	}
	if (argc == 4 && !strcmp(argv[1], "needed"))
		return report(check_needed(argv[2], argv[3]), "ok");
	size_t n;
	if (argc == 4 && (!strcmp(argv[1], "mapsyms") || !strcmp(argv[1], "schemasha"))) {
		char *schema = slurp(argv[3], &n);
		if (!schema)
			return 0;
		if (!strcmp(argv[1], "mapsyms"))
			return report(check_map_symbols(argv[2], schema, n), "ok");
		char sha[65];
		err_t e = check_schema_sha(argv[2], schema, n, sha);
		return report(e, sha);
	}
	if (argc == 4 && !strcmp(argv[1], "records")) {
		size_t tn;
		char *schema = slurp(argv[2], &n), *table = schema ? slurp(argv[3], &tn) : NULL;
		if (!table)
			return 0;
		return report(check_records_table(schema, n, table), "ok");
	}
	if (argc >= 4 && !strcmp(argv[1], "run")) {
		/* run_cmd(exe, dir or NULL for "-", extra env after "--" or NULL without it): the child's stdout, a "--" line, the
		 * error text or "none" */
		char *child[] = {argv[3], NULL};
		char **extra = NULL;
		if (argc >= 5) {
			if (strcmp(argv[4], "--"))
				goto usage;
			extra = argv + 5; /* argv[argc] is NULL */
		}
		struct run_out o = {0};
		err_t e = run_cmd(child, strcmp(argv[2], "-") ? argv[2] : NULL, extra, 0, &o);
		printf("%s--\n%s\n", o.out.p ? o.out.p : "", e ? e : "none");
		return 0;
	}
usage:
	fputs("usage: driver_tool codes | uprobe-kinds | mapsyms ELF SCHEMA | schemasha ELF SCHEMA | records SCHEMA TABLE | needed EXE ALLOW"
	      " | run DIR|- EXE [-- ENV...]\n",
	      stderr);
	return 2;
}
