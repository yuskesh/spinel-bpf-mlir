/* spinelread — the C form of internal/frontend's Spinel output reader.
 *
 * The Go reader (spinel.go, ast.go, types.go) stays the canon. This C is reached only by the spinelread tool and its Go tests,
 * which compare its canonical dump with the Go dumper (internal/frontend/e176_dump_test.go) byte for byte.
 *
 * Errors come in two kinds. A reproduced error carries Go's error text exactly (dumped as `error <text>`). A "not ported" stop is
 * a case where this C does not reproduce Go (an OS error text, a JSON type error, Go %q of non-ASCII text, ...); it is dumped as
 * `not-ported <text>` and can never compare equal with a Go dump. Memory comes from one arena, freed at exit. */
#ifndef SPINELREAD_SR_H
#define SPINELREAD_SR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ---- arena and byte strings ---- */
void *sr_alloc(size_t n); /* zeroed; exits on out of memory */
void *sr_grow(void *p, size_t old_n, size_t new_n);

typedef struct {
	const char *p;
	size_t n;
} sr_str;

sr_str sr_dup(const char *p, size_t n);
sr_str sr_cstr(const char *s);
int sr_eq(sr_str a, sr_str b);
int sr_eqc(sr_str a, const char *s);
int sr_cmp(sr_str a, sr_str b); /* Go's string order: bytes, then length */

typedef struct {
	char *p;
	size_t n, cap;
} sr_buf;
void sr_put(sr_buf *b, const void *p, size_t n);
void sr_puts(sr_buf *b, const char *s);
void sr_putc(sr_buf *b, char c);
void sr_printf(sr_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sr_putstr(sr_buf *b, sr_str s);
sr_str sr_bufstr(const sr_buf *b);

/* ---- Go's strconv and unicode/utf8, as far as the reader needs them ---- */
/* strconv.ParseInt(s, 10, 64) (and Atoi on a 64-bit target): 1 and *out on success. */
int sr_parse_int64(sr_str s, int64_t *out);
/* utf8.DecodeRune: the rune and its width; invalid bytes, surrogates and overlong forms give U+FFFD width 1; empty gives width 0. */
int32_t sr_decode_rune(const char *p, size_t n, size_t *width);
void sr_append_rune(sr_buf *b, int32_t r); /* utf8.AppendRune (invalid runes as U+FFFD) */
/* strconv.QuoteToASCII. */
void sr_quote_ascii(sr_buf *b, sr_str s);
/* strconv.Quote for text that is all ASCII: 1 when written; 0 when s has a byte >= 0x80 (not ported: no C copy of Go's unicode.IsPrint). */
int sr_quote_go_ascii(sr_buf *b, sr_str s);
/* strings.TrimSpace (unicode.IsSpace). */
sr_str sr_trim_space(sr_str s);

/* ---- results ---- */
enum { SR_OK = 0, SR_ERR = 1, SR_NOT_PORTED = 2 };
typedef struct {
	int kind;
	sr_str text;
} sr_result;
sr_result sr_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
sr_result sr_err_str(sr_str s);
sr_result sr_not_ported(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
extern const sr_result sr_ok;

/* ---- int64 → pointer and int64 → int64 maps (Go map[int]...) ---- */
typedef struct {
	int64_t *keys;
	void **vals;
	unsigned char *used;
	size_t n, cap;
} sr_imap;
void **sr_imap_slot(sr_imap *m, int64_t k, int *created); /* inserts when missing */
void *sr_imap_get(const sr_imap *m, int64_t k);
int64_t *sr_imap_sorted_keys(const sr_imap *m); /* ascending, m->n entries */

/* ---- the AST (ast.go) ---- */
typedef struct {
	sr_str k, v;
} sr_kv_str;
typedef struct {
	sr_str k;
	int64_t v;
} sr_kv_int;
typedef struct {
	sr_str k;
	int64_t *ids;
	size_t n;
} sr_kv_arr;

typedef struct {
	int64_t id;
	sr_str type;
	sr_kv_str *str;
	size_t n_str;
	sr_kv_int *ints;
	size_t n_int;
	sr_kv_str *inttext;
	size_t n_inttext;
	sr_kv_int *ref;
	size_t n_ref;
	sr_kv_arr *arr;
	size_t n_arr;
	int64_t file_id, line, col, end_line, end_col;
} sr_node;

typedef struct {
	int64_t root;
	sr_str source_file;
	sr_imap files;  /* id → sr_str* */
	sr_imap nodes;  /* id → sr_node* */
	sr_imap parent; /* child → int64_t* */
} sr_ast;

sr_result sr_parse_ast(sr_str text, sr_ast **out);
sr_str sr_ast_file(const sr_ast *a, const sr_node *n);

/* ---- the types document (types.go) ---- */
typedef struct {
	sr_str file;
	int64_t line, col, end_line, end_col;
	sr_str kind, name, type, rbs, owner, signature;
	int singleton, widened;
} sr_type_rec;

typedef struct {
	sr_str file;
	int64_t line, col, end_line, end_col;
	sr_str kind, name, dispatch, callee;
	sr_str *candidates;
	size_t n_candidates;
	int candidates_nil;
	int inlined; /* -1 nil, 0 false, 1 true */
} sr_codegen_rec;

typedef struct {
	sr_str file;
	int64_t line, col;
	sr_str severity, method, slot, param, message;
} sr_diag_rec;

typedef struct sr_index sr_index;
typedef struct {
	sr_type_rec *types;
	size_t n_types;
	int types_nil;
	sr_diag_rec *diags;
	size_t n_diags;
	int diags_nil;
	sr_codegen_rec *codegen;
	size_t n_codegen;
	int codegen_nil;
	sr_index *by_key, *cg_by_key;
} sr_types;

sr_result sr_parse_types(sr_str data, sr_types **out);
/* TypeOf / CodegenOf: the record index, or -1 with *count set (0 none, ≥ 2 ambiguous). */
long sr_type_of(const sr_types *t, const sr_ast *a, const sr_node *n, size_t *count);
long sr_codegen_of(const sr_types *t, const sr_ast *a, const sr_node *n, size_t *count);
/* types.go reindex: rebuilds the span index after records' positions change (the splice correction calls it). */
void sr_reindex_types(sr_types *t);

/* ---- the run (spinel.go) ---- */
typedef struct {
	sr_str code, file, msg;
	int64_t line, col;
} sr_diag;

typedef struct {
	const char *bin, *lib_dir;
} sr_spinel;

typedef struct {
	sr_ast *ast;
	sr_types *types;
	sr_diag *diags;
	size_t n_diags;
} sr_analysis;

/* Spinel.Analyze. On SR_OK, *out is set: ast and types may be NULL (Go's nil analysis) with diagnostics. */
sr_result sr_analyze(const sr_spinel *s, const char *dir, const char *base, sr_str text, sr_analysis *out);
sr_result sr_uses_threads(const sr_spinel *s, const char *dir, const char *base, int *threads);
sr_result sr_version(const sr_spinel *s, sr_str *version);
sr_str sr_first_lines(sr_str b, int n);

/* ---- the dump (e176_dump_test.go's format) ---- */
void sr_dump_result(sr_buf *b, sr_result r); /* "error <q>" or "not-ported <q>" */
void sr_dump_analysis(sr_buf *b, const sr_analysis *a);
void sr_dump_ast(sr_buf *b, const sr_ast *a);
void sr_dump_types(sr_buf *b, const sr_ast *a, const sr_types *t); /* a NULL: no join lines */

#endif
