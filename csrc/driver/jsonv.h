/* csrc/driver/jsonv.h - a lenient JSON reader for parts of a document.
 *
 * The Go driver reads parts of the schema with requirements.DecodeStrictJSON(data, &any) and then json.Unmarshal into a partial
 * struct (strictUnmarshal in cmd/spinelbpf/build.go). The C driver runs bml_build_json_check_any first (the strict rules, Go's
 * text), and then this reader, which only walks the already valid document.
 *
 * Unmarshal's key matching is kept: an exact key first, else an ASCII case-insensitive one (the first in document order).
 * Unmarshal's type errors are not ported: a value of the wrong type stops the driver with "not ported". The schema is the
 * frontend's own output, so a wrong type there is a frontend defect. */
#ifndef SPINELBPF_DRIVER_JSONV_H
#define SPINELBPF_DRIVER_JSONV_H

#include <stddef.h>
#include <stdint.h>

enum jv_type { JV_NULL, JV_BOOL, JV_NUM, JV_STR, JV_ARR, JV_OBJ };

struct jv {
	enum jv_type t;
	int b;
	char *s;     /* JV_STR: decoded bytes (NUL-terminated); JV_NUM: the literal text */
	size_t slen; /* JV_STR */
	struct jv *items; /* JV_ARR: elements; JV_OBJ: values */
	char **keys;      /* JV_OBJ */
	size_t n;
	const char *raw; /* the value's text in the document, and its length (json.RawMessage) */
	size_t rawlen;
};

/* Parses a document that bml_build_json_check_any accepted. NULL on a syntax error (which check_any already excluded). */
struct jv *jv_parse(const char *data, size_t len);
/* The member for key (exact, else ASCII case-insensitive), or NULL. */
const struct jv *jv_get(const struct jv *o, const char *key);
/* Typed reads of an optional member, with Go's zero value when the member is absent or null; another type stops with
 * "not ported" naming where. */
const char *jv_str(const struct jv *o, const char *key, const char *where);
int64_t jv_int(const struct jv *o, const char *key, const char *where);
int jv_bool(const struct jv *o, const char *key, const char *where);
/* An array member: NULL when absent or null. */
const struct jv *jv_arr(const struct jv *o, const char *key, const char *where);
/* An object member: NULL when absent or null. */
const struct jv *jv_obj(const struct jv *o, const char *key, const char *where);

#endif
