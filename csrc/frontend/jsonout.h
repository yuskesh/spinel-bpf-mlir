/* jsonout — the JSON writer of schema_out.c: the bytes of Go's json.MarshalIndent(v, "", "  ") (with its default HTML escaping) for the
 * value shapes the schema, maps.json and domain-graph documents use. The caller writes in Go's struct field order and skips the
 * omitempty fields itself; this file owns the layout (indentation, `{}` / `[]` for an empty container, `": "` after a key) and
 * the string escaping. */
#ifndef FRONTEND_JSONOUT_H
#define FRONTEND_JSONOUT_H

#include <stdint.h>

#include "../spinelread/sr.h"

#define FE_JW_DEPTH 32

typedef struct {
	sr_buf *b;
	int depth;
	int after_key;
	char is_obj[FE_JW_DEPTH];
	int64_t count[FE_JW_DEPTH];
} fe_jw;

void fe_jw_init(fe_jw *w, sr_buf *b);
void fe_jw_obj_begin(fe_jw *w);
void fe_jw_obj_end(fe_jw *w);
void fe_jw_arr_begin(fe_jw *w);
void fe_jw_arr_end(fe_jw *w);
/* A key of the object being written; the next value call is its value. */
void fe_jw_key(fe_jw *w, sr_str k);
void fe_jw_keyc(fe_jw *w, const char *k);
void fe_jw_str(fe_jw *w, sr_str s);
void fe_jw_strc(fe_jw *w, const char *s);
void fe_jw_i64(fe_jw *w, int64_t v);
void fe_jw_u64(fe_jw *w, uint64_t v);
void fe_jw_bool(fe_jw *w, int v);
void fe_jw_null(fe_jw *w);
/* json.Marshal's string literal (with the quotes) appended to b. */
void fe_json_quote(sr_buf *b, sr_str s);
/* Sort keys the way Go's encoding/json sorts a map[string]: by the raw bytes (sr_cmp), before any escaping. */
void fe_json_sort_keys(sr_str *keys, size_t n);

#endif
