/* schema_out — the three artefacts in C: Schema, MapsJSON and RecordsTable of internal/frontend (schema.go, record.go,
 * globals.go), over the fe_result that the C analyze() builds. Each function appends the bytes Go returns. */
#ifndef FRONTEND_SCHEMA_OUT_H
#define FRONTEND_SCHEMA_OUT_H

#include "body.h"

/* Schema(res): the schema JSON, ending in "\n" */
void fe_schema_json(sr_buf *b, const fe_result *r);
/* MapsJSON(res): the maps.json document, ending in "\n" */
void fe_maps_json(sr_buf *b, const fe_result *r);
/* RecordsTable(res): the embedded layout table ("" when there is no record map and no global) */
void fe_records_table(sr_buf *b, const fe_result *r);
/* usedRecords(res): the records the maps and rings use, in map order, without duplicates (the pointers) */
fe_record_decl **fe_used_records(const fe_result *r, size_t *n);

#endif
