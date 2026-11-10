/* spinelread: ParseAST and unescape (internal/frontend/ast.go). */
#include "sr.h"

#include <string.h>

/* unescape: every %XX with two hex digits (strconv.ParseUint(s[i+1:i+3], 16, 8)) becomes its byte; the test is Go's i+2 < len(s). */
static sr_str unescape(sr_str s)
{
	if (!memchr(s.p, '%', s.n))
		return s;
	sr_buf b = {0};
	for (size_t i = 0; i < s.n; i++) {
		if (s.p[i] == '%' && i + 2 < s.n) {
			int v = 0, ok = 1;
			for (int k = 1; k <= 2; k++) {
				char c = s.p[i + k];
				v <<= 4;
				if (c >= '0' && c <= '9')
					v |= c - '0';
				else if (c >= 'a' && c <= 'f')
					v |= c - 'a' + 10;
				else if (c >= 'A' && c <= 'F')
					v |= c - 'A' + 10;
				else
					ok = 0;
			}
			if (ok) {
				sr_putc(&b, (char)v);
				i += 2;
				continue;
			}
		}
		sr_putc(&b, s.p[i]);
	}
	return sr_bufstr(&b);
}

/* map[string]V assignment: replace the value of an existing key, else append */
#define SET_FIELD(arr, n, key, field, val)                                                                                     \
	do {                                                                                                                   \
		size_t i_;                                                                                                     \
		for (i_ = 0; i_ < (n); i_++)                                                                                   \
			if (sr_eq((arr)[i_].k, (key)))                                                                         \
				break;                                                                                         \
		if (i_ == (n)) {                                                                                               \
			(arr) = sr_grow((arr), (n) * sizeof *(arr), ((n) + 1) * sizeof *(arr));                                \
			(arr)[i_].k = (key);                                                                                   \
			(n)++;                                                                                                 \
		}                                                                                                              \
		(arr)[i_].field = (val);                                                                                       \
	} while (0)

static sr_node *get_node(sr_ast *a, int64_t id)
{
	int created;
	void **slot = sr_imap_slot(&a->nodes, id, &created);
	if (created) {
		sr_node *n = sr_alloc(sizeof *n);
		n->id = id;
		n->file_id = -1;
		*slot = n;
	}
	return *slot;
}

static void set_parent(sr_ast *a, int64_t child, int64_t parent)
{
	void **slot = sr_imap_slot(&a->parent, child, NULL);
	int64_t *p = sr_alloc(sizeof *p);
	*p = parent;
	*slot = p;
}

/* strings.Cut(s, " ") */
static int cut_space(sr_str s, sr_str *before, sr_str *after)
{
	const char *sp = memchr(s.p, ' ', s.n);
	if (!sp) {
		*before = s;
		*after = (sr_str){s.p + s.n, 0};
		return 0;
	}
	*before = (sr_str){s.p, (size_t)(sp - s.p)};
	*after = (sr_str){sp + 1, s.n - (size_t)(sp - s.p) - 1};
	return 1;
}

static sr_result bad(long ln, const char *why, sr_str line)
{
	sr_buf b = {0};
	sr_printf(&b, "spinel AST line %ld: %s: ", ln, why);
	if (!sr_quote_go_ascii(&b, line))
		return sr_not_ported("Go %%q of non-ASCII text, in the AST error \"spinel AST line %ld: %s\"", ln, why);
	return sr_err_str(sr_bufstr(&b));
}

sr_result sr_parse_ast(sr_str text, sr_ast **out)
{
	sr_ast *a = sr_alloc(sizeof *a);
	a->root = -1;
	long ln = 0;
	size_t pos = 0;
	while (pos < text.n) {
		/* bufio.ScanLines: up to '\n', or the rest at EOF; one trailing '\r' dropped */
		const char *nl = memchr(text.p + pos, '\n', text.n - pos);
		size_t end = nl ? (size_t)(nl - text.p) : text.n;
		sr_str line = {text.p + pos, end - pos};
		pos = nl ? end + 1 : text.n;
		if (line.n >= (1u << 30) - 1)
			return sr_not_ported("an AST line of %zu bytes (bufio.Scanner's 1<<30 limit)", line.n);
		if (line.n > 0 && line.p[line.n - 1] == '\r')
			line.n--;
		ln++;
		if (line.n == 0)
			continue;
		sr_str tag, rest;
		cut_space(line, &tag, &rest);
		if (sr_eqc(tag, "ROOT")) {
			int64_t id;
			if (!sr_parse_int64(rest, &id))
				return bad(ln, "ROOT id", line);
			a->root = id;
		} else if (sr_eqc(tag, "SOURCE_FILE")) {
			a->source_file = unescape(rest);
		} else if (sr_eqc(tag, "FILE")) {
			sr_str fid, p;
			int ok = cut_space(rest, &fid, &p);
			int64_t id;
			if (!sr_parse_int64(fid, &id) || !ok)
				return bad(ln, "FILE record", line);
			sr_str *v = sr_alloc(sizeof *v);
			*v = unescape(p);
			*sr_imap_slot(&a->files, id, NULL) = v;
		} else if (tag.n == 1 && strchr("NSIFRA", tag.p[0])) {
			/* strings.SplitN(rest, " ", 3) */
			sr_str f[3];
			size_t nf = 1;
			f[0] = rest;
			for (; nf < 3;) {
				sr_str b4, af;
				if (!cut_space(f[nf - 1], &b4, &af))
					break;
				f[nf - 1] = b4;
				f[nf++] = af;
			}
			int64_t id;
			if (!sr_parse_int64(f[0], &id) || nf < 2)
				return bad(ln, "record id", line);
			sr_node *n = get_node(a, id);
			char t = tag.p[0];
			if (t == 'N') {
				if (n->type.n != 0)
					return bad(ln, "node declared twice", line);
				n->type = f[1];
				continue;
			}
			sr_str field = f[1], val = nf == 3 ? f[2] : (sr_str){"", 0};
			switch (t) {
			case 'S':
			case 'F':
				SET_FIELD(n->str, n->n_str, field, v, unescape(val));
				break;
			case 'I': {
				int64_t v;
				SET_FIELD(n->inttext, n->n_inttext, field, v, val);
				if (!sr_parse_int64(val, &v))
					break; /* the text of an integer that does not fit stays in IntText only */
				if (sr_eqc(field, "node_file"))
					n->file_id = v;
				else if (sr_eqc(field, "node_line"))
					n->line = v;
				else if (sr_eqc(field, "node_col"))
					n->col = v;
				else if (sr_eqc(field, "node_end_line"))
					n->end_line = v;
				else if (sr_eqc(field, "node_end_col"))
					n->end_col = v;
				else
					SET_FIELD(n->ints, n->n_int, field, v, v);
				break;
			}
			case 'R': {
				int64_t c;
				if (!sr_parse_int64(val, &c))
					return bad(ln, "R child id", line);
				SET_FIELD(n->ref, n->n_ref, field, v, c);
				if (c >= 0)
					set_parent(a, c, id);
				break;
			}
			case 'A': {
				int64_t *ids = NULL;
				size_t nids = 0;
				if (val.n != 0) {
					size_t s = 0;
					for (;;) {
						const char *comma = memchr(val.p + s, ',', val.n - s);
						size_t e = comma ? (size_t)(comma - val.p) : val.n;
						int64_t c;
						if (!sr_parse_int64((sr_str){val.p + s, e - s}, &c))
							return bad(ln, "A child id", line);
						ids = sr_grow(ids, nids * sizeof *ids, (nids + 1) * sizeof *ids);
						ids[nids++] = c;
						set_parent(a, c, id);
						if (!comma)
							break;
						s = e + 1;
					}
				}
				size_t i;
				for (i = 0; i < n->n_arr; i++)
					if (sr_eq(n->arr[i].k, field))
						break;
				if (i == n->n_arr) {
					n->arr = sr_grow(n->arr, n->n_arr * sizeof *n->arr, (n->n_arr + 1) * sizeof *n->arr);
					n->arr[i].k = field;
					n->n_arr++;
				}
				n->arr[i].ids = ids;
				n->arr[i].n = nids;
				break;
			}
			}
		} else {
			return bad(ln, "unknown record tag", line);
		}
	}
	if (a->root < 0 || !sr_imap_get(&a->nodes, a->root))
		return sr_err("spinel AST: no ROOT node");
	/* Go walks the node map in random order; when several nodes fail, Go may name any of them. This C names the lowest id. Real
	 * outputs never fail here, and each control has one failing node. */
	int64_t *ids = sr_imap_sorted_keys(&a->nodes);
	for (size_t i = 0; i < a->nodes.n; i++) {
		sr_node *n = sr_imap_get(&a->nodes, ids[i]);
		if (n->type.n == 0)
			return sr_err("spinel AST: node %lld has attributes but no N record", (long long)n->id);
		if (n->file_id < 0)
			continue;
		if (!sr_imap_get(&a->files, n->file_id))
			return sr_err("spinel AST: node %lld names file id %lld with no FILE record", (long long)n->id,
				      (long long)n->file_id);
	}
	*out = a;
	return sr_ok;
}

sr_str sr_ast_file(const sr_ast *a, const sr_node *n)
{
	sr_str *f = sr_imap_get(&a->files, n->file_id);
	return f ? *f : (sr_str){"", 0};
}
