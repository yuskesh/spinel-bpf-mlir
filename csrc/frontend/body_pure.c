/* body_pure — the G1 functions that need no walker state (compared alone with Go): message texts and small predicates of the map,
 * record, ring, hash, lpm and output files. Each comment names the Go it follows. Strings come from the arena. */
#include "body.h"

#include <string.h>

/* record.go memberLike: identRe `^[a-z_][a-zA-Z0-9_]*$` and not an object method */
static const char *const object_methods[] = {"dup", "clone", "freeze", "frozen?", "to_a", "to_h", "deconstruct", "members", "values", "each",
					     "hash", "eql?", "equal?", "inspect", "to_s", "size", "length", "tap", "then"};
int fe_member_like(sr_str name)
{
	if (name.n == 0) return 0;
	for (size_t i = 0; i < name.n; i++) {
		unsigned char c = (unsigned char)name.p[i];
		int lower = c >= 'a' && c <= 'z', upper = c >= 'A' && c <= 'Z', digit = c >= '0' && c <= '9';
		if (i == 0 ? !(lower || c == '_') : !(lower || upper || digit || c == '_')) return 0;
	}
	for (size_t i = 0; i < sizeof object_methods / sizeof *object_methods; i++)
		if (sr_eqc(name, object_methods[i])) return 0;
	return 1;
}

/* ring.go droppedMsg */
sr_str fe_dropped_msg(const fe_ring_decl *r)
{
	sr_buf b = {0};
	sr_puts(&b, "the result of ");
	sr_putstr(&b, r->const_name);
	sr_puts(&b, ".output (false when the ring is full) is dropped — use it as an `if` / `unless` condition (count drops in the false arm) or write `_ = ");
	sr_putstr(&b, r->const_name);
	sr_puts(&b, ".output(…)` to choose not to count them");
	return sr_bufstr(&b);
}

/* outputbuf.go outputBufForm */
sr_str fe_output_buf_form(sr_str param)
{
	sr_buf b = {0};
	sr_puts(&b, "`r = R.output_buf(S.new(…), :<u8 array member>, ");
	sr_putstr(&b, param);
	sr_puts(&b, ".buf_arg(n), <length>, :<i64 status member>, :<i32 count member>)` then `if r`, or `_ = R.output_buf(…)`");
	return sr_bufstr(&b);
}

/* comm.go outputCommShape */
sr_str fe_output_comm_shape(const fe_ring_decl *r)
{
	sr_buf b = {0};
	sr_puts(&b, "`r = ");
	sr_putstr(&b, r->const_name);
	sr_puts(&b, ".output_comm(");
	sr_putstr(&b, r->record->const_name);
	sr_puts(&b, ".new(…), :<[:u8, 16] member>, :<i64 status member>)` then `if r` (read `r.status` inside), or `_ = ");
	sr_putstr(&b, r->const_name);
	sr_puts(&b, ".output_comm(…)`");
	return sr_bufstr(&b);
}

/* hash.go perCPUExempt: a per-CPU map and every root kind xdp (no kinds: false) */
int fe_per_cpu_exempt(const fe_map_decl *m, const sr_str *kinds, size_t n_kinds)
{
#ifdef E188_MUTANT_PERCPU_EXEMPT_ALL
	if (m) return 1;
#endif
	if (!m || !fe_map_per_cpu(m) || n_kinds == 0) return 0;
	for (size_t i = 0; i < n_kinds; i++)
		if (!sr_eqc(kinds[i], "xdp")) return 0;
	return 1;
}

/* hash.go statusIgnored */
sr_str fe_status_ignored(const fe_map_decl *m, sr_str op)
{
	sr_buf b = {0};
	sr_puts(&b, "the status of `");
	sr_putstr(&b, m->const_name);
	sr_putc(&b, '.');
	sr_putstr(&b, op);
	sr_puts(&b, "` (0 or a negative errno such as BPF::EEXIST) is dropped — receive it as `st = ");
	sr_putstr(&b, m->const_name);
	sr_putc(&b, '.');
	sr_putstr(&b, op);
	sr_puts(&b, "(…)` and read `st`, compare it (`if ");
	sr_putstr(&b, m->const_name);
	sr_putc(&b, '.');
	sr_putstr(&b, op);
	sr_puts(&b, "(…) != 0`), or drop it explicitly with `_ = ");
	sr_putstr(&b, m->const_name);
	sr_putc(&b, '.');
	sr_putstr(&b, op);
	sr_puts(&b, "(…)`");
	return sr_bufstr(&b);
}

/* lpm.go valueTypesText */
sr_str fe_value_types_text(sr_str kind) { return sr_cstr(sr_eqc(kind, "lpm_trie") ? ":u32|:i32" : ":u32|:u64|:i32|:i64"); }

/* lpm.go valueTypesWords */
sr_str fe_value_types_words(sr_str kind) { return sr_cstr(sr_eqc(kind, "lpm_trie") ? ":u32 or :i32" : ":u32, :u64, :i32 or :i64"); }

#include "body_priv.h"

/* record.go pow2Above (n >= 1) */
int64_t fe_pow2_above(int64_t n)
{
	int64_t p = 1;
	while (p < n) p <<= 1;
	return p;
}

/* record.go indexHint (n >= 1) */
sr_str fe_index_hint(int64_t n)
{
	sr_buf b = {0};
	if ((n & (n - 1)) == 0) {
		sr_printf(&b, "narrow it into [0, %lld] (e.g. `i & %lld`, `i %% %lld` or inside `if i >= 0 && i < %lld`)", (long long)(n - 1), (long long)(n - 1),
			  (long long)n, (long long)n);
		return sr_bufstr(&b);
	}
	sr_printf(&b,
		  "narrow it into [0, %lld] (e.g. inside `if i >= 0 && i < %lld`, or `i %% %lld` for a non-negative i — %lld is not a power of two, so no mask `i & M` covers exactly [0, %lld]: `i & %lld` can reach %lld)",
		  (long long)(n - 1), (long long)n, (long long)n, (long long)n, (long long)(n - 1), (long long)(fe_pow2_above(n) - 1), (long long)(fe_pow2_above(n) - 1));
	return sr_bufstr(&b);
}

/* interval.go Ival.String: "[lo, hi]" */
sr_str fe_ival_text(fe_ival v)
{
	char lo[48], hi[48];
	sr_buf b = {0};
	sr_printf(&b, "[%s, %s]", intv_string(v.lo, lo), intv_string(v.hi, hi));
	return sr_bufstr(&b);
}

/* interval.go Ival.within */
int fe_ival_within(fe_ival v, intv lo, intv hi) { return intv_cmp(v.lo, lo) >= 0 && intv_cmp(v.hi, hi) <= 0; }
