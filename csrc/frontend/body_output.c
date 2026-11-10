/* body_output — outputbuf.go and comm.go of G1: `R.output_buf(…)` and `R.output_comm(…)`, both checked and then built by the
 * shared outputStrMake (G2's). Follows internal/frontend/outputbuf.go and comm.go at main c204310. */
#include "body.h"
#include "body_priv.h"

#include <string.h>

static int is_type(const sr_node *n, const char *t) { return n && sr_eqc(n->type, t); }

static sr_str nstr(const sr_node *n, const char *k)
{
	int ok;
	return fe_node_str(n, k, &ok);
}

static void reject(fe_prog_ctx *c, fe_code code, const sr_node *n, sr_buf *b) { fe_ctx_add(c, FE_REJECTED, code, n, sr_bufstr(b)); }

/* the `member` closure of both functions: the record member a Symbol names, or NULL */
static fe_record_field *member(const fe_ring_decl *r, const sr_node *x)
{
	if (!x || !is_type(x, "SymbolNode")) return NULL;
	sr_str v = nstr(x, "value");
	for (size_t i = 0; i < r->record->n_fields; i++)
		if (sr_eq(r->record->fields[i].name, v)) return &r->record->fields[i];
	return NULL;
}

/* outputbuf.go outputBuf: returns Go's bool, *out the Stmt */
int fe_output_buf(fe_prog_ctx *c, const sr_node *call, sr_str name, sr_str ref_var, fe_stmt *out)
{
	*out = fe_stmt_new("");
	fe_ring_decl *r = fe_ring_of(c, fe_ast_ref(c->a, call, "receiver"));
	if (!sr_eqc(c->prog->kind, "uprobe")) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, r->const_name);
		sr_puts(&b, ".output_buf` reads a user buffer (`ctx.buf_arg(n)` of a :user_buf parameter in a uprobe program) — a ");
		fe_fmt_s(&b, c->prog->kind);
		sr_puts(&b, " program has none");
		reject(c, FE_SB028, call, &b);
		return 0;
	}
	int ok;
	sr_str callee = fe_callee(c, call, &ok);
	if (!ok) return 0;
	if (!sr_eqc(callee, "RingBuf#output_buf")) {
		sr_buf b = {0};
		sr_puts(&b, "`output_buf` resolves to ");
		fe_fmt_s(&b, callee);
		sr_puts(&b, ", not BPF::RingBuf#output_buf");
		reject(c, FE_SB011, call, &b);
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, call, &n_as);
	if (n_as != 6) {
		sr_buf b = {0};
		sr_puts(&b, "output_buf takes six arguments — ");
		fe_fmt_s(&b, fe_output_buf_form(c->param));
		reject(c, FE_SB024, call, &b);
		return 0;
	}
	fe_record_field *f = member(r, as[1]), *st = member(r, as[4]), *cn = member(r, as[5]);
	if (!f || f->count == 0 || f->bits != 8 || f->is_signed) {
		sr_buf b = {0};
		sr_puts(&b, "the buffer member of output_buf must be a :u8 array member of ");
		fe_fmt_s(&b, r->record->const_name);
		sr_puts(&b, " (`data: [:u8, 64]` — bpf-mlir's user.read fills a 1-dimensional 8-bit array)");
		reject(c, FE_SB024, as[1], &b);
		return 0;
	}
	if (!st || st->count != 0 || st->bits != 64 || !st->is_signed) {
		sr_buf b = {0};
		sr_puts(&b, "the status member of output_buf must be an :i64 member of ");
		fe_fmt_s(&b, r->record->const_name);
		sr_puts(&b, " (the raw status of probe_read_user — 0 or a negative errno)");
		reject(c, FE_SB024, as[4], &b);
		return 0;
	}
	if (!cn || cn->count != 0 || cn->bits != 32 || !cn->is_signed) {
		sr_buf b = {0};
		sr_puts(&b, "the count member of output_buf must be an :i32 member of ");
		fe_fmt_s(&b, r->record->const_name);
		sr_puts(&b, " (the clamped length max(0, min(length, N)) — not the bytes read)");
		reject(c, FE_SB024, as[5], &b);
		return 0;
	}
	const sr_node *sa = as[2];
	if (!is_type(sa, "CallNode") || !sr_eqc(nstr(sa, "name"), "buf_arg") || !fe_is_var_read(c, fe_ast_ref(c->a, sa, "receiver"), c->param)) {
		sr_buf b = {0};
		sr_puts(&b, "the third argument of output_buf is `");
		fe_fmt_s(&b, c->param);
		sr_puts(&b, ".buf_arg(n)` itself (a user buffer is not a value on the eBPF side — not through a local)");
		reject(c, FE_SB028, sa, &b);
		return 0;
	}
	int cok;
	sr_str cs = fe_callee(c, sa, &cok);
	if (!cok || !sr_eqc(cs, "UprobeCtx#buf_arg")) {
		if (cok) {
			sr_buf b = {0};
			sr_puts(&b, "`buf_arg` resolves to ");
			fe_fmt_s(&b, cs);
			sr_puts(&b, ", not BPF::UprobeCtx#buf_arg");
			reject(c, FE_SB011, sa, &b);
		}
		return 0;
	}
	size_t n_sa;
	const sr_node **sas = fe_args(c->a, sa, &n_sa);
	fe_kparam *kp = fe_uprobe_param(c, sa, sas, n_sa);
	if (!kp) return 0;
	if (!sr_eqc(kp->type, "user_buf")) {
		sr_buf b = {0};
		sr_puts(&b, "`");
		fe_fmt_s(&b, c->param);
		sr_puts(&b, ".buf_arg(");
		fe_fmt_d(&b, kp->n);
		sr_puts(&b, ")`: parameter ");
		fe_fmt_d(&b, kp->n);
		sr_puts(&b, " is declared :");
		fe_fmt_s(&b, kp->type);
		sr_puts(&b, ", not :user_buf");
		reject(c, FE_SB028, sa, &b);
		return 0;
	}
	fe_expr *ln = fe_ctx_expr(c, as[3], ref_var);
	if (!ln) return 0;
	const sr_node *sub[4] = {as[0], as[1], as[2], as[4]};
	if (!fe_output_str_make(c, call, sub, 4, r, sr_cstr("output_buf"), f, st, name, ref_var, out)) return 0;
	out->buf = 1;
	out->buf_len = ln;
	out->count_f = cn;
	out->len = kp->n; /* Go: os.Len = int64(kp.N) */
	return 1;
}

/* comm.go outputComm: returns Go's bool, *out the Stmt */
int fe_output_comm(fe_prog_ctx *c, const sr_node *call, sr_str name, sr_str ref_var, fe_stmt *out)
{
	*out = fe_stmt_new("");
	fe_ring_decl *r = fe_ring_of(c, fe_ast_ref(c->a, call, "receiver"));
	int ok;
	sr_str callee = fe_callee(c, call, &ok);
	if (!ok) return 0;
	if (!sr_eqc(callee, "RingBuf#output_comm")) {
		sr_buf b = {0};
		sr_puts(&b, "`output_comm` resolves to ");
		fe_fmt_s(&b, callee);
		sr_puts(&b, ", not BPF::RingBuf#output_comm");
		reject(c, FE_SB011, call, &b);
		return 0;
	}
	size_t n_as;
	const sr_node **as = fe_args(c->a, call, &n_as);
	if (n_as == 2 || (n_as == 3 && !member(r, as[2]))) {
		sr_buf b = {0};
		sr_puts(&b, "output_comm needs a status member: add `status: :i64` to BPF.record(");
		fe_fmt_s(&b, r->record->const_name);
		sr_puts(&b, ", …) and pass it as the third argument — the raw status of bpf_get_current_comm — ");
		fe_fmt_s(&b, fe_output_comm_shape(r));
		reject(c, FE_SB024, call, &b);
		return 0;
	}
	if (n_as != 3) {
		sr_buf b = {0};
		sr_puts(&b, "output_comm takes three arguments — ");
		fe_fmt_s(&b, fe_output_comm_shape(r));
		reject(c, FE_SB002, call, &b);
		return 0;
	}
	fe_record_field *f = member(r, as[1]), *st = member(r, as[2]);
	if (!f || f->count != 16 || f->bits != 8 || f->is_signed) {
		sr_buf b = {0};
		sr_puts(&b, "the comm member of output_comm must be a [:u8, 16] member of ");
		fe_fmt_s(&b, r->record->const_name);
		sr_puts(&b, " (TASK_COMM_LEN — bpf_get_current_comm fills 16 bytes)");
		reject(c, FE_SB024, as[1], &b);
		return 0;
	}
	if (st->count != 0 || st->bits != 64 || !st->is_signed) {
		sr_buf b = {0};
		sr_puts(&b, "the status member ");
		fe_fmt_s(&b, st->name);
		sr_puts(&b, " of output_comm must be :i64 (the raw status of bpf_get_current_comm)");
		reject(c, FE_SB024, as[2], &b);
		return 0;
	}
	int res = fe_output_str_make(c, call, as, 1, r, sr_cstr("output_comm"), f, st, name, ref_var, out);
	out->comm = 1;
	return res;
}
