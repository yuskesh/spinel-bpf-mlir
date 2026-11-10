/* lower_world.c — bpfworld.go's allowedOps, MlirOps, AllowedOps and VerifyWorld in C. */
#include "lower.h"

#include <stdlib.h>
#include <string.h>

/* bpfworld.go allowedOps, in its order (a test compares the set with Go's AllowedOps) */
static const char *const allowed_ops[] = {
	"ebpf.program", "ebpf.verdict",
	"ebpf.map.lookup", "ebpf.map.update", "ebpf.map.atomic_add",
	"ebpf.ref.check", "ebpf.ref.load", "ebpf.yield",
	"arith.constant",
	"ebpf.if", "ebpf.if.yield",
	"arith.addi", "arith.subi", "arith.muli", "arith.andi", "arith.ori", "arith.xori",
	"arith.shli", "arith.shrsi", "arith.shrui", "arith.divui", "arith.remui",
	"arith.floordivsi", "arith.remsi", "arith.cmpi", "arith.select",
	"arith.extui", "arith.extsi", "arith.trunci",
	"ebpf.packet.check", "ebpf.packet.window_load", "ebpf.byteorder.from_be",
	"ebpf.ktime.ns", "ebpf.record.make",
	"ebpf.global.load", "ebpf.global.atomic_add",
	"ebpf.ctx.retval", "ebpf.kprobe.arg", "ebpf.probe.retval", "ebpf.task.pid_tgid",
	"ebpf.uprobe.arg", "ebpf.user.read_str", "ebpf.ringbuf.store_field",
	"ebpf.ctx.arg", "ebpf.kfield.load",
	"ebpf.ctx.field",
	"ebpf.ctx.field.store",
	"ebpf.xdp.adjust_head",
	"ebpf.xdp.adjust_tail",
	"ebpf.flow_keys.load", "ebpf.flow_keys.store",
	"ebpf.tp.field",
	"ebpf.ksyscall.arg",
	"ebpf.kernel.read_scalar",
	"ebpf.kernel.read_str",
	"ebpf.task.comm",
	"ebpf.user.str_at",
	"ebpf.user.read",
	"ebpf.redirect_map",
	"ebpf.sock.map_lookup", "ebpf.sock.ref_check", "ebpf.sk.assign", "ebpf.sock.release",
	"ebpf.kfield.ptr", "ebpf.kptr.check",
	"ebpf.kfield.copy",
	"ebpf.tp.field.copy",
	"ebpf.kptr.addr",
	"ebpf.func", "ebpf.call", "ebpf.return",
	"ebpf.ringbuf.discard",
	"ebpf.ringbuf.reserve", "ebpf.ringbuf.if_reserved", "ebpf.ringbuf.store_record", "ebpf.ringbuf.submit", "ebpf.ref.field.load",
	"ebpf.ref.field.store", "ebpf.ref.field.atomic_add",
	"ebpf.map.try_update", "ebpf.map.try_delete", "ebpf.ref.atomic_add",
	"ebpf.loop", "ebpf.loop.yield", "ebpf.break", "ebpf.continue",
	"ebpf.ref.index", "ebpf.elem.load", "ebpf.elem.store",
	"ebpf.verdict.if",
};
#define N_ALLOWED (sizeof allowed_ops / sizeof allowed_ops[0])

static int allowed(sr_str op)
{
	for (size_t i = 0; i < N_ALLOWED; i++)
		if (sr_eqc(op, allowed_ops[i]))
			return 1;
	return 0;
}

static int has_prefix(sr_str s, const char *p)
{
	size_t n = strlen(p);
	return s.n >= n && memcmp(s.p, p, n) == 0;
}

/* MlirOps: calls f for each op, in order */
static void each_op(sr_str text, void (*f)(void *u, sr_str op), void *u)
{
	size_t i = 0;
	for (;;) { /* strings.Split(text, "\n"): every piece, the last one included */
		size_t j = i;
		while (j < text.n && text.p[j] != '\n')
			j++;
		sr_str s = sr_trim_space((sr_str){text.p + i, j - i});
		int skip = s.n == 0 || has_prefix(s, "//") || has_prefix(s, "^") || has_prefix(s, "}");
		if (!skip && has_prefix(s, "%")) {
			size_t k = 0;
			while (k + 1 < s.n && !(s.p[k] == '=' && s.p[k + 1] == ' '))
				k++;
			if (k + 1 >= s.n) {
				sr_buf b = {0};
				sr_puts(&b, "<unparsed:");
				sr_putstr(&b, s);
				sr_putc(&b, '>');
				f(u, sr_bufstr(&b));
				skip = 1;
			} else {
				s = (sr_str){s.p + k + 2, s.n - k - 2};
			}
		}
		if (!skip) {
			size_t k = 0;
			while (k < s.n && s.p[k] != ' ' && s.p[k] != '\t')
				k++;
			f(u, (sr_str){s.p, k});
		}
		if (j >= text.n)
			break;
		i = j + 1;
	}
}

static void put_line(void *u, sr_str op)
{
	sr_putstr(u, op);
	sr_putc(u, '\n');
}

void fe_mlir_ops(sr_str text, sr_buf *out) { each_op(text, put_line, out); }

typedef struct {
	sr_buf list;
	size_t n;
} bad_ops;

static void collect_bad(void *u, sr_str op)
{
	bad_ops *b = u;
	if (allowed(op))
		return;
	if (b->n++)
		sr_putc(&b->list, ' ');
	sr_putstr(&b->list, op);
}

int fe_verify_world(sr_str text, sr_buf *err)
{
	bad_ops b = {{0}, 0};
	each_op(text, collect_bad, &b);
	if (b.n == 0)
		return 1;
	sr_puts(err, "verify-bpf-world: the generated .mlir has ops outside the allowed set: [");
	sr_putstr(err, sr_bufstr(&b.list));
	sr_putc(err, ']');
	return 0;
}

static int cmp_ops(const void *a, const void *b)
{
	return sr_cmp(sr_cstr(*(const char *const *)a), sr_cstr(*(const char *const *)b));
}

void fe_allowed_ops(sr_buf *out)
{
	const char *v[N_ALLOWED];
	memcpy(v, allowed_ops, sizeof v);
	qsort(v, N_ALLOWED, sizeof v[0], cmp_ops);
	for (size_t i = 0; i < N_ALLOWED; i++)
		if (i == 0 || strcmp(v[i], v[i - 1]) != 0) {
			sr_puts(out, v[i]);
			sr_putc(out, '\n');
		}
}
