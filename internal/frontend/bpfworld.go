package frontend

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// verify-bpf-world (the same shape as go-bpf-mlir's and mojo-bpf-mlir's). allowedOps holds, in one place, the set of ops the frontend
// may emit; the frontend's exit check and the tests confirm that every op in the generated .mlir is in this set. The set must be a
// subset of the "① Input operations" in bpf-mlir's docs/reference/ebpf_ops.md (tested with ReferenceOps). **Do not add an op the
// frontend does not emit** — widen the set in the same commit as the lowering that emits it.
var allowedOps = map[string]bool{
	"ebpf.program": true, "ebpf.verdict": true,
	"ebpf.map.lookup": true, "ebpf.map.update": true, "ebpf.map.atomic_add": true,
	"ebpf.ref.check": true, "ebpf.ref.load": true, "ebpf.yield": true,
	"arith.constant": true,
	// operators, comparisons, Bool, width changes, if
	"ebpf.if": true, "ebpf.if.yield": true,
	"arith.addi": true, "arith.subi": true, "arith.muli": true, "arith.andi": true, "arith.ori": true, "arith.xori": true,
	"arith.shli": true, "arith.shrsi": true, "arith.shrui": true, "arith.divui": true, "arith.remui": true, "arith.maxui": true, // maxui: BPF.u64_div's divisor
	"arith.floordivsi": true, "arith.remsi": true, "arith.cmpi": true, "arith.select": true,
	"arith.extui": true, "arith.extsi": true, "arith.trunci": true,
	// reads from a checked packet window (the unchecked ebpf.packet.load is left out — out of range it silently reads 0)
	"ebpf.packet.check": true, "ebpf.packet.window_load": true, "ebpf.byteorder.from_be": true,
	// record map values
	"ebpf.ktime.ns": true, "ebpf.record.make": true,
	// tracing reads and helpers
	"ebpf.global.load": true, "ebpf.global.atomic_add": true, // globals
	"ebpf.ctx.retval": true, "ebpf.kprobe.arg": true, "ebpf.probe.retval": true /* kretprobe / uretprobe return value */, "ebpf.task.pid_tgid": true,
	"ebpf.uprobe.arg": true, "ebpf.user.read_str": true, "ebpf.ringbuf.store_field": true, // uprobe and output_str
	"ebpf.ctx.arg": true, "ebpf.kfield.load": true, // tp_btf and CO-RE (compile once, run everywhere)
	"ebpf.kfield.store": true,                            // struct_ops: a field write of the checked socket
	"module":            true, "ebpf.global.store": true, // the module attribute ebpf.scx_kfuncs, and a Global's write
	"ebpf.scx.select_cpu_dfl": true, "ebpf.scx.dsq_insert": true, "ebpf.scx.dsq_insert_vtime": true, "ebpf.scx.dsq_move_to_local": true, // the sched_ext ops
	"ebpf.scx.create_dsq": true, "ebpf.scx.task_set_dsq_vtime": true, "ebpf.scx.error": true, "ebpf.scx.exit_info": true, "ebpf.scx.const": true,
	"ebpf.ctx.field":       true,                               // socket_filter's __sk_buff len, and raw_tp's args[i]
	"ebpf.ctx.field.store": true,                               // sched_cls writing __sk_buff's mark
	"ebpf.xdp.adjust_head": true,                               // the head of an XDP packet
	"ebpf.xdp.adjust_tail": true,                               // shrinking the tail of an XDP packet
	"ebpf.flow_keys.load":  true, "ebpf.flow_keys.store": true, // flow_dissector's flow_keys
	"ebpf.tp.field":           true,                                                                                 // tracepoint event fields
	"ebpf.ksyscall.arg":       true,                                                                                 // ksyscall's syscall arguments
	"ebpf.kernel.read_scalar": true,                                                                                 // a fixed-width read through a kprobe ptr
	"ebpf.kernel.read_str":    true,                                                                                 // the string behind a char * in a kernel struct
	"ebpf.task.comm":          true,                                                                                 // the current task's comm — R.output_comm
	"ebpf.user.str_at":        true,                                                                                 // an argv slot — R.output_argv
	"ebpf.user.read":          true,                                                                                 // a user buffer — R.output_buf
	"ebpf.redirect_map":       true,                                                                                 // xdp redirect to a devmap (a terminator)
	"ebpf.sock.map_lookup":    true, "ebpf.sock.ref_check": true, "ebpf.sk.assign": true, "ebpf.sock.release": true, // sk_lookup's sk.assign
	"ebpf.kfield.ptr": true, "ebpf.kptr.check": true, // nullable kernel pointers
	"ebpf.kfield.copy":   true,                                         // copying an array field
	"ebpf.tp.field.copy": true,                                         // copying a tracepoint array field
	"ebpf.kptr.addr":     true,                                         // the address of a checked kernel pointer
	"ebpf.func":          true, "ebpf.call": true, "ebpf.return": true, // subprograms
	"ebpf.ringbuf.discard": true, // output_str_or_discard — a discard in each arm
	// ring buffer (discard is not emitted)
	"ebpf.ringbuf.reserve": true, "ebpf.ringbuf.if_reserved": true, "ebpf.ringbuf.store_record": true, "ebpf.ringbuf.submit": true, "ebpf.ref.field.load": true, "ebpf.ref.field.store": true, "ebpf.ref.field.atomic_add": true,
	// hash-family map operations that return a status, and atomic_add on a borrow (ebpf.map.delete, which drops the status, is not emitted)
	"ebpf.map.try_update": true, "ebpf.map.try_delete": true, "ebpf.ref.atomic_add": true,
	// the (U) — fully unrolled — form of bounded loops (the callback form and stop are not emitted)
	"ebpf.loop": true, "ebpf.loop.yield": true, "ebpf.break": true, "ebpf.continue": true,
	// variable indexes into a record's array members (only indexes proven in range by interval analysis)
	"ebpf.ref.index": true, "ebpf.elem.load": true, "ebpf.elem.store": true,
	// the early-return guard — two verdicts directly under the program
	"ebpf.verdict.if": true,
}

// AllowedOps returns the names of the allowed ops (for tests).
func AllowedOps() []string {
	var out []string
	for k := range allowedOps {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MlirOps returns the names of the ops in a .mlir text, in order of appearance.
func MlirOps(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		switch {
		case s == "", strings.HasPrefix(s, "//"), strings.HasPrefix(s, "^"), strings.HasPrefix(s, "}"):
			continue
		case strings.HasPrefix(s, "%"):
			i := strings.Index(s, "= ")
			if i < 0 {
				out = append(out, "<unparsed:"+s+">")
				continue
			}
			s = s[i+2:]
		}
		op := s
		if i := strings.IndexAny(s, " \t"); i >= 0 {
			op = s[:i]
		}
		out = append(out, op)
	}
	return out
}

// VerifyWorld checks that every op in text is in the allowed set.
func VerifyWorld(text string) error {
	var bad []string
	for _, op := range MlirOps(text) {
		if !allowedOps[op] {
			bad = append(bad, op)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("verify-bpf-world: the generated .mlir has ops outside the allowed set: %v", bad)
	}
	return nil
}

var refOpsLine = regexp.MustCompile("(?m)^- ① Input operations \\(\\d+\\): (.*)$") // bpf-mlir's English heading (it used to be in Japanese)
var backquoted = regexp.MustCompile("`([a-z0-9_.]+)`")

// ReferenceOps reads the list of ① (input) ops from bpf-mlir's docs/reference/ebpf_ops.md.
func ReferenceOps(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := refOpsLine.FindSubmatch(data)
	if m == nil {
		return nil, fmt.Errorf("%s: no `- ① Input operations (N): …` line", path)
	}
	out := map[string]bool{}
	for _, x := range backquoted.FindAllSubmatch(m[1], -1) {
		out[string(x[1])] = true
	}
	return out, nil
}
