package frontend

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var allowedOps = map[string]bool{
	"ebpf.program": true, "ebpf.verdict": true,
	"ebpf.map.lookup": true, "ebpf.map.update": true, "ebpf.map.atomic_add": true,
	"ebpf.ref.check": true, "ebpf.ref.load": true, "ebpf.yield": true,
	"arith.constant": true,
	"ebpf.if":        true, "ebpf.if.yield": true,
	"arith.addi": true, "arith.subi": true, "arith.muli": true, "arith.andi": true, "arith.ori": true, "arith.xori": true,
	"arith.shli": true, "arith.shrsi": true, "arith.shrui": true, "arith.divui": true, "arith.remui": true,
	"arith.floordivsi": true, "arith.remsi": true, "arith.cmpi": true, "arith.select": true,
	"arith.extui": true, "arith.extsi": true, "arith.trunci": true,
	"ebpf.packet.check": true, "ebpf.packet.window_load": true, "ebpf.byteorder.from_be": true,
	"ebpf.ktime.ns": true, "ebpf.record.make": true,
	"ebpf.global.load": true, "ebpf.global.atomic_add": true,
	"ebpf.ctx.retval": true, "ebpf.kprobe.arg": true, "ebpf.probe.retval": true, "ebpf.task.pid_tgid": true,
	"ebpf.uprobe.arg": true, "ebpf.user.read_str": true, "ebpf.ringbuf.store_field": true,
	"ebpf.ctx.arg": true, "ebpf.kfield.load": true,
	"ebpf.ctx.field":       true,
	"ebpf.ctx.field.store": true,
	"ebpf.xdp.adjust_head": true,
	"ebpf.xdp.adjust_tail": true,
	"ebpf.flow_keys.load":  true, "ebpf.flow_keys.store": true,
	"ebpf.tp.field":           true,
	"ebpf.ksyscall.arg":       true,
	"ebpf.kernel.read_scalar": true,
	"ebpf.kernel.read_str":    true,
	"ebpf.task.comm":          true,
	"ebpf.user.str_at":        true,
	"ebpf.user.read":          true,
	"ebpf.redirect_map":       true,
	"ebpf.sock.map_lookup":    true, "ebpf.sock.ref_check": true, "ebpf.sk.assign": true, "ebpf.sock.release": true,
	"ebpf.kfield.ptr": true, "ebpf.kptr.check": true,
	"ebpf.kfield.copy":   true,
	"ebpf.tp.field.copy": true,
	"ebpf.kptr.addr":     true,
	"ebpf.func":          true, "ebpf.call": true, "ebpf.return": true,
	"ebpf.ringbuf.discard": true,
	"ebpf.ringbuf.reserve": true, "ebpf.ringbuf.if_reserved": true, "ebpf.ringbuf.store_record": true, "ebpf.ringbuf.submit": true, "ebpf.ref.field.load": true, "ebpf.ref.field.store": true, "ebpf.ref.field.atomic_add": true,
	"ebpf.map.try_update": true, "ebpf.map.try_delete": true, "ebpf.ref.atomic_add": true,
	"ebpf.loop": true, "ebpf.loop.yield": true, "ebpf.break": true, "ebpf.continue": true,
	"ebpf.ref.index": true, "ebpf.elem.load": true, "ebpf.elem.store": true,
	"ebpf.verdict.if": true,
}

func AllowedOps() []string {
	var out []string
	for k := range allowedOps {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

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

var refOpsLine = regexp.MustCompile("(?m)^- ① Input operations \\(\\d+\\): (.*)$")
var backquoted = regexp.MustCompile("`([a-z0-9_.]+)`")

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
