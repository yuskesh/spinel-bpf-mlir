package frontend

import (
	"fmt"
	"regexp"
	"strings"
)

// struct_ops: a table of kernel callbacks filled with eBPF programs and registered as one struct_ops map.
//
//	BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "rbcount", init: :cc_init, ssthresh: :cc_ssthresh, …
//
// The first argument names the struct_ops map and the second is the kernel type. `name:` is the kernel-visible name; every other key
// is a member, and its value is the callback (a top-level def, a root like any other). Each callback becomes a struct_ops program
// whose argument count, argument kinds and return come from the member table below — the user declares none of them. The load-time
// requirements (structop / retsig / farg) check the table against the kernel's BTF.

// soArg is one argument of a struct_ops member: "sock" (the verifier's tcp_sock — read through a nullable kernel pointer),
// "task" (a struct task_struct *, read the same way), "exitinfo" (the struct scx_exit_info * of sched_ext's exit, read only
// by BPF::Scx.exit_info), "ptr" (a pointer the language does not read), "bool" (not read in this version), "int" (Type is
// :u8 … :i64) or "enum" (Bits wide, read as an unsigned integer).
type soArg struct {
	Kind string
	Type string
	Bits int
}

// soMember is one row of a struct_ops type's member table.
type soMember struct {
	Name string
	Line int // the line of the member in the kernel header the table cites
	Args []soArg
	Ret  string // "void" or an integer type name (:u32, :i32)
}

// soType is a struct_ops type the language accepts.
type soType struct {
	Name          string
	Header        string // the kernel header of the member table (7.3.1)
	Line          int    // the line of the struct in that header
	Members       []soMember
	Required      [][]string // each inner list is one requirement: at least one of its members must be declared
	NameMax       int        // the size of the name field including the NUL
	NameLine      int        // the line of the name length's definition (checked by a fixture; 0 when the test does not check it)
	Excluded      map[string]string
	ExcludedLines map[string]int
	Data          []soData        // the writable data members besides name
	Flags         []soFlag        // the named flags of the `flags` data member
	Sleepable     map[string]bool // the members whose programs are emitted sleepable
}

var soSock = soArg{Kind: "sock"}
var soPtr = soArg{Kind: "ptr"}

func soInt(t string) soArg { return soArg{Kind: "int", Type: t, Bits: recordTypes[t][0]} }

// tcpCongestionOps is 7.3.1 include/net/tcp.h's struct tcp_congestion_ops (:1324). The test TestStructOpsTable compares it with the
// pinned fixture testdata/structops/tcp_congestion_ops_7.3.1.txt row by row.
var tcpCongestionOps = &soType{
	Name: "tcp_congestion_ops", Header: "include/net/tcp.h", Line: 1324, NameMax: 16,
	Members: []soMember{
		{"cong_avoid", 1339, []soArg{soSock, soInt("u32"), soInt("u32")}, "void"},
		{"cong_control", 1343, []soArg{soSock, soInt("u32"), soInt("i32"), soPtr}, "void"},
		{"ssthresh", 1346, []soArg{soSock}, "u32"},
		{"set_state", 1349, []soArg{soSock, soInt("u8")}, "void"},
		{"cwnd_event", 1352, []soArg{soSock, {Kind: "enum", Type: "u32", Bits: 32}}, "void"},
		{"cwnd_event_tx_start", 1355, []soArg{soSock}, "void"},
		{"in_ack_event", 1358, []soArg{soSock, soInt("u32")}, "void"},
		{"pkts_acked", 1361, []soArg{soSock, soPtr}, "void"},
		{"min_tso_segs", 1364, []soArg{soSock}, "u32"},
		{"undo_cwnd", 1367, []soArg{soSock}, "u32"},
		{"sndbuf_expand", 1369, []soArg{soSock}, "u32"},
		{"init", 1383, []soArg{soSock}, "void"},
		{"release", 1385, []soArg{soSock}, "void"},
	},
	// tcp_validate_congestion_control (7.3.1 net/ipv4/tcp_cong.c)
	Required: [][]string{{"ssthresh"}, {"undo_cwnd"}, {"cong_avoid", "cong_control"}},
	Excluded: map[string]string{"get_info": "get_info returns size_t, a 64-bit return, which a struct_ops member does not support here"},
}

// soData is a writable data member of a struct_ops type (bpf-mlir StructOpsTypes.def's DATA rows): an unsigned integer of Bits
// bits, at most Max, with none of the Clear bits set.
type soData struct {
	Name  string
	Line  int // the line of the member in the kernel header
	Bits  int
	Max   uint64
	Clear uint64
}

// soFlag is a named flag a data member may be written with (`BPF::Scx::OPS_<NAME>`).
type soFlag struct {
	Name  string
	Line  int
	Value uint64
}

var soTask = soArg{Kind: "task"}
var soExitInfo = soArg{Kind: "exitinfo"}
var soBool = soArg{Kind: "bool"}

// schedExtOps is 7.3.1 kernel/sched/ext/internal.h's struct sched_ext_ops (:347). The tests compare it with the pinned fixture
// testdata/structops/sched_ext_ops_7.3.1.txt row by row.
var schedExtOps = &soType{
	Name: "sched_ext_ops", Header: "kernel/sched/ext/internal.h", Line: 347, NameMax: 128, NameLine: 18,
	Members: []soMember{
		{"select_cpu", 373, []soArg{soTask, soInt("i32"), soInt("u64")}, "i32"},
		{"enqueue", 388, []soArg{soTask, soInt("u64")}, "void"},
		{"dequeue", 404, []soArg{soTask, soInt("u64")}, "void"},
		{"dispatch", 427, []soArg{soInt("i32"), soTask}, "void"},
		{"tick", 438, []soArg{soTask}, "void"},
		{"runnable", 465, []soArg{soTask, soInt("u64")}, "void"},
		{"running", 482, []soArg{soTask}, "void"},
		{"stopping", 502, []soArg{soTask, soBool}, "void"},
		{"quiescent", 522, []soArg{soTask, soInt("u64")}, "void"},
		{"set_weight", 569, []soArg{soTask, soInt("u32")}, "void"},
		{"set_cpumask", 578, []soArg{soTask, soPtr}, "void"},
		{"update_idle", 607, []soArg{soInt("i32"), soBool}, "void"},
		{"init_task", 622, []soArg{soTask, soPtr}, "i32"},
		{"exit_task", 632, []soArg{soTask, soPtr}, "void"},
		{"enable", 641, []soArg{soTask}, "void"},
		{"disable", 651, []soArg{soTask}, "void"},
		{"dump", 659, []soArg{soPtr}, "void"},
		{"dump_cpu", 671, []soArg{soPtr, soInt("i32"), soBool}, "void"},
		{"dump_task", 681, []soArg{soPtr, soTask}, "void"},
		{"cgroup_init", 707, []soArg{soPtr, soPtr}, "i32"},
		{"cgroup_exit", 722, []soArg{soPtr}, "void"},
		{"cgroup_prep_move", 742, []soArg{soTask, soPtr, soPtr}, "i32"},
		{"cgroup_move", 753, []soArg{soTask, soPtr, soPtr}, "void"},
		{"cgroup_cancel_move", 765, []soArg{soTask, soPtr, soPtr}, "void"},
		{"cgroup_set_weight", 780, []soArg{soPtr, soInt("u32")}, "void"},
		{"cgroup_set_bandwidth", 802, []soArg{soPtr, soInt("u64"), soInt("u64"), soInt("u64")}, "void"},
		{"cgroup_set_idle", 816, []soArg{soPtr, soBool}, "void"},
		{"sub_attach", 826, []soArg{soPtr}, "i32"},
		{"sub_detach", 832, []soArg{soPtr}, "void"},
		{"sub_caps_updated", 852, []soArg{soPtr, soInt("u64")}, "void"},
		{"sub_ecaps_updated", 865, []soArg{soInt("i32"), soInt("u64"), soInt("u64")}, "void"},
		{"cpu_online", 878, []soArg{soInt("i32")}, "void"},
		{"cpu_offline", 887, []soArg{soInt("i32")}, "void"},
		{"init_cids", 900, nil, "i32"},
		{"init", 905, nil, "i32"},
		{"exit", 915, []soArg{soExitInfo}, "void"},
		{"cpu_acquire", 1034, []soArg{soInt("i32"), soPtr}, "void"},
		{"cpu_release", 1047, []soArg{soInt("i32"), soPtr}, "void"},
	},
	Excluded: map[string]string{
		"yield":             "it returns bool, which a struct_ops member does not return in this version",
		"core_sched_before": "it returns bool, which a struct_ops member does not return in this version",
	},
	ExcludedLines: map[string]int{"yield": 537, "core_sched_before": 560},
	// bpf-mlir StructOpsTypes.def:69-74 (the rules of bpf_scx_init_member, 7.3.1 ext/ext.c:8171)
	Data: []soData{
		{"dispatch_max_batch", 924, 32, 2147483647, 0},
		{"flags", 929, 64, 1<<63 - 1, 0xff00000000000000},
		{"timeout_ms", 938, 32, 30000, 0},
	},
	Flags: []soFlag{
		{"OPS_KEEP_BUILTIN_IDLE", 136, 1}, {"OPS_ENQ_LAST", 144, 2}, {"OPS_ENQ_EXITING", 158, 4}, {"OPS_SWITCH_PARTIAL", 164, 8},
		{"OPS_ENQ_MIGRATION_DISABLED", 177, 16}, {"OPS_ALLOW_QUEUED_WAKEUP", 193, 32}, {"OPS_BUILTIN_IDLE_PER_NODE", 199, 64},
		{"OPS_ALWAYS_ENQ_IMMED", 205, 128}, {"OPS_TID_TO_TASK", 216, 256},
	},
	// only init, as scx_simple.bpf.c:134 (BPF_STRUCT_OPS_SLEEPABLE); the kernel allows more (ext.c:8250-8263) — a frontend limit
	Sleepable: map[string]bool{"init": true},
}

// structOpsTypes holds the accepted struct_ops types.
var structOpsTypes = map[string]*soType{"tcp_congestion_ops": tcpCongestionOps, "sched_ext_ops": schedExtOps}

func (t *soType) member(name string) *soMember {
	for i := range t.Members {
		if t.Members[i].Name == name {
			return &t.Members[i]
		}
	}
	return nil
}

// StructOpsDecl is one `BPF.struct_ops` declaration (one struct_ops map).
type StructOpsDecl struct {
	Const   string // the map's symbol (the first argument)
	Type    string // the kernel struct_ops type
	KName   string // the kernel-visible name (`name:`)
	Ops     []StructOpsSlot
	Data    map[string]uint64 // the data members given besides name (sched_ext_ops' timeout_ms, flags, dispatch_max_batch)
	Pos     Pos
	EndLine int // the last line of the declaration (the twin keeps the whole statement)
}

func (t *soType) data(name string) *soData {
	for i := range t.Data {
		if t.Data[i].Name == name {
			return &t.Data[i]
		}
	}
	return nil
}

func (t *soType) dataNames() string {
	s := []string{"`name:`"}
	for _, d := range t.Data {
		s = append(s, "`"+d.Name+":`")
	}
	return strings.Join(s, ", ")
}

// soDataValue reads a data member's value: an Integer literal or, for `flags`, `BPF::Scx::OPS_<NAME>` constants joined with `|`.
// It returns the value, or a message for SB008.
func (z *analyzer) soDataValue(a *AST, t *soType, key string, v *Node) (uint64, string) {
	switch {
	case v.Type == "IntegerNode":
		x, ok := parseRubyInt(z.slice(v))
		if !ok || x.Sign() < 0 || !x.IsUint64() {
			return 0, fmt.Sprintf("`%s:` takes a non-negative Integer literal", key)
		}
		return x.Uint64(), ""
	case key == "flags" && (v.Type == "ConstantPathNode" || v.Type == "ConstantReadNode"):
		c := constName(a, v)
		for _, f := range t.Flags {
			if c == "BPF::Scx::"+f.Name {
				return f.Value, ""
			}
		}
		var names []string
		for _, f := range t.Flags {
			names = append(names, "BPF::Scx::"+f.Name)
		}
		return 0, fmt.Sprintf("%s is not a flag of %s (the flags are %s)", c, t.Name, strings.Join(names, ", "))
	case key == "flags" && v.Type == "CallNode" && v.Str["name"] == "|" && len(args(a, v)) == 1:
		l, msg := z.soDataValue(a, t, key, a.ref(v, "receiver"))
		if msg != "" {
			return 0, msg
		}
		r, msg := z.soDataValue(a, t, key, args(a, v)[0])
		if msg != "" {
			return 0, msg
		}
		return l | r, ""
	}
	if key == "flags" {
		return 0, "`flags:` takes an Integer literal or `BPF::Scx::OPS_<NAME>` constants joined with `|`"
	}
	return 0, fmt.Sprintf("`%s:` takes an Integer literal", key)
}

// StructOpsSlot binds a member to its callback.
type StructOpsSlot struct {
	Member  string
	Program string
}

// objName is bpf_obj_name_cpy's charset (7.3.1 kernel/bpf/syscall.c:1225 — isalnum, '_' and '.').
var objName = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)

// structOpsDecl reads `BPF.struct_ops :Map, "type", name: "…", member: :callback, …` (shape errors are SB008). It returns the
// declaration and one root per member.
func (z *analyzer) structOpsDecl(a *AST, n *Node) (*StructOpsDecl, []rootDecl, bool) {
	as := args(a, n)
	pos := z.pos(a, n)
	bad := func(at Pos, format string, x ...any) (*StructOpsDecl, []rootDecl, bool) {
		z.add(Rejected, SB008ProgramShape, at, format, x...)
		return nil, nil, false
	}
	shape := "`BPF.struct_ops :Map, \"tcp_congestion_ops\", name: \"kname\", member: :callback, …`" // the tcp form in every message
	if len(as) != 3 || as[0].Type != "SymbolNode" || as[1].Type != "StringNode" || as[2].Type != "KeywordHashNode" {
		return bad(pos, "a struct_ops table is declared as %s — a Symbol, a String literal and the keyword options", shape)
	}
	t := structOpsTypes[as[1].Str["content"]]
	if t == nil {
		return bad(z.pos(a, as[1]), "the String is not a struct_ops type of this version — the accepted types are sched_ext_ops and tcp_congestion_ops")
	}
	d := &StructOpsDecl{Const: as[0].Str["value"], Type: t.Name, Pos: pos, EndLine: n.EndLine}
	var roots []rootDecl
	declared := map[string]bool{}
	nameSeen := false
	for _, e := range a.arr(as[2], "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || v == nil || k.Type != "SymbolNode" {
			return bad(pos, "the options of %s are `key: literal` pairs", shape)
		}
		key := k.Str["value"]
		at := z.pos(a, k)
		if key == "name" {
			if v.Type != "StringNode" {
				return bad(z.pos(a, v), "`name:` of a %s table is a String literal (the kernel-visible name)", t.Name)
			}
			s := v.Str["content"]
			if len(s) == 0 || len(s) > t.NameMax-1 || !objName.MatchString(s) {
				return bad(z.pos(a, v), "`name:` is %d bytes; the kernel's name is 1 to %d bytes of [A-Za-z0-9_.] (bpf_obj_name_cpy; the %d-byte field holds the NUL)", len(s), t.NameMax-1, t.NameMax)
			}
			d.KName, nameSeen = s, true
			continue
		}
		if why, ok := t.Excluded[key]; ok {
			return bad(at, "the member `%s` of %s is not accepted in this version — %s", key, t.Name, why)
		}
		if dm := t.data(key); dm != nil { // a data member besides name
			if _, dup := d.Data[key]; dup {
				return bad(at, "the data member `%s:` is given twice", key)
			}
			x, msg := z.soDataValue(a, t, key, v)
			if msg != "" {
				return bad(z.pos(a, v), "%s", msg)
			}
			if x > dm.Max || x&dm.Clear != 0 {
				rule := fmt.Sprintf("at most %d", dm.Max)
				if dm.Clear != 0 {
					rule = fmt.Sprintf("without the bits 0x%x (the kernel's internal flags)", dm.Clear)
				}
				return bad(z.pos(a, v), "`%s:` is %d; %s.%s must be %s (bpf_scx_init_member, as bpf-mlir's struct_ops data rule)", key, x, t.Name, key, rule)
			}
			if d.Data == nil {
				d.Data = map[string]uint64{}
			}
			d.Data[key] = x
			continue
		}
		m := t.member(key)
		if m == nil {
			if len(t.Data) > 0 {
				return bad(at, "`%s` is not a member of %s (the members are %s; the data members are %s)", key, t.Name, t.memberNames(), t.dataNames())
			}
			return bad(at, "`%s` is not a member of %s (the members are %s; the only data member is `name:`)", key, t.Name, t.memberNames())
		}
		if declared[key] {
			return bad(at, "the member `%s` is given twice", key)
		}
		if v.Type != "SymbolNode" {
			return bad(z.pos(a, v), "the member `%s` takes the callback's name as a Symbol (`%s: :callback`)", key, key)
		}
		declared[key] = true
		d.Ops = append(d.Ops, StructOpsSlot{Member: key, Program: v.Str["value"]})
		roots = append(roots, rootDecl{Name: v.Str["value"], Kind: "struct_ops", Pos: pos, Target: d.Const, SOType: t.Name, SOMember: key, Nargs: len(m.Args), Ret: m.Ret})
	}
	if !nameSeen {
		return bad(pos, "a %s table needs `name:` (the kernel-visible name)", t.Name)
	}
	for _, req := range t.Required {
		ok := false
		for _, m := range req {
			ok = ok || declared[m]
		}
		if !ok {
			return bad(pos, "a %s table needs %s (tcp_validate_congestion_control)", t.Name, "`"+strings.Join(req, "` or `")+"`")
		}
	}
	return d, roots, true
}

func (t *soType) memberNames() string {
	var s []string
	for _, m := range t.Members {
		s = append(s, m.Name)
	}
	return strings.Join(s, ", ")
}

// soMemberOf returns the table row of a struct_ops program.
func soMemberOf(p *Program) *soMember {
	if t := structOpsTypes[p.SOType]; t != nil {
		return t.member(p.SOMember)
	}
	return nil
}

// structOpsArg checks `ctx.arg(i)` in a struct_ops program against the member table and returns the integer field (nil after an error).
func (c *progCtx) structOpsArg(n, idx *Node, i int64) *RecordField {
	m := soMemberOf(c.prog)
	if m == nil {
		return nil
	}
	if i < 0 || i >= int64(len(m.Args)) {
		c.add(Rejected, SB033KernelTypeShape, idx, "%s.%s has %d arguments — `%s.arg(%d)` is outside them", c.prog.SOType, m.Name, len(m.Args), c.param, i)
		return nil
	}
	ar := m.Args[i]
	switch ar.Kind {
	case "sock":
		c.add(Rejected, SB033KernelTypeShape, n, "argument %d of %s.%s is the socket pointer (struct sock *, read as tcp_sock) — it is not an integer; bind it with `tp = %s.kptr_or_null(%d, T)`", i, c.prog.SOType, m.Name, c.param, i)
		return nil
	case "task":
		c.add(Rejected, SB033KernelTypeShape, n, "argument %d of %s.%s is the task pointer (struct task_struct *) — it is not an integer; bind it with `p = %s.kptr_or_null(%d, T)`", i, c.prog.SOType, m.Name, c.param, i)
		return nil
	case "exitinfo":
		c.add(Rejected, SB033KernelTypeShape, n, "argument %d of %s.%s is the exit info (struct scx_exit_info *) — it is read only by `BPF::Scx.exit_info(%s, U)`", i, c.prog.SOType, m.Name, c.param)
		return nil
	case "bool":
		c.add(Rejected, SB033KernelTypeShape, n, "argument %d of %s.%s is a bool, which this version does not read", i, c.prog.SOType, m.Name)
		return nil
	case "ptr":
		c.add(Rejected, SB033KernelTypeShape, n, "argument %d of %s.%s is a pointer this version does not read", i, c.prog.SOType, m.Name)
		return nil
	}
	c.prog.SOArgs = soAddIndex(c.prog.SOArgs, int(i))
	rt := recordTypes[ar.Type]
	return &RecordField{Name: ar.Type, Bits: rt[0], Signed: rt[1] == 1}
}

// soAddIndex inserts i into the ascending list xs once.
func soAddIndex(xs []int, i int) []int {
	for k, x := range xs {
		if x == i {
			return xs
		}
		if x > i {
			return append(xs[:k], append([]int{i}, xs[k:]...)...)
		}
	}
	return append(xs, i)
}

// structOpsArgsSchema is the schema's args of a struct_ops program: present only when an argument is read, up to the last read
// index, null for the unread ones (bpf-mlir's shape).
func structOpsArgsSchema(p *Program) []any {
	m := soMemberOf(p)
	if m == nil || len(p.SOArgs) == 0 {
		return nil
	}
	out := make([]any, p.SOArgs[len(p.SOArgs)-1]+1)
	for _, i := range p.SOArgs {
		ar := m.Args[i]
		if ar.Kind == "sock" { // the socket argument read as a tcp_sock (bpf-mlir's schema)
			out[i] = "tcp_sock"
		} else if ar.Kind == "task" { // a task argument (bpf-mlir's schema)
			out[i] = "task_struct"
		} else if ar.Kind == "exitinfo" {
			out[i] = "scx_exit_info"
		} else if ar.Kind == "enum" {
			out[i] = schemaEnum{Kind: "enum", Bits: ar.Bits}
		} else {
			out[i] = traceInt(ar.Type)
		}
	}
	return out
}

// schemaEnum is a struct_ops enum argument ({"kind": "enum", "bits": N} — the width only).
type schemaEnum struct {
	Kind string `json:"kind"`
	Bits int    `json:"bits"`
}

// schemaStructOps is the struct_ops part of a struct_ops map row.
type schemaStructOps struct {
	Type             string           `json:"type"`
	Name             string           `json:"name"`
	TimeoutMs        *uint64          `json:"timeout_ms,omitempty"` // sched_ext_ops data members, only when given
	Flags            *uint64          `json:"flags,omitempty"`
	DispatchMaxBatch *uint64          `json:"dispatch_max_batch,omitempty"`
	Ops              []schemaStructOp `json:"ops"`
}

type schemaStructOp struct {
	Member  string `json:"member"`
	Program string `json:"program"`
}

// schemaStructOpsMap is a struct_ops map row (no value — the value is the kernel type).
type schemaStructOpsMap struct {
	Symbol     string          `json:"symbol"`
	Kind       string          `json:"kind"`
	Key        schemaInt       `json:"key"`
	MaxEntries int             `json:"max_entries"`
	Flags      int             `json:"flags"`
	Record     string          `json:"record"`
	StructOps  schemaStructOps `json:"struct_ops"`
	Note       string          `json:"note"`
}

func structOpsMapSchema(d *StructOpsDecl) schemaStructOpsMap {
	so := schemaStructOps{Type: d.Type, Name: d.KName}
	for k, v := range d.Data {
		x := v
		switch k {
		case "timeout_ms":
			so.TimeoutMs = &x
		case "flags":
			so.Flags = &x
		case "dispatch_max_batch":
			so.DispatchMaxBatch = &x
		}
	}
	for _, o := range d.Ops {
		so.Ops = append(so.Ops, schemaStructOp{Member: o.Member, Program: o.Program})
	}
	if mutation("structops-slot-swap") { // mutation: the programs of ssthresh and undo_cwnd swap slots
		var a, b = -1, -1
		for i, o := range so.Ops {
			if o.Member == "ssthresh" {
				a = i
			}
			if o.Member == "undo_cwnd" {
				b = i
			}
		}
		if a >= 0 && b >= 0 {
			so.Ops[a].Program, so.Ops[b].Program = so.Ops[b].Program, so.Ops[a].Program
		}
	}
	return schemaStructOpsMap{Symbol: d.Const, Kind: "struct_ops", Key: schemaInt{"int", 32, false, "little", 4}, MaxEntries: 1, Flags: 0, Record: "", StructOps: so, Note: fmt.Sprintf("Ruby BPF.struct_ops :%s", d.Const)}
}

// structOpsSock checks the socket-argument rule for `q = ctx.kptr_or_null(i, T)` in a struct_ops program: argument i of the member must be the
// socket, and T the sample handle of a kernel type named tcp_sock (the verifier's promotion of struct sock *). It records the read
// argument (the schema's args) and returns the nullable struct argument, or nil after an error.
func (c *progCtx) structOpsSock(v *Node, as []*Node, i int, h *KernelTypeDecl) *TpArg {
	m := soMemberOf(c.prog)
	if m == nil {
		return nil
	}
	if i < 0 || i >= len(m.Args) {
		c.add(Rejected, SB033KernelTypeShape, as[0], "%s.%s has %d arguments — `%s.kptr_or_null(%d, T)` is outside them", c.prog.SOType, m.Name, len(m.Args), c.param, i)
		return nil
	}
	if c.prog.SOType == "sched_ext_ops" { // a task argument, read as a task_struct
		if m.Args[i].Kind != "task" {
			c.add(Rejected, SB033KernelTypeShape, as[0], "argument %d of %s.%s is not a task pointer — only a struct task_struct * argument is read with `%s.kptr_or_null(i, T)`", i, c.prog.SOType, m.Name, c.param)
			return nil
		}
		if h == nil || h.Name != "task_struct" {
			got := as[1].Str["name"]
			if h != nil {
				got = fmt.Sprintf("%s (%s)", h.Const, h.Name)
			}
			c.add(Rejected, SB033KernelTypeShape, as[1], "argument %d of %s.%s is read as the kernel type task_struct, not %s — declare it with `BPF.kernel_type(S, \"task_struct\", …)`", i, c.prog.SOType, m.Name, got)
			return nil
		}
	} else if m.Args[i].Kind != "sock" {
		c.add(Rejected, SB033KernelTypeShape, as[0], "argument %d of %s.%s is not the socket pointer — only the struct sock * argument is read with `%s.kptr_or_null(i, T)` (as a tcp_sock)", i, c.prog.SOType, m.Name, c.param)
		return nil
	} else if h == nil || h.Name != "tcp_sock" {
		got := as[1].Str["name"]
		if h != nil {
			got = fmt.Sprintf("%s (%s)", h.Const, h.Name)
		}
		c.add(Rejected, SB033KernelTypeShape, as[1], "argument %d of %s.%s is read as the kernel type tcp_sock (the verifier promotes struct sock * to tcp_sock), not %s — declare it with `BPF.kernel_type(S, \"tcp_sock\", …)`", i, c.prog.SOType, m.Name, got)
		return nil
	}
	ta := c.prog.tpArg(i)
	if ta == nil {
		c.prog.TArgs = append(c.prog.TArgs, TpArg{Idx: i, KT: h, Null: true})
		ta = &c.prog.TArgs[len(c.prog.TArgs)-1]
	}
	c.prog.SOArgs = soAddIndex(c.prog.SOArgs, i)
	return ta
}

// structOpsKptrRefused stops `ctx.kptr(i, T)` in a struct_ops program (R1: the socket is read only through the null check).
func (c *progCtx) structOpsKptrRefused(n *Node) {
	c.add(Rejected, SB033KernelTypeShape, n, "a struct_ops program reads its socket argument only as `tp = %s.kptr_or_null(i, T)` followed by `if tp` — not with `%s.kptr`", c.param, c.param)
}

// kstoreCall reads the socket-write rule, the statement `q.set_field(:m, v)`: Stmt "kstore" → ebpf.kfield.store. The old name `q.store(…)` on a kernel
// pointer is a named refusal before any type lookup (Spinel types it as Hash#store). handled is false when n is
// neither on a kernel pointer nor on a checked local (then the ordinary rules apply, and Hash#store stays an ordinary call).
func (c *progCtx) kstoreCall(n *Node) (s Stmt, ok, handled bool) {
	op := n.Str["name"]
	if op != "set_field" && op != "store" {
		return Stmt{}, false, false
	}
	recv := c.a.ref(n, "receiver")
	if recv == nil || recv.Type != "LocalVariableReadNode" {
		return Stmt{}, false, false
	}
	t := recv.Str["name"]
	d := c.kptrs[t]
	if d == nil {
		if c.kchecked[t] { // after the `if q` (or in its else): q is not a pointer there
			c.add(Rejected, SB005RefCheckShape, n, "`%s` (a nullable kernel pointer) may be read only as `if %s` and as `%s.load.m` / `%s.set_field(:m, v)` inside it", t, t, t, t)
			return Stmt{}, false, true
		}
		return Stmt{}, false, false
	}
	if op == "store" {
		c.add(Rejected, SB033KernelTypeShape, n, "`%s.store` is not the kernel field write — write a field with `%s.set_field(:m, v)` (`store` is Hash#store to Spinel)", t, t)
		return Stmt{}, false, true
	}
	callee, cok := c.callee(n)
	if !cok {
		return Stmt{}, false, true
	}
	if callee != "KPtr#set_field" {
		c.add(Rejected, SB011ShadowedName, n, "`set_field` resolves to %s, not BPF::KPtr#set_field", callee)
		return Stmt{}, false, true
	}
	if c.prog.Kind != "struct_ops" {
		c.add(Rejected, SB033KernelTypeShape, n, "a kernel struct field is written only in a struct_ops program (`tp.set_field(:m, v)`) — %s programs read kernel structs only", c.prog.Kind)
		return Stmt{}, false, true
	}
	if !c.soSock[t] {
		c.add(Rejected, SB033KernelTypeShape, n, "`%s` is not the member's checked socket argument — only the tcp_sock bound by `tp = %s.kptr_or_null(i, T)` is written (the kernel writes no other struct)", t, c.param)
		return Stmt{}, false, true
	}
	as := args(c.a, n)
	if len(as) != 2 || as[0].Type != "SymbolNode" {
		c.add(Rejected, SB033KernelTypeShape, n, "`%s.set_field(:m, v)` takes a member Symbol literal and an Integer", t)
		return Stmt{}, false, true
	}
	f := d.field(as[0].Str["value"])
	if f == nil || f.Kind != "int" {
		what := "declares no member"
		if f != nil {
			what = "has no integer member"
		}
		c.add(Rejected, SB033KernelTypeShape, as[0], "%s (%s) %s `%s` to write", d.Const, d.Name, what, as[0].Str["value"])
		return Stmt{}, false, true
	}
	e := c.expr(as[1], "")
	if e == nil {
		return Stmt{}, false, true
	}
	r := widthRange(f.Bits, f.Signed)
	if e.Bool || e.Wide || !e.Iv.within(r.Lo, r.Hi) {
		if e.Bool || e.Wide {
			what := "a Bool, not an Integer"
			if !e.Bool {
				what = "an unnarrowed u64 value"
			}
			c.add(Rejected, SB014SemanticGap, as[1], "the value is %s — it does not fit %s.%s (%s %s); write an Integer that fits", what, d.Name, f.Name, soFieldTypeName(f), r)
			return Stmt{}, false, true
		}
		c.add(Rejected, SB014SemanticGap, as[1], "the value's range %s does not fit %s.%s (%s %s) — the store would truncate silently; narrow it (e.g. `& 0x%X`)", e.Iv, d.Name, f.Name, soFieldTypeName(f), r, r.Hi)
		return Stmt{}, false, true
	}
	return Stmt{Kind: "kstore", Var: t, Field: &RecordField{Name: f.Name, Bits: f.Bits, Signed: f.Signed}, KT: d, Val: e, Pos: c.z.pos(c.a, n)}, true, true
}

// soFieldTypeName names a kernel field's integer type in a diagnostic (u32, i32, …).
func soFieldTypeName(f *KernelField) string {
	if f.Signed {
		return fmt.Sprintf("i%d", f.Bits)
	}
	return fmt.Sprintf("u%d", f.Bits)
}
