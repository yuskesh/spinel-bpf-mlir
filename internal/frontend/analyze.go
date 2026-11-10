package frontend

import (
	"fmt"
	"math/big"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The classification of the program (accepted / rejected / unknown, with SB codes), and the translation of the eBPF-side subset into IR.

// ebpfOnlyHelpers lists the eBPF-side-only APIs outside libCallees that are stopped when called on the user side (the methods in bpf.rb
// that call BPF.ebpf_only; together with libCallees they cover every ebpf_only name in bpf.rb — TestEBPFOnlyStatic).
var ebpfOnlyHelpers = map[string]bool{
	"BPF.pid_tgid": true, "BPF.ktime_ns": true,
	"BPF.u64_add": true, "BPF.u64_sub": true, "BPF.u64_mul": true, "BPF.u64_div": true, "BPF.time_before": true, // the u64 intrinsics (u64ops.go)
	"BPF.fmod_return": true, // fmod_ret's replacement of the return value (only at the program's end and in a guard's return — verdict in program.go)
	"XdpMd#check":     true, "SkBuff#check": true, "Window#u8": true, "Window#be16": true, "Window#be32": true, "Window#le16": true, "Window#le32": true,
}

// libCallees lists the callees accepted on the eBPF side (the codegen's callee names); their defs must be in the library file (a callee
// is pinned by its file, not only by its name).
var libCallees = map[string]bool{
	"ArrayMap#atomic_add": true,
	"ArrayMap#lookup":     true,
	"ArrayMap#update":     true,
	"MapRef#load":         true,
	// records
	"RecordMap#lookup":     true,
	"RecordMap#update":     true,
	"RecordRef#load":       true,
	"RecordRef#atomic_add": true,
	// ring buffer
	"RingBuf#output": true,
	// hash-family maps, and atomic_add on a borrowed integer value
	"MapRef#atomic_add": true,
	// per-CPU maps
	"PerCpuArrayMap#lookup":       true,
	"PerCpuArrayMap#update":       true,
	"PerCpuArrayMap#atomic_add":   true,
	"PerCpuRecordMap#lookup":      true,
	"PerCpuRecordMap#update":      true,
	"PerCpuHashMap#lookup":        true,
	"PerCpuHashMap#update":        true,
	"PerCpuHashMap#insert":        true,
	"PerCpuHashMap#replace":       true,
	"PerCpuHashMap#delete":        true,
	"PerCpuHashMap#add_or_init":   true,
	"PerCpuRecordHashMap#lookup":  true,
	"PerCpuRecordHashMap#update":  true,
	"PerCpuRecordHashMap#insert":  true,
	"PerCpuRecordHashMap#replace": true,
	"PerCpuRecordHashMap#delete":  true,
	"HashMap#lookup":              true,
	"HashMap#update":              true,
	"HashMap#insert":              true,
	"HashMap#replace":             true,
	"HashMap#delete":              true,
	"HashMap#add_or_init":         true,
	"LruHashMap#lookup":           true,
	"LruHashMap#update":           true,
	"LruHashMap#insert":           true,
	"LruHashMap#replace":          true,
	"LruHashMap#delete":           true,
	"LruHashMap#add_or_init":      true,
	"RecordHashMap#lookup":        true,
	"RecordHashMap#update":        true,
	"RecordHashMap#insert":        true,
	"RecordHashMap#replace":       true,
	"RecordHashMap#delete":        true,
	"LruRecordHashMap#lookup":     true,
	"LruRecordHashMap#update":     true,
	"LruRecordHashMap#insert":     true,
	"LruRecordHashMap#replace":    true,
	"LruRecordHashMap#delete":     true,
	// lpm_trie (read-only — lookup only)
	"LpmTrieMap#lookup": true,
	// tracing context reads and helpers
	"FexitCtx#ret":        true,
	"KretprobeCtx#ret":    true,                          // kretprobe's return value
	"UretprobeCtx#ret":    true,                          // uretprobe's return value
	"SocketFilterCtx#len": true,                          // socket_filter's __sk_buff len
	"CgroupSkb#len":       true, "CgroupSkb#check": true, // cgroup_skb's len and packet window
	"NfCtx#state": true, "NfCtx#skb": true, // netfilter's kernel pointers in bpf_nf_ctx
	"StructOpsCtx#arg":          true,                            // struct_ops: an integer argument of the member
	"StructOpsCtx#kptr_or_null": true, "StructOpsCtx#kptr": true, // struct_ops: the socket argument (kptr is refused by name)
	"KPtr#set_field": true,                                               // struct_ops: a kernel struct integer field write (ebpf.kfield.store)
	"FmodRetCtx#arg": true,                                               // fmod_ret's integer argument (the same ctx.arg as fentry)
	"FlowCtx#check":  true, "FlowCtx#key": true, "FlowCtx#set_key": true, // flow_dissector's packet and flow_keys
	"XdpMd#ingress_ifindex": true, "SkBuff#len": true, "SkBuff#mark": true, "SkBuff#mark=": true, // xdp / tc context fields
	"XdpMd#adjust_head": true, "XdpMd#adjust_tail": true, // XDP adjust_head / adjust_tail
	// global variables
	"Config#value": true, "OptionalConfig#value": true, "Counter#value": true, "Counter#add": true,
	"Global#value": true, "Global#set": true, "Global#store": true, "ExitInfo#value": true, // a Global (store is refused by name) and the exit record
	"Scx.select_cpu_dfl": true, "Scx.dsq_insert": true, "Scx.dsq_insert_vtime": true, "Scx.dsq_move_to_local": true, // the sched_ext ops
	"Scx.create_dsq": true, "Scx.task_set_dsq_vtime": true, "Scx.error": true, "Scx.exit_info": true,
	"KprobeCtx#arg":   true,
	"FentryCtx#arg":   true,                                 // fentry's integer argument
	"DevMap#redirect": true,                                 // xdp's redirect_map terminator
	"SockMap#assign":  true, "SkLookupCtx#local_port": true, // sk_lookup's sk.assign and the ctx's local_port
	"KprobeCtx#read":       true,                                                                // a fixed-width read through a ptr argument (value and status)
	"RawTpCtx#arg":         true,                                                                // raw_tp's args[i] (u64)
	"KsyscallCtx#arg":      true,                                                                // ksyscall's syscall argument (the declared n)
	"KsyscallCtx#str_arg":  true,                                                                // ksyscall's :user_str argument (only as the third argument of output_str)
	"KsyscallCtx#argv_arg": true, "TracepointCtx#argv_field": true, "RingBuf#output_argv": true, // argv (only as the third argument of output_argv)
	"TracepointCtx#copy":      true, // copy of an array field (only as an argument of S.new in R.output, or in r.load.m =)
	"KPtr#addr":               true, // the address of a checked kernel pointer (ebpf.kptr.addr)
	"TracepointCtx#field":     true, // a tracepoint event field (the declared type)
	"TracepointCtx#str_field": true, // a tracepoint :user_str field (only as the third argument of output_str)
	// uprobe context reads and output_str
	"UprobeCtx#arg": true, "UprobeCtx#str_arg": true, "RingBuf#output_str": true, "OutputStr#status": true, "RingBuf#output_str_or_discard": true, "OutputStr#sent": true, // output_str_or_discard
	"UprobeCtx#buf_arg": true, "RingBuf#output_buf": true, // uprobe's :user_buf (only as the third argument of output_buf)
	"RingBuf#output_comm": true, // the comm of the current task (ebpf.task.comm)
	// tp_btf and CO-RE (Compile Once – Run Everywhere: kernel-struct field reads relocated at load time)
	"TpBtfCtx#kptr": true, "TpBtfCtx#kptr_or_null": true, "FentryCtx#kptr_or_null": true, "TpBtfCtx#arg": true, "KPtr#load": true, "KPtr#ptr": true, "KPtr#copy": true, "KPtr#str": true, /* KPtr#str: kernel string read */
}

// libNames lists the names that ruby/lib/bpf.rb defines (a user who defines or reopens a class / module of the same name gets SB011).
var libNames = map[string]bool{"BPF": true, "ArrayMap": true, "MapRef": true, "XdpMd": true, "Window": true, "RecordMap": true, "RecordRef": true, "RingBuf": true, "HashMap": true, "LruHashMap": true, "RecordHashMap": true, "LruRecordHashMap": true, "PerCpuArrayMap": true, "PerCpuRecordMap": true, "PerCpuHashMap": true, "PerCpuRecordHashMap": true, "LpmTrieMap": true, "DevMap": true, "SockMap": true}

// builtinReopen lists the builtins whose reopening makes the eBPF-side verdict Unknown (the meaning of operators and comparisons may
// change).
var builtinReopen = map[string]bool{
	"Integer": true, "Object": true, "Kernel": true, "BasicObject": true, "Comparable": true, "Module": true, "Class": true,
	"NilClass": true, "TrueClass": true, "FalseClass": true, "Symbol": true, "String": true, "Array": true, "Hash": true, "Numeric": true,
}

// dynamicCalls lists the calls that break the assumption of static callees when they appear anywhere in the program.
var dynamicCalls = map[string]bool{
	"send": true, "public_send": true, "__send__": true, "define_method": true, "instance_eval": true, "class_eval": true,
	"module_eval": true, "instance_exec": true, "class_exec": true, "eval": true, "method": true, "instance_variable_get": true,
	"instance_variable_set": true, "const_get": true, "const_set": true, "prepend": true, "include": true, "extend": true,
	"refine": true, "using": true, "alias_method": true, "remove_method": true, "undef_method": true,
}

// threadConsts lists the constants that pull in Spinel's threaded runtime (used to attach a position; the decision itself comes from
// Spinel's -DSP_THREADS).
var threadConsts = map[string]bool{"Thread": true, "Mutex": true, "Queue": true, "SizedQueue": true, "ConditionVariable": true, "Monitor": true, "Ractor": true}

var dynamicDefs = map[string]bool{"method_missing": true, "respond_to_missing?": true}

// operators lists the names of the builtin operators (if one resolves to a callee, the user redefined it — SB009).
var operators = map[string]bool{
	"+": true, "-": true, "*": true, "/": true, "%": true, "**": true, "==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
	"<=>": true, "&": true, "|": true, "^": true, "<<": true, ">>": true, "!": true, "~": true, "-@": true, "+@": true, "===": true, "[]": true, "[]=": true,
}

// xdpVerdicts maps the BPF::XDP_* constants to ebpf.verdict names (ebpf.verdict in bpf-mlir's docs/reference/ebpf_ops.md).
var xdpVerdicts = map[string]string{"XDP_ABORTED": "aborted", "XDP_DROP": "drop", "XDP_PASS": "pass", "XDP_TX": "tx"}

// tcVerdicts maps the BPF::TC_* constants to sched_cls ebpf.verdict names (bpf-mlir's sched_cls has only pass / drop).
var tcVerdicts = map[string]string{"TC_PASS": "pass", "TC_DROP": "drop"}

// sfVerdicts maps the BPF::SF_* constants to socket_filter ebpf.verdict names (keep is the u32 maximum — accept all bytes; drop is 0).
var sfVerdicts = map[string]string{"SF_KEEP": "keep", "SF_DROP": "drop"}

// cgVerdicts maps the BPF::CG_* constants to cgroup_skb ebpf.verdict names (allow is 1, deny is 0; the egress-only deny_cn / allow_cn
// are not added).
var cgVerdicts = map[string]string{"CG_ALLOW": "allow", "CG_DENY": "deny"}

// nfVerdicts maps the BPF::NF_* constants to netfilter ebpf.verdict names (accept is 1, drop is 0 — Linux's NF_ACCEPT / NF_DROP).
var nfVerdicts = map[string]string{"NF_ACCEPT": "accept", "NF_DROP": "drop"}

// flowVerdicts maps the BPF::FLOW_* constants to flow_dissector ebpf.verdict names (BPF_OK is 0, BPF_DROP 2,
// BPF_FLOW_DISSECTOR_CONTINUE 129).
var flowVerdicts = map[string]string{"FLOW_OK": "ok", "FLOW_DROP": "drop", "FLOW_CONTINUE": "flow_dissector_continue"}

// skVerdicts maps the BPF::SK_* constants to sk_lookup ebpf.verdict names (SK_DROP is 0, SK_PASS 1).
var skVerdicts = map[string]string{"SK_PASS": "pass", "SK_DROP": "drop"}

// fmodVerdicts maps BPF::FMOD_CALL to the fmod_ret ebpf.verdict name (0 calls the original function; replacing the return value is
// `BPF.fmod_return(e)` — ebpf.return).
var fmodVerdicts = map[string]string{"FMOD_CALL": "done"}

// verdictsOf returns the verdict table of a kind. Tracing kinds get nil (they return no verdict — the last value is dropped and the
// program ends with "done").
func verdictsOf(kind string) map[string]string {
	switch kind {
	case "xdp":
		return xdpVerdicts
	case "sched_cls":
		return tcVerdicts
	case "socket_filter":
		return sfVerdicts
	case "cgroup_skb":
		return cgVerdicts
	case "netfilter":
		return nfVerdicts
	case "flow_dissector":
		return flowVerdicts
	case "sk_lookup":
		return skVerdicts
	case "fmod_ret":
		return fmodVerdicts
	}
	return nil
}

// verdictKindOf returns the kind of the table ("xdp" / "sched_cls" / "socket_filter") when `BPF::<name>` is a verdict constant, and ""
// otherwise (a verdict constant of another kind is SB028).
func verdictKindOf(cn string) string {
	if len(cn) <= 5 || cn[:5] != "BPF::" {
		return ""
	}
	if xdpVerdicts[cn[5:]] != "" {
		return "xdp"
	}
	if tcVerdicts[cn[5:]] != "" {
		return "sched_cls"
	}
	if sfVerdicts[cn[5:]] != "" {
		return "socket_filter"
	}
	if cgVerdicts[cn[5:]] != "" {
		return "cgroup_skb"
	}
	if nfVerdicts[cn[5:]] != "" {
		return "netfilter"
	}
	if flowVerdicts[cn[5:]] != "" {
		return "flow_dissector"
	}
	if skVerdicts[cn[5:]] != "" {
		return "sk_lookup"
	}
	if fmodVerdicts[cn[5:]] != "" {
		return "fmod_ret"
	}
	return ""
}

// hasPacket reports whether a kind has a packet (`ctx.check` and windows): xdp and sched_cls, and cgroup_skb (whose data starts at the
// network header). A tracing context has no packet.
func hasPacket(kind string) bool {
	return kind == "xdp" || kind == "sched_cls" || kind == "cgroup_skb" || kind == "flow_dissector"
}

// isTracing reports whether a kind has no verdict table (tracing: the last value is dropped and the program ends with "done"; the
// harness attaches it and runs it with a real trigger or a tracing test run). socket_filter has no packet but returns a verdict and runs
// in a test run — code that used `!hasPacket` to mean tracing uses this instead.
func isTracing(kind string) bool { return verdictsOf(kind) == nil }

// attachesKernelFunc reports whether the harness attaches a kind after loading it (tracing kinds, and fmod_ret, which returns a value).
func attachesKernelFunc(kind string) bool { return isTracing(kind) || kind == "fmod_ret" }

// declName returns the name of the method that declares a kind (sched_cls is `BPF.tcx`; the others are the kind itself).
func declName(kind string) string {
	if kind == "sched_cls" {
		return "tcx"
	}
	return kind
}

// relRequire matches the require_relative / load lines named when Spinel fails (only statements at the start of a line).
var relRequire = regexp.MustCompile(`^\s*(require_relative|load)\b`)

var reservedPrefix = regexp.MustCompile(`^_?spinelbpf_`)

// MapDecl is the declaration of a shared map (`Counts = BPF::ArrayMap.new("Counts", 64, 2)`).
type MapDecl struct {
	Const      string
	Name       string
	ValueBits  int
	Signed     bool
	MaxEntries uint64
	Record     *RecordDecl // a record map — nil for an integer map
	// hash-family maps (Kind "" is an array). The key is an integer (KeyBits / KeySigned) or a record (KeyRecord)
	Kind      string
	Class     string
	KeyBits   int
	KeySigned bool
	KeyRecord *RecordDecl
	Pos       Pos
}

// MapKind returns the kind used in the schema and maps.json ("array" / "percpu_array" / "hash" / "lru_hash" / "percpu_hash" / "lpm_trie").
func (m *MapDecl) MapKind() string {
	if m.Kind == "" {
		return "array"
	}
	return m.Kind
}

// IsHash reports whether the map is in the hash family (hash / lru_hash / percpu_hash — the key has any type, and write operations
// return a status).
func (m *MapDecl) IsHash() bool {
	return m.Kind == "hash" || m.Kind == "lru_hash" || m.Kind == "percpu_hash"
}

// IsArray reports whether the map is in the array family (array / percpu_array — the key is a u32 index). It became an explicit test
// when lpm_trie was added (before, it was !IsHash, and an lpm_trie silently became an array).
func (m *MapDecl) IsArray() bool { return m.Kind == "" || m.Kind == "percpu_array" }

// PerCPU reports whether the map is per-CPU (reads and writes go to the current CPU's slot).
func (m *MapDecl) PerCPU() bool { return strings.HasPrefix(m.Kind, "percpu_") }

// ClassName returns the bpf.rb class name (the Spinel type of the map constant).
func (m *MapDecl) ClassName() string {
	switch {
	case m.Class != "":
		return m.Class
	case m.Record != nil:
		return "RecordMap"
	}
	return "ArrayMap"
}

// KeyTypeName returns the spelling of the key type (in maps.json — u32 for an array).
func (m *MapDecl) KeyTypeName() string {
	switch {
	case m.KeyRecord != nil:
		return "record:" + m.KeyRecord.Const
	case m.IsArray(), m.IsDevmap(), m.Kind == "sockmap": // the devmap and sockmap keys are u32 too
		return "u32"
	case m.KeySigned:
		return fmt.Sprintf("i%d", m.KeyBits)
	}
	return fmt.Sprintf("u%d", m.KeyBits)
}

// TypeName returns the spelling of the value type (u32 / i32 / u64 / i64 — the same as in maps.json and the schema).
func (m *MapDecl) TypeName() string {
	if m.Record != nil {
		return "record:" + m.Record.Const
	}
	if m.Signed {
		return fmt.Sprintf("i%d", m.ValueBits)
	}
	return fmt.Sprintf("u%d", m.ValueBits)
}

// Program is one eBPF-side program.
type Program struct {
	Name         string
	Kind         string        // "xdp" "fentry" "fexit" "kprobe" "sched_cls" (sched_cls is declared with BPF.tcx, and Target is the direction)
	Target       string        // tracing: the attach target
	Nargs        int           // fexit
	Ret          string        // fexit: the return type (a name such as :i32)
	Params       []KParam      // kprobe / uprobe (a uprobe's Type may also be :user_str)
	TArgs        []TpArg       // tp_btf: declarations of the arguments read
	TFields      []TpField     // tracepoint: declarations of the event fields
	FParams      []string      // func: the names of the subprogram's arguments
	FRet         *Expr         // func: the return value (the last expression)
	FBorrow      int           // func: the position of the borrowed argument (-1 for none)
	FBorrowMap   *MapDecl      // func: the map of the borrow
	FWin         int           // func: the position of the packet-window argument (-1 for none)
	FWinLen      int64         // func: the window length
	FCtx         int           // func: the position of the context argument (-1 for none)
	FCtxKind     string        // func: the kind of the context
	BinarySHA    string        // uprobe: target binary's SHA-256 (read at build time, path relative to the source dir; the path stays out of the outputs)
	BinaryPath   string        // uprobe: the path of the file read at build time (only for the build-time check — not put in the outputs)
	SysTarget    string        // uprobe: the declared target if it is a canonical absolute path (a system library); the test harness loads it (not in outputs)
	Globals      []*GlobalDecl // the globals used (in declaration order)
	Pos          Pos
	DeclPos      Pos
	Body         []Stmt
	Verdict      string
	VerdictConst string // the name of the BPF::XDP_* constant (XDP_PASS)
	// the last expression is `M.redirect(k, BPF::XDP_*)` (xdp's redirect_map terminator — Verdict is the fallback)
	RedirMap     *MapDecl
	RedirKey     *Expr
	GuardVerdict string // the verdict of an early-return guard ("" for none — the end is ebpf.verdict.if fired "<GuardVerdict>" else "<Verdict>")
	// fmod_ret's replacement of the return value: FmodVal is the e of the last `BPF.fmod_return(e)` (nil for BPF::FMOD_CALL), FmodGuard
	// is the literal of the guard's `return BPF.fmod_return(literal) if c` (nil when there is no guard or it is FMOD_CALL). If either is
	// set, the terminator is ebpf.return … : i32
	FmodVal          *Expr
	FmodGuard        *big.Int
	VerdictPos       Pos
	EndLine          int         // the last line of the def (for the copy in the native twin)
	Maps             []*MapDecl  // the maps used (in declaration order)
	Rings            []*RingDecl // the ring buffers used (in declaration order — not in the program's maps [...] or its block arguments)
	SOType, SOMember string      // struct_ops: the kernel type and the member
	SOArgs           []int       // struct_ops: the argument indexes read, ascending and once each
	SOVal            *Expr       // struct_ops: the return value of an integer member (the last expression)
	Scx              bool        // the program calls a sched_ext op (the module carries ebpf.scx_kfuncs = "insert")
}

// Edge is a call edge (for the domain graph).
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Pos      Pos    `json:"pos"`
	Dispatch string `json:"dispatch"`
}

// Result is the result of the analysis.
type Result struct {
	Source      string
	Programs    []*Program
	Maps        []*MapDecl
	Rings       []*RingDecl         // the ring buffers the programs use (in declaration order)
	Globals     []*GlobalDecl       // the globals the programs use (in declaration order)
	KernelTypes []*KernelTypeDecl   // the CO-RE kernel structs (in declaration order — when there is a tp_btf program)
	Funcs       []*Program          // the eBPF-side subprograms (Kind "func" — in declaration order)
	StructOps   []*StructOpsDecl    // the struct_ops tables
	Membership  map[string][]string // function → {"user","bpf"}
	Edges       []Edge
	Diags       Diags
}

type analyzer struct {
	base      string
	text      string
	lines     []string
	userLines int
	// threadRefs holds the positions of references to constants such as Thread (SB012 / SB027 — split after reachability)
	threadRefs []threadRef
	lib        string                     // the absolute path of bpf.rb
	srcDir     string                     // the directory of the user's source (the base of a uprobe target's relative path)
	kts        map[string]*KernelTypeDecl // Struct constant → kernel struct declaration
	ktOrder    []*KernelTypeDecl
	ktHandles  map[string]*KernelTypeDecl // constant of a sample handle → declaration
	funcs      map[string]*funcInfo       // the eBPF-side subprograms
	flowsOf    map[string]*fnFlows        // value flows and call sites per function (for SB019 across functions)
	siteByNode map[int]*callSite          // call node → site
	anyBadFunc bool                       // some subprogram was stopped
	plain      *Analysis
	structOps  []*StructOpsDecl
	typing     *Analysis
	diags      Diags
	maps       map[string]*MapDecl // constant name → declaration
	mapOrder   []*MapDecl
	records    map[string]*RecordDecl // Struct constant name → record declaration
	rings      map[string]*RingDecl   // constant name → ring buffer declaration
	ringOrder  []*RingDecl
	badRings   map[string]bool // ring buffer constants whose declaration was stopped
	badMaps    map[string]bool // map constants whose declaration was stopped (not reported again at the uses — reason priority 1)
	// global variables
	globals     map[string]*GlobalDecl
	globalOrder []*GlobalDecl
	badGlobals  map[string]bool
	rootKinds   []string        // the kinds of the program roots (the condition for the per-CPU SB019 exemption)
	badHash     map[string]bool // those of them that are hash-family maps (status operations are not reported again at the uses)
	badRecs     map[string]bool // Struct constants of records whose declaration was stopped
}

func (z *analyzer) add(v Verdict, c Code, p Pos, format string, args ...any) {
	z.diags = append(z.diags, Diag{Verdict: v, Code: c, Pos: p, Msg: fmt.Sprintf(format, args...)})
}

func (z *analyzer) pos(a *AST, n *Node) Pos {
	f := a.File(n)
	if f != z.base {
		f = filepath.Base(f)
	}
	return Pos{File: f, Line: n.Line, Col: n.Col + 1}
}

// userFile returns the id of the user's file.
func userFileID(a *AST, base string) int {
	for id, p := range a.Files {
		if p == base {
			return id
		}
	}
	return -1
}

// topStatements returns the top-level statements of the user's file (excluding library statements spliced in by require).
func topStatements(a *AST, fid int) []*Node {
	root := a.node(a.Root)
	st := a.ref(root, "statements")
	if st == nil {
		return nil
	}
	var out []*Node
	for _, n := range a.arr(st, "body") {
		if n.FileID == fid {
			out = append(out, n)
		}
	}
	return out
}

// walk visits the subtree of n in preorder.
func walk(a *AST, n *Node, f func(*Node) bool) {
	if n == nil {
		return
	}
	if !f(n) {
		return
	}
	fields := make([]string, 0, len(n.Ref)+len(n.Arr))
	for k := range n.Ref {
		fields = append(fields, "R"+k)
	}
	for k := range n.Arr {
		fields = append(fields, "A"+k)
	}
	sort.Strings(fields)
	for _, k := range fields {
		if k[0] == 'R' {
			walk(a, a.ref(n, k[1:]), f)
		} else {
			for _, c := range a.arr(n, k[1:]) {
				walk(a, c, f)
			}
		}
	}
}

// constName returns the name of a ConstantReadNode / ConstantPathNode (one level) ("Counts" / "BPF::ArrayMap"), and "" for anything else.
func constName(a *AST, n *Node) string {
	if n == nil {
		return ""
	}
	switch n.Type {
	case "ConstantReadNode":
		return n.Str["name"]
	case "ConstantPathNode":
		p := a.ref(n, "parent")
		if p == nil {
			return "::" + n.Str["name"]
		}
		pn := constName(a, p)
		if pn == "" {
			return ""
		}
		return pn + "::" + n.Str["name"]
	}
	return ""
}

func args(a *AST, call *Node) []*Node {
	an := a.ref(call, "arguments")
	if an == nil {
		return nil
	}
	return a.arr(an, "arguments")
}

// Analyze analyzes the user's source. Any blocking verdict goes into Result.Diags, and Programs is then left empty.
func Analyze(sp Spinel, work, sourcePath, text string) (*Result, error) {
	return analyze(sp, work, sourcePath, text, analyzeOpts{})
}

// analyzeOpts holds overrides for tests (not used on the user path).
type analyzeOpts struct {
	inject       string       // the context expression to inject ("" means .new of the root kind's class — BPF::XdpMd.new and so on)
	mutateTyping func(*Types) // rewrites the injected run's types before the checks (tests of verdicts the source cannot reach — SB004, SB015, SB010)
	// stopTop, when set, receives the state after step 2 and the step 3 injected text, and analyze returns right after it,
	// before the typing Spinel run (the C frontend's top level is compared with this state). Test only; nil on the user path.
	stopTop func(z *analyzer, roots []rootDecl, inject string)
}

func analyze(sp Spinel, work, sourcePath, text string, o analyzeOpts) (*Result, error) {
	base := filepath.Base(sourcePath)
	lib, err := filepath.Abs(filepath.Join(sp.LibDir, "bpf.rb"))
	if err != nil {
		return nil, err
	}
	z := &analyzer{kts: map[string]*KernelTypeDecl{}, ktHandles: map[string]*KernelTypeDecl{}, base: base, srcDir: filepath.Dir(sourcePath), text: text, lib: lib, maps: map[string]*MapDecl{}, records: map[string]*RecordDecl{}, rings: map[string]*RingDecl{}, badRings: map[string]bool{}, badMaps: map[string]bool{}, globals: map[string]*GlobalDecl{}, badGlobals: map[string]bool{}, badHash: map[string]bool{}, badRecs: map[string]bool{}}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
		z.text = text
	}
	z.lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	z.userLines = len(z.lines)
	res := &Result{Source: base}

	// 1. no injection (the user's source as it is)
	plain, ds, err := sp.Analyze(filepath.Join(work, "plain"), base, text)
	if err != nil {
		return nil, err
	}
	if len(ds) > 0 {
		// Only when Spinel failed: name the require_relative / load that cannot be resolved in the analysis directory (a program is one
		// file plus require "bpf")
		for i, l := range z.lines {
			if m := relRequire.FindStringSubmatchIndex(l); m != nil {
				res.Diags = Diags{{Verdict: Rejected, Code: SB001UnsupportedConstruct, Pos: Pos{File: base, Line: i + 1, Col: m[2] + 1},
					Msg: "`" + l[m[2]:m[3]] + "` is not accepted (the program is one file plus `require \"bpf\"`); spinel: " + ds[0].Msg}}
				return res, nil
			}
		}
		res.Diags = ds
		return res, nil
	}
	z.plain = plain
	a := plain.AST
	fid := userFileID(a, base)
	if fid < 0 {
		return nil, fmt.Errorf("spinel AST has no FILE record for %s", base)
	}
	// When Spinel splices in builtins it adds require lines at the head of the source, and the user's file's lines shift
	// (upstream_suspects S11). Measure the shift k by matching named nodes and move the AST and type records back. If it cannot be
	// measured, stop with SB000 before every check that relies on positions
	if _, ok := alignSplice(plain, base, text); !ok {
		z.add(Rejected, SB000Spinel, Pos{File: base}, spliceMsg)
		res.Diags = z.diags
		return res, nil
	}

	// Threads: Spinel's own decision (the -DSP_THREADS runtime). The position comes from the constant reads in the AST
	threads, err := sp.UsesThreads(filepath.Join(work, "plain"), base)
	if err != nil {
		return nil, err
	}
	if threads {
		walk(a, a.node(a.Root), func(n *Node) bool {
			if n.FileID == fid && (n.Type == "ConstantReadNode" || n.Type == "ConstantPathNode") && threadConsts[n.Str["name"]] {
				// diagnosed after reachability (flushThreadRefs): SB027 inside a function the eBPF side reaches (the user side is allowed)
				z.threadRefs = append(z.threadRefs, threadRef{name: n.Str["name"], pos: z.pos(a, n), line: n.Line})
			}
			return true
		})
		// Threads on the user side are allowed (SB012 is retired — the C loader has no Go runtime signals to conflict with)
	}

	// 2. top-level statements: require, map declarations, root declarations, def, class
	roots := z.scanTop(a, fid)
	for _, r := range roots {
		z.rootKinds = append(z.rootKinds, r.Kind) // the condition for the per-CPU exemption
	}
	z.scanProgramWide(a, fid)
	z.checkMemberDefs(a, fid, roots)
	if len(roots) == 0 {
		if !z.diags.Blocking() {
			z.add(Rejected, SB008ProgramShape, Pos{File: base}, "no eBPF program: declare one with `BPF.xdp :name` at the top level")
		}
		z.flushThreadRefs(nil, nil)
		res.Diags = z.diags
		return res, nil
	}

	// 3. injection — a file with the same basename in another directory. It does not go into the user's executable
	var inj strings.Builder
	inj.WriteString(text)
	inj.WriteString("if false\n")
	for _, r := range roots {
		inj0 := o.inject
		if inj0 == "" {
			inj0 = "BPF::" + ctxClass[r.Kind] + ".new" // the context of each kind
		}
		fmt.Fprintf(&inj, "  %s(%s)\n", r.Name, inj0)
	}
	inj.WriteString("end\n")
	if o.stopTop != nil {
		o.stopTop(z, roots, inj.String())
		return res, nil
	}
	typing, ds, err := sp.Analyze(filepath.Join(work, "typing"), base, inj.String())
	if err != nil {
		return nil, err
	}
	if _, ok := alignSplice(typing, base, inj.String()); !ok { // the same correction for the typing run
		z.add(Rejected, SB000Spinel, Pos{File: base}, spliceMsg)
		res.Diags = z.diags
		return res, nil
	}
	if len(ds) > 0 {
		z.flushThreadRefs(nil, nil)
		res.Diags = append(z.diags, ds...)
		return res, nil
	}
	if o.mutateTyping != nil {
		o.mutateTyping(typing.Types)
		reindex(typing.Types)
	}
	z.typing = typing
	ta := typing.AST
	tfid := userFileID(ta, base)

	// 4. the defs of the library callees are in bpf.rb, and the user has not redefined them
	z.checkLibDefs()

	// 5. each root
	defs := map[string]*Node{}
	for _, n := range topStatements(ta, tfid) {
		if n.Type == "DefNode" && a.ref(n, "receiver") == nil {
			defs[n.Str["name"]] = n
		}
	}
	z.scanSubprograms(ta, defs, roots) // top-level defs become subprogram candidates; static call graph (recursion is SB035; topological order)
	order := z.callGraph(ta, defs, roots)
	for _, r := range roots {
		d := defs[r.Name]
		if d == nil {
			continue // stopped in scanTop
		}
		p := z.program(ta, d, r)
		if p != nil {
			res.Programs = append(res.Programs, p)
		}
	}
	res.StructOps = z.structOps
	for _, fi := range order { // after the callers (an argument's interval is the union over the call sites)
		if fi.Bad || !fi.Called {
			continue
		}
		if fp := z.function(ta, fi); fp != nil {
			fi.Prog = fp
		}
	}
	for _, fi := range order {
		if fi.Prog != nil {
			res.Funcs = append(res.Funcs, fi.Prog)
		}
	}
	sort.Slice(res.Funcs, func(i, j int) bool { return z.funcs[res.Funcs[i].Name].Decl < z.funcs[res.Funcs[j].Name].Decl }) // declaration order
	z.resolveSubprograms(order, res.Programs)

	// 6. the injection does not change any other record
	z.compareInjection(roots)

	// 7. Membership and edges
	res.Membership, res.Edges = z.membership(ta, tfid, roots, defs)
	for name, m := range res.Membership {
		if len(m) == 2 {
			dn := defs[name]
			z.diags = append(z.diags, Diag{Verdict: Rejected, Code: SB003CrossDomainUse, Pos: z.pos(ta, dn), Path: []string{"user", name},
				Msg: fmt.Sprintf("function `%s` is reached from both the user-space side and the eBPF side ({User, BPF}) — the eBPF side's functions must not be called from Ruby", name)})
		}
	}
	z.checkUserSideAPI(ta, tfid, roots, defs)
	z.flushThreadRefs(res.Membership, defs)

	// A map that is only declared and that the eBPF side does not use does not go into the ELF (ebpf-compile leaves out unused maps; when
	// such a map was put in the schema, the build-time check of map symbols stopped on the mismatch).
	// Leave it out of the schema and maps.json and report it with a Conditional SB013 (generation does not stop — reading it from user
	// space stops at load or with map_get's MapMismatch)
	res.Maps = z.mapOrder
	if len(res.Programs) > 0 {
		used := map[*MapDecl]bool{}
		for _, p := range withFuncs(res) { // the maps the subprograms use, too
			for _, m := range p.Maps {
				used[m] = true
			}
		}
		res.Maps = nil
		for _, m := range z.mapOrder {
			if used[m] {
				res.Maps = append(res.Maps, m)
				continue
			}
			z.add(Conditional, SB013MapDeclShape, m.Pos, "map %s is declared but no eBPF program uses it — it is left out of the ELF, the schema and maps.json (user space cannot read it)", m.Name)
		}
	}
	// an unused global does not go into the ELF either (the same as maps)
	res.Globals = usedGlobalsOf(z.globalOrder, withFuncs(res))
	if len(res.Programs) > 0 {
		usedG := map[*GlobalDecl]bool{}
		for _, g := range res.Globals {
			usedG[g] = true
		}
		for _, g := range z.globalOrder {
			if !usedG[g] {
				z.add(Conditional, SB013MapDeclShape, g.Pos, "global %s is declared but no eBPF program reads or adds it — it is left out of the ELF, the schema and maps.json", g.Name)
			}
		}
	}
	for _, p := range res.Programs { // if there is a tp_btf program (or an fentry with args:), all declared kernel structs (declaration order — schema kernel_types)
		if usesKernelTypes(p) || p.Kind == "netfilter" { // netfilter's state / skb are CO-RE kernel structs too
			res.KernelTypes = z.ktOrder
			break
		}
	}
	usedRing := map[*RingDecl]bool{}
	for _, p := range withFuncs(res) {
		for _, r := range p.Rings {
			usedRing[r] = true
		}
	}
	for _, r := range z.ringOrder {
		if usedRing[r] {
			res.Rings = append(res.Rings, r)
		} else if len(res.Programs) > 0 {
			z.add(Conditional, SB013MapDeclShape, r.Pos, "ring buffer %s is declared but no eBPF program outputs to it — it is left out of the ELF, the schema and maps.json", r.Name)
		}
	}
	res.Diags = oneReasonEach(z.diags)
	if res.Diags.Blocking() {
		res.Programs = nil
	}
	return res, nil
}

// rootDecl is a `BPF.xdp :name` declaration.
type rootDecl struct {
	Name string
	Kind string
	Pos  Pos
	// tracing: the attach target, fexit's nargs and return type, kprobe's params (n is the 1-based register number — the same as n in
	// the schema)
	Target string
	Nargs  int
	Ret    string
	Params []KParam
	// uprobe: the SHA-256 of the target binary and the path read at build time (not put in the outputs)
	BinarySHA, BinaryPath string
	SysTarget             string    // a target given as a canonical absolute path (empty for a relative one)
	TArgs                 []TpArg   // tp_btf
	TFields               []TpField // tracepoint
	SOType, SOMember      string    // struct_ops: the kernel type and the member this callback fills
}

// KParam is an argument of a kprobe declaration (the register number and the type Symbol — :u8 … :i64).
type KParam struct {
	N    int
	Type string
}

// rootKinds maps the method name of a top-level declaration to the program kind.
var rootKindOf = map[string]bool{"xdp": true, "fentry": true, "fexit": true, "kprobe": true, "tcx": true, "uprobe": true, "tp_btf": true, "kretprobe": true, "uretprobe": true, "raw_tp": true, "socket_filter": true, "cgroup_skb": true, "tracepoint": true, "ksyscall": true, "netfilter": true, "flow_dissector": true, "sk_lookup": true, "fmod_ret": true}

// ctxClass maps a kind to the context class of the root's argument (under BPF:: in bpf.rb).
var ctxClass = map[string]string{"xdp": "XdpMd", "fentry": "FentryCtx", "fexit": "FexitCtx", "kprobe": "KprobeCtx", "kretprobe": "KretprobeCtx", "uretprobe": "UretprobeCtx", "sched_cls": "SkBuff", "uprobe": "UprobeCtx", "tp_btf": "TpBtfCtx", "raw_tp": "RawTpCtx", "socket_filter": "SocketFilterCtx", "cgroup_skb": "CgroupSkb", "tracepoint": "TracepointCtx", "ksyscall": "KsyscallCtx", "netfilter": "NfCtx", "flow_dissector": "FlowCtx", "sk_lookup": "SkLookupCtx", "fmod_ret": "FmodRetCtx", "struct_ops": "StructOpsCtx"}

func (z *analyzer) scanTop(a *AST, fid int) []rootDecl {
	var roots []rootDecl
	seen := map[string]bool{}
	defs := map[string]*Node{}
	// first pass: Struct constants and BPF.record declarations (before the map declarations — independent of declaration order)
	structs := map[string]*structInfo{}
	for _, n := range topStatements(a, fid) {
		if n.Type == "ConstantWriteNode" {
			if si, ok := z.structOf(a, n); ok {
				structs[n.Str["name"]] = si
			}
		}
	}
	for _, n := range topStatements(a, fid) {
		if n.Type == "CallNode" && n.Str["name"] == "record" && constName(a, a.ref(n, "receiver")) == "BPF" {
			z.recordDecl(a, n, structs)
		}
	}
	// kernel struct declarations and sample handles (independent of declaration order — before tp_btf's args)
	ptrs := map[*KernelField]*Node{}
	for _, n := range topStatements(a, fid) {
		if n.Type == "CallNode" && n.Str["name"] == "kernel_type" && constName(a, a.ref(n, "receiver")) == "BPF" {
			z.kernelTypeDecl(a, n, structs, ptrs)
		}
	}
	z.kernelTypesResolve(a, ptrs)
	for _, n := range topStatements(a, fid) {
		if v := a.ref(n, "value"); n.Type == "ConstantWriteNode" && v != nil && v.Type == "CallNode" && v.Str["name"] == "new" && constName(a, a.ref(v, "receiver")) == "BPF::KernelType" {
			z.kernelHandleDecl(a, n)
		}
	}
	for _, n := range topStatements(a, fid) {
		switch n.Type {
		case "DefNode":
			if a.ref(n, "receiver") == nil {
				defs[n.Str["name"]] = n
			}
		case "CallNode":
			switch {
			case n.Str["name"] == "require" && a.ref(n, "receiver") == nil:
				as := args(a, n)
				if len(as) != 1 || as[0].Type != "StringNode" || (as[0].Str["content"] != "bpf" && as[0].Str["content"] != "spinelbpf") {
					z.add(Rejected, SB001UnsupportedConstruct, z.pos(a, n), "only `require \"bpf\"` and `require \"spinelbpf\"` are accepted (the program is one file)")
				}
			case n.Str["name"] == "require_relative" || n.Str["name"] == "load":
				z.add(Rejected, SB001UnsupportedConstruct, z.pos(a, n), "`%s` is not accepted (the program is one file plus `require \"bpf\"`)", n.Str["name"])
			case n.Str["name"] == "struct_ops" && constName(a, a.ref(n, "receiver")) == "BPF":
				d, rs, ok := z.structOpsDecl(a, n)
				if !ok {
					continue
				}
				z.structOps = append(z.structOps, d)
				for _, r := range rs {
					if seen[r.Name] {
						z.add(Rejected, SB008ProgramShape, z.pos(a, n), "`BPF.struct_ops :%s` uses the callback :%s twice (or it is declared as another root too)", d.Const, r.Name)
						continue
					}
					seen[r.Name] = true
					roots = append(roots, r)
				}
			case rootKindOf[n.Str["name"]] && constName(a, a.ref(n, "receiver")) == "BPF":
				r, ok := z.rootCall(a, n)
				if !ok {
					continue
				}
				if seen[r.Name] {
					z.add(Rejected, SB008ProgramShape, z.pos(a, n), "`BPF.%s :%s` is declared twice", declName(r.Kind), r.Name)
					continue
				}
				seen[r.Name] = true
				roots = append(roots, r)
			}
		case "ConstantWriteNode":
			if z.globalDecl(a, n) { // a global variable
				continue
			}
			if v := a.ref(n, "value"); v != nil && v.Type == "CallNode" && v.Str["name"] == "new" && (constName(a, a.ref(v, "receiver")) == "BPF::RecordMap" || constName(a, a.ref(v, "receiver")) == "BPF::PerCpuRecordMap") {
				z.recordMapDecl(a, n)
			} else if v != nil && v.Type == "CallNode" && v.Str["name"] == "new" && constName(a, a.ref(v, "receiver")) == "BPF::RingBuf" {
				z.ringDecl(a, n)
			} else if hc, ok := hashClasses[constName(a, a.ref(v, "receiver"))]; ok && v.Type == "CallNode" && v.Str["name"] == "new" {
				z.hashMapDecl(a, n, hc)
			} else {
				z.mapDecl(a, n)
			}
		}
	}
	// reject BPF.xdp / fentry / fexit / kprobe inside an expression (not a top-level statement)
	for _, n := range topStatements(a, fid) {
		if n.Type == "CallNode" && rootKindOf[n.Str["name"]] && constName(a, a.ref(n, "receiver")) == "BPF" {
			continue
		}
		walk(a, n, func(c *Node) bool {
			if c != n && c.Type == "CallNode" && rootKindOf[c.Str["name"]] && constName(a, a.ref(c, "receiver")) == "BPF" {
				z.add(Rejected, SB008ProgramShape, z.pos(a, c), "`BPF.%s` must be a top-level statement", c.Str["name"])
			}
			return true
		})
	}
	var out []rootDecl
	for _, r := range roots {
		d := defs[r.Name]
		if d == nil {
			z.add(Rejected, SB008ProgramShape, r.Pos, "`BPF.%s :%s` names no top-level `def %s`", declName(r.Kind), r.Name, r.Name)
			continue
		}
		pn := a.ref(d, "parameters")
		ok := pn != nil && len(pn.Arr["requireds"]) == 1 && len(pn.Arr["optionals"]) == 0 && len(pn.Arr["keywords"]) == 0 && len(pn.Arr["posts"]) == 0 &&
			a.ref(pn, "rest") == nil && a.ref(pn, "block") == nil && a.ref(pn, "keyword_rest") == nil
		if ok && a.arr(pn, "requireds")[0].Type != "RequiredParameterNode" {
			ok = false
		}
		if !ok {
			z.add(Rejected, SB008ProgramShape, z.pos(a, d), "the eBPF program `%s` must take exactly one required parameter (the context) — no optional, rest, keyword or block parameters", r.Name)
			continue
		}
		out = append(out, r)
	}
	z.checkGlobalNames(roots) // global variable names
	return out
}

// mapDecl reads a top-level `C = BPF::ArrayMap.new("C", bits, n)`.
func (z *analyzer) mapDecl(a *AST, n *Node) {
	v := a.ref(n, "value")
	if v == nil || v.Type != "CallNode" || v.Str["name"] != "new" || (constName(a, a.ref(v, "receiver")) != "BPF::ArrayMap" && constName(a, a.ref(v, "receiver")) != "BPF::PerCpuArrayMap" && constName(a, a.ref(v, "receiver")) != "BPF::LpmTrieMap" && constName(a, a.ref(v, "receiver")) != "BPF::DevMap" && constName(a, a.ref(v, "receiver")) != "BPF::SockMap") {
		return // a constant that is not a map declaration (a user-side one)
	}
	kind, class := "", ""
	if constName(a, a.ref(v, "receiver")) == "BPF::PerCpuArrayMap" {
		kind, class = "percpu_array", "PerCpuArrayMap" // per-CPU array
	} else if constName(a, a.ref(v, "receiver")) == "BPF::LpmTrieMap" {
		kind, class = "lpm_trie", "LpmTrieMap" // longest-prefix-match trie
	} else if constName(a, a.ref(v, "receiver")) == "BPF::DevMap" {
		kind, class = "devmap", "DevMap" // the target of XDP redirect_map (the value is an ifindex, u32 — the user side puts it)
	} else if constName(a, a.ref(v, "receiver")) == "BPF::SockMap" {
		kind, class = "sockmap", "SockMap" // the source of sk_lookup's sk.assign (the value is a socket — the user side puts its fd, u64)
	}
	shown := "ArrayMap" // the class named in error messages (the existing array messages do not change)
	if kind == "lpm_trie" || kind == "devmap" || kind == "sockmap" {
		shown = class
	}
	c := n.Str["name"]
	p := z.pos(a, n)
	z.badMaps[c] = true
	if _, dup := z.maps[c]; dup {
		z.add(Rejected, SB013MapDeclShape, p, "constant %s is assigned twice", c)
		return
	}
	as := args(a, v)
	if len(as) == 3 && as[1].Type == "IntegerNode" {
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[1]), "the value type is a Symbol — write `:u32`, `:u64`, `:i32` or `:i64` (e.g. `BPF::%s.new(\"%s\", %s, n)`)", shown, c, map[bool]string{false: ":u64", true: ":u32"}[kind == "lpm_trie"])
		return
	}
	if len(as) != 3 || as[0].Type != "StringNode" || as[1].Type != "SymbolNode" || as[2].Type != "IntegerNode" {
		z.add(Rejected, SB013MapDeclShape, p, "a map is declared as `%s = BPF::%s.new(\"%s\", %s, max_entries)` with literal arguments", c, shown, c, valueTypesText(kind))
		return
	}
	name := as[0].Str["content"]
	if name != c {
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[0]), "the map name %q differs from its constant %s — both sides look the map up by this name, so they must be the same", name, c)
		return
	}
	for _, m := range z.mapOrder {
		if m.Name == name {
			z.add(Rejected, SB013MapDeclShape, p, "two map declarations use the name %q", name)
			return
		}
	}
	vt := map[string][2]int{"u32": {32, 0}, "u64": {64, 0}, "i32": {32, 1}, "i64": {64, 1}}[as[1].Str["value"]]
	if kind == "sockmap" && as[1].Str["value"] != "u64" { // a sockmap's value is u64 (bpf-mlir's !ebpf.map<"sockmap", i32, i64>)
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[1]), "the value type of a sockmap is :u64 (a socket — user space puts its fd), got :%s", as[1].Str["value"])
		return
	}
	if kind == "devmap" && as[1].Str["value"] != "u32" { // a devmap's value is u32 (an ifindex)
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[1]), "the value type of a devmap is :u32 (an ifindex), got :%s", as[1].Str["value"])
		return
	}
	if kind == "lpm_trie" && vt[0] == 64 {
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[1]), "the value type of an lpm_trie map is :u32 or :i32, got :%s — 64-bit values are not accepted yet", as[1].Str["value"])
		return
	}
	if vt[0] == 0 {
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[1]), "the value type must be %s, got :%s", valueTypesWords(kind), as[1].Str["value"])
		return
	}
	entries, ok2 := z.literal(a, as[2])
	if !ok2 {
		return
	}
	if entries.Sign() <= 0 || !entries.IsUint64() || entries.Uint64() > 1<<32-1 {
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[2]), "max_entries must be a positive integer below 2^32, got %s", entries)
		return
	}
	if reservedPrefix.MatchString(name) {
		z.add(Rejected, SB007ReservedName, p, "map name %q uses the reserved prefix spinelbpf_", name)
		return
	}
	delete(z.badMaps, c)
	m := &MapDecl{Const: c, Name: name, ValueBits: vt[0], Signed: vt[1] == 1, MaxEntries: entries.Uint64(), Pos: p, Kind: kind, Class: class}
	if kind == "lpm_trie" {
		m.KeyRecord = lpmKey4 // the library owns the key record
	}
	z.maps[c] = m
	z.mapOrder = append(z.mapOrder, m)
}

// literal returns the value of an IntegerNode. It reads the source text rather than Spinel's AST value (so a literal over 64 bits is
// not missed even if Spinel rounds it).
// If the source text and the AST value differ, SB014.
func (z *analyzer) literal(a *AST, n *Node) (*big.Int, bool) {
	src := z.slice(n)
	v, ok := parseRubyInt(src)
	if !ok {
		z.add(Rejected, SB001UnsupportedConstruct, z.pos(a, n), "cannot read the integer literal %q", src)
		return nil, false
	}
	astv, ok2 := new(big.Int).SetString(n.IntText["value"], 10)
	if !ok2 || astv.Cmp(v) != 0 {
		z.add(Rejected, SB014SemanticGap, z.pos(a, n), "integer literal %s is not an Integer Spinel can hold (Spinel reads it as %q) — literals must be within [-2^63+1, 2^63-1]", src, n.IntText["value"])
		return nil, false
	}
	return v, true
}

// slice returns the source text of a node (single-line nodes only).
func (z *analyzer) slice(n *Node) string {
	if n.Line != n.EndLine || n.Line < 1 || n.Line > len(z.lines) {
		return ""
	}
	l := z.lines[n.Line-1]
	if n.Col < 0 || n.EndCol > len(l) || n.Col > n.EndCol {
		return ""
	}
	return l[n.Col:n.EndCol]
}

// parseRubyInt reads a Ruby integer literal (sign, _, and the 0x / 0b / 0o / 0d / 0 prefixes).
func parseRubyInt(s string) (*big.Int, bool) {
	s = strings.ReplaceAll(s, "_", "")
	neg := false
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	base := 10
	switch {
	case strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"):
		base, s = 16, s[2:]
	case strings.HasPrefix(s, "0b") || strings.HasPrefix(s, "0B"):
		base, s = 2, s[2:]
	case strings.HasPrefix(s, "0o") || strings.HasPrefix(s, "0O"):
		base, s = 8, s[2:]
	case strings.HasPrefix(s, "0d") || strings.HasPrefix(s, "0D"):
		base, s = 10, s[2:]
	case len(s) > 1 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return nil, false
	}
	v, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, false
	}
	if neg {
		v.Neg(v)
	}
	return v, true
}

// scanProgramWide checks the whole program (the user's file) for forbidden forms (shadowing of library names, dynamic features, and
// reserved prefixes).
func (z *analyzer) scanProgramWide(a *AST, fid int) {
	walk(a, a.node(a.Root), func(n *Node) bool {
		if n.FileID != fid {
			return true
		}
		switch n.Type {
		case "ClassNode", "ModuleNode":
			name := constName(a, a.ref(n, "constant_path"))
			short := name[strings.LastIndex(name, ":")+1:]
			switch {
			case libNames[short] || strings.HasPrefix(name, "BPF::"):
				z.add(Rejected, SB011ShadowedName, z.pos(a, n), "`%s` is defined by ruby/lib/bpf.rb — the program must not define or reopen it", name)
			case builtinReopen[short]:
				z.add(Unknown, SB016DynamicProgram, z.pos(a, n), "the program reopens builtin `%s` — operators and calls may no longer mean what the eBPF side assumes", name)
			}
		case "SingletonClassNode":
			z.add(Unknown, SB016DynamicProgram, z.pos(a, n), "`class << …` is not accepted (call targets must be static)")
		case "DefNode":
			name := n.Str["name"]
			if dynamicDefs[name] {
				z.add(Unknown, SB016DynamicProgram, z.pos(a, n), "the program defines `%s` — calls may no longer resolve statically", name)
			}
			if reservedPrefix.MatchString(name) {
				z.add(Rejected, SB007ReservedName, z.pos(a, n), "`%s` uses the reserved prefix spinelbpf_", name)
			}
			if strings.HasPrefix(name, "__ebpf_") && !mutation("no-ebpf-prefix") { // reserved for bpf-mlir's outlined functions (the mutation control shows bpf-mlir's collision message — test builds only)
				z.add(Rejected, SB007ReservedName, z.pos(a, n), "`%s` uses the reserved prefix __ebpf_ — a program or an eBPF-side function becomes a symbol next to bpf-mlir's internal functions (`__ebpf_present_*` — the outlined ring buffer present, `__ebpf_loop_cb_*` …); rename it", name)
			}
		case "CallNode":
			if dynamicCalls[n.Str["name"]] {
				z.add(Unknown, SB016DynamicProgram, z.pos(a, n), "the program calls `%s` — calls may no longer resolve statically", n.Str["name"])
			}
		case "ConstantWriteNode":
			if reservedPrefix.MatchString(strings.ToLower(n.Str["name"])) {
				z.add(Rejected, SB007ReservedName, z.pos(a, n), "`%s` uses the reserved prefix spinelbpf_", n.Str["name"])
			}
		}
		return true
	})
}

// checkLibDefs checks that each libCallees def appears once in the typing types and that all of them are in bpf.rb.
func (z *analyzer) checkLibDefs() {
	found := map[string][]TypeRec{}
	for _, r := range z.typing.Types.Types {
		if r.Kind != "DefNode" || r.Singleton {
			continue
		}
		k := r.Owner + "#" + r.Name
		if libCallees[k] {
			found[k] = append(found[k], r)
		}
	}
	for k := range libCallees {
		rs := found[k]
		if len(rs) == 0 {
			continue // an unused (unreached) def may not appear in the types — the callee check at the use stops it
		}
		for _, r := range rs {
			if r.File != z.lib {
				z.add(Rejected, SB011ShadowedName, Pos{File: filepath.Base(r.File), Line: r.Line, Col: r.Col + 1},
					"`%s` is defined outside ruby/lib/bpf.rb — the eBPF side's API must be the library's", k)
			}
		}
	}
}

// compareInjection checks that, with and without the injection, the user's file's records match except for the root's arguments and
// the signature of the root's def.
func (z *analyzer) compareInjection(roots []rootDecl) {
	rootSet := map[string]bool{}
	for _, r := range roots {
		rootSet[r.Name] = true
	}
	d := CompareTypes(z.plain.Types, z.typing.Types, z.base, z.userLines, rootSet, z.paramReads(roots))
	z.diags = append(z.diags, d...)
}

// CompareTypes compares the plain and typing types (exported so that tests can call it directly). It looks only at the records of the
// user's file that fit within userLines.
// Allowed differences: the type of the root def's RequiredParameterNode (untyped → XdpMd) and the signature of the root's DefNode.
// dependent holds the spans of nodes that contain a value flowing from the root's argument (through local variables) (paramReads — a
// rule added after the fact once the first run had happened, and later widened to data flow). Their differences are allowed **only when
// the side without the injection has no type (no record, or untyped)** — the injection only adds types and never changes a type that
// is already there.
func CompareTypes(plain, typing *Types, base string, userLines int, roots map[string]bool, dependent []spanKey) Diags {
	collect := func(t *Types) (map[spanKey][]string, map[spanKey]TypeRec) {
		m := map[spanKey][]string{}
		one := map[spanKey]TypeRec{}
		for _, r := range t.Types {
			if r.File != base || r.EndLine > userLines {
				continue
			}
			k := spanKey{r.File, r.Line, r.Col, r.EndLine, r.EndCol, r.Kind}
			m[k] = append(m[k], r.Name+"|"+r.RBS+"|"+r.Signature)
			one[k] = r
		}
		return m, one
	}
	pm, _ := collect(plain)
	tm, tone := collect(typing)
	// the span of the root's def, and the spans of the root's arguments
	allowed := map[spanKey]bool{}
	for k, r := range tone {
		if r.Kind == "DefNode" && roots[r.Name] && r.Owner == "Object" {
			allowed[k] = true
		}
	}
	for k, r := range tone {
		if r.Kind != "RequiredParameterNode" {
			continue
		}
		for dk := range allowed {
			if dk.Kind == "DefNode" && inside(k, dk) {
				allowed[k] = true
			}
		}
	}
	// a difference in a node that contains a value flowing from the root's argument is allowed only when the side without the injection
	// has no type (additive).
	// A rule added after the fact: first kept narrow after review, then widened to data flow for the ctx.check packet window
	additive := map[spanKey]bool{}
	for _, dk := range dependent {
		additive[dk] = true
	}
	var ds Diags
	keys := map[spanKey]bool{}
	for k := range pm {
		keys[k] = true
	}
	for k := range tm {
		keys[k] = true
	}
	var sorted []spanKey
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		return a.Kind < b.Kind
	})
	for _, k := range sorted {
		p, t := strings.Join(pm[k], ";"), strings.Join(tm[k], ";")
		if p == t || allowed[k] {
			continue
		}
		if additive[k] && untypedOnly(pm[k]) {
			continue
		}
		if additive[k] && k.Kind == "DefNode" { // a subprogram def that receives a root value (window, context) — its signature is those argument types (treated like the root's def)
			continue
		}
		ds = append(ds, Diag{Verdict: Rejected, Code: SB010TypingProbe, Pos: Pos{File: base, Line: k.Line, Col: k.Col + 1},
			Msg: fmt.Sprintf("the typing probe changed Spinel's inference of this %s (without: %q, with: %q) — the eBPF side's types must not depend on the injected call", k.Kind, p, t)})
	}
	return ds
}

// untypedOnly reports whether the side without the injection has no record, or only untyped records (with no type).
func untypedOnly(recs []string) bool {
	for _, r := range recs {
		parts := strings.SplitN(r, "|", 3)
		if len(parts) != 3 || parts[1] != "untyped" || parts[2] != "" {
			return false
		}
	}
	return true
}

func inside(k, outer spanKey) bool {
	if k.Line < outer.Line || (k.Line == outer.Line && k.Col < outer.Col) {
		return false
	}
	if k.EndLine > outer.EndLine || (k.EndLine == outer.EndLine && k.EndCol > outer.EndCol) {
		return false
	}
	return true
}

// membership computes Membership {User, BPF} and the edges. The edges are the codegen callees of the typing run (only lines of the
// user's file before the injection).
func (z *analyzer) membership(a *AST, fid int, roots []rootDecl, defs map[string]*Node) (map[string][]string, []Edge) {
	t := z.typing.Types
	callees := func(n *Node) []Edge {
		var out []Edge
		walk(a, n, func(c *Node) bool {
			if c.Type == "DefNode" && c != n {
				return false
			}
			if c.Type != "CallNode" || c.Line > z.userLines {
				return true
			}
			cg, cnt := t.CodegenOf(a, c)
			if cnt != 1 || cg.Callee == "" {
				return true
			}
			if _, ok := defs[cg.Callee]; ok {
				out = append(out, Edge{To: cg.Callee, Pos: z.pos(a, c), Dispatch: cg.Dispatch})
			}
			return true
		})
		return out
	}
	var edges []Edge
	mem := map[string]map[string]bool{}
	var visit func(from, name, dom string)
	visit = func(from, name, dom string) {
		if mem[name] == nil {
			mem[name] = map[string]bool{}
		}
		if mem[name][dom] {
			return
		}
		mem[name][dom] = true
		for _, e := range callees(defs[name]) {
			e.From = name
			edges = append(edges, e)
			visit(name, e.To, dom)
		}
	}
	isRoot := map[string]bool{}
	for _, r := range roots {
		isRoot[r.Name] = true
		visit("", r.Name, "bpf")
	}
	for _, n := range topStatements(a, fid) {
		if n.Type == "DefNode" || n.Line > z.userLines {
			continue
		}
		for _, e := range callees(n) {
			e.From = "<top>"
			edges = append(edges, e)
			visit("<top>", e.To, "user")
		}
	}
	out := map[string][]string{}
	for name, m := range mem {
		var l []string
		if m["user"] {
			l = append(l, "user")
		}
		if m["bpf"] {
			l = append(l, "bpf")
		}
		out[name] = l
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Pos.Line != edges[j].Pos.Line {
			return edges[i].Pos.Line < edges[j].Pos.Line
		}
		return edges[i].Pos.Col < edges[j].Pos.Col
	})
	return out, edges
}

// checkUserSideAPI stops calls to eBPF-side-only APIs on the user-space side (outside the eBPF side's defs) — misuse across the two
// sides.
func (z *analyzer) checkUserSideAPI(a *AST, fid int, roots []rootDecl, defs map[string]*Node) {
	bpf := map[*Node]bool{}
	for _, r := range roots {
		if d := defs[r.Name]; d != nil {
			bpf[d] = true
		}
	}
	for _, fi := range z.funcs { // subprograms reached from a root are on the eBPF side too
		if fi.Path != nil {
			bpf[fi.Def] = true
		}
	}
	for _, n := range topStatements(a, fid) {
		if bpf[n] || n.Line > z.userLines {
			continue
		}
		walk(a, n, func(c *Node) bool {
			if c.Type != "CallNode" {
				return true
			}
			cg, cnt := z.typing.Types.CodegenOf(a, c)
			if cnt == 1 && (libCallees[cg.Callee] || ebpfOnlyHelpers[cg.Callee]) {
				z.add(Rejected, SB003CrossDomainUse, z.pos(a, c), "`%s` is eBPF-side only — user space reads maps through the loaded object (SpinelBPF)", cg.Callee)
			}
			return true
		})
	}
}

// paramReads returns the spans of the nodes in the root's def that contain a value flowing from the root's argument (through local
// variables) (in the typing AST).
func (z *analyzer) paramReads(roots []rootDecl) []spanKey {
	a := z.typing.AST
	fid := userFileID(a, z.base)
	isRoot := map[string]bool{}
	for _, r := range roots {
		isRoot[r.Name] = true
	}
	defs := map[string]*Node{}
	for _, n := range topStatements(a, fid) {
		if n.Type == "DefNode" && a.ref(n, "receiver") == nil {
			defs[n.Str["name"]] = n
		}
	}
	// tainted arguments (def name → argument number): for a root, argument 0 (the context). Also the arguments of a subprogram that
	// receives a value flowing from a root (window, context)
	tp := map[string]map[int]bool{}
	var work []string
	for _, r := range roots {
		if n := defs[r.Name]; n != nil {
			if pn := a.ref(n, "parameters"); pn != nil && len(a.arr(pn, "requireds")) == 1 {
				tp[r.Name] = map[int]bool{0: true}
				work = append(work, r.Name)
			}
		}
	}
	var out []spanKey
	done := map[string]bool{}
	for len(work) > 0 {
		name := work[0]
		work = work[1:]
		n := defs[name]
		pn := a.ref(n, "parameters")
		ps := a.arr(pn, "requireds")
		// closure of the flow: the arguments, and local variables assigned an expression that contains a flowing value (to a fixed point)
		tainted := map[string]bool{}
		for i := range tp[name] {
			if i < len(ps) {
				tainted[ps[i].Str["name"]] = true
			}
		}
		reads := func(x *Node) bool {
			found := false
			walk(a, x, func(y *Node) bool {
				if y.Type == "LocalVariableReadNode" && tainted[y.Str["name"]] {
					found = true
				}
				return !found
			})
			return found
		}
		for changed := true; changed; {
			changed = false
			walk(a, n, func(x *Node) bool {
				if (x.Type == "LocalVariableWriteNode" || x.Type == "LocalVariableOperatorWriteNode") && !tainted[x.Str["name"]] && reads(a.ref(x, "value")) {
					tainted[x.Str["name"]] = true
					changed = true
				}
				if x.Type == "MultiWriteNode" && reads(a.ref(x, "value")) { // the two locals of `v, st = ctx.read(…)` also flow from the root's argument
					for _, t := range a.arr(x, "lefts") {
						if t.Type == "LocalVariableTargetNode" && !tainted[t.Str["name"]] {
							tainted[t.Str["name"]] = true
							changed = true
						}
					}
				}
				return true
			})
		}
		if !isRoot[name] && !done[name] { // subprogram: also the def and the tainted argument nodes (the signature changes)
			out = append(out, keyOf(a, n))
			for i := range tp[name] {
				if i < len(ps) {
					out = append(out, keyOf(a, ps[i]))
				}
			}
		}
		done[name] = true
		walk(a, n, func(x *Node) bool {
			if x != n && reads(x) {
				out = append(out, keyOf(a, x))
			}
			if x.Type == "CallNode" && a.ref(x, "receiver") == nil && defs[x.Str["name"]] != nil && !isRoot[x.Str["name"]] {
				callee := x.Str["name"]
				for i, arg := range args(a, x) {
					if reads(arg) {
						if tp[callee] == nil {
							tp[callee] = map[int]bool{}
						}
						if !tp[callee][i] {
							tp[callee][i] = true
							work = append(work, callee)
						}
					}
				}
			}
			return true
		})
	}
	return out
}

// threadRef is a reference to a constant such as Thread.
type threadRef struct {
	name string
	pos  Pos
	line int
}

// flushThreadRefs turns the collected references to Thread and the like that lie within the lines of a function the eBPF side reaches
// (bpf in its Membership) into SB027.
// References on the user side are allowed (SB012 is retired). With no membership (analysis stopped for another reason before
// reachability) it adds nothing.
func (z *analyzer) flushThreadRefs(membership map[string][]string, defs map[string]*Node) {
	for _, r := range z.threadRefs {
		inBPF := false
		for name, m := range membership {
			d := defs[name]
			if d == nil || r.line < d.Line || r.line > d.EndLine {
				continue
			}
			for _, k := range m {
				if k == "bpf" {
					inBPF = true
				}
			}
		}
		if inBPF {
			z.add(Rejected, SB027ThreadInBPFSide, r.pos, "`%s` inside a function reached from an eBPF program — threads do not exist on the eBPF side", r.name)
		}
	}
	z.threadRefs = nil
}

// rootCall reads a top-level `BPF.<kind> :name[, "target"[, opts]]` (a malformed one is SB008, with a position).
func (z *analyzer) rootCall(a *AST, n *Node) (rootDecl, bool) {
	kind := n.Str["name"]
	as := args(a, n)
	bad := func(format string, x ...any) (rootDecl, bool) {
		z.add(Rejected, SB008ProgramShape, z.pos(a, n), format, x...)
		return rootDecl{}, false
	}
	if kind == "xdp" {
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.xdp` takes exactly one Symbol literal (`BPF.xdp :name`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "xdp", Pos: z.pos(a, n)}, true
	}
	if kind == "flow_dissector" { // `BPF.flow_dissector :name` — no attach clause (user space attaches it to a netns with attach_netns)
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.flow_dissector` takes exactly one Symbol literal (`BPF.flow_dissector :name` — it is attached to a network namespace in user space with `obj.attach_netns`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "flow_dissector", Pos: z.pos(a, n)}, true
	}
	if kind == "sk_lookup" { // `BPF.sk_lookup :name` — no attach clause (user space attaches it to a netns with attach_netns; tests use a test run)
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.sk_lookup` takes exactly one Symbol literal (`BPF.sk_lookup :name`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "sk_lookup", Pos: z.pos(a, n)}, true
	}
	if kind == "netfilter" { // `BPF.netfilter :name` — pf / hook / priority are arguments of the user-side attach (no attach clause in the .mlir)
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.netfilter` takes exactly one Symbol literal (`BPF.netfilter :name` — the hook is chosen in user space with `obj.attach_netfilter(name, pf, hooknum, priority)`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "netfilter", Pos: z.pos(a, n)}, true
	}
	if kind == "cgroup_skb" { // `BPF.cgroup_skb :name, :ingress|:egress` — the direction is the attach (cgroup_inet_ingress / egress)
		if len(as) != 2 || as[0].Type != "SymbolNode" || as[1].Type != "SymbolNode" || (as[1].Str["value"] != "ingress" && as[1].Str["value"] != "egress") {
			return bad("a cgroup_skb program is declared as `BPF.cgroup_skb :name, :ingress` or `BPF.cgroup_skb :name, :egress` (two Symbol literals — the second is the direction)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "cgroup_skb", Pos: z.pos(a, n), Target: as[1].Str["value"]}, true
	}
	if kind == "socket_filter" { // `BPF.socket_filter :name` — no attach direction or target (SO_ATTACH_BPF on one's own socket)
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.socket_filter` takes exactly one Symbol literal (`BPF.socket_filter :name` — it is attached to a socket in user space with `obj.attach_socket`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "socket_filter", Pos: z.pos(a, n)}, true
	}
	if kind == "tcx" { // `BPF.tcx :name, :ingress|:egress` — the kind is bpf-mlir's sched_cls; the direction is the attach (the tcx link's direction)
		if len(as) != 2 || as[0].Type != "SymbolNode" || as[1].Type != "SymbolNode" || (as[1].Str["value"] != "ingress" && as[1].Str["value"] != "egress") {
			return bad("a sched_cls program is declared as `BPF.tcx :name, :ingress` or `BPF.tcx :name, :egress` (two Symbol literals — the second is the tcx direction)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "sched_cls", Pos: z.pos(a, n), Target: as[1].Str["value"]}, true
	}
	if kind == "tracepoint" { // tracepoint with declared event fields
		return z.tracepointDecl(a, n, as, bad)
	}
	if kind == "uprobe" || kind == "uretprobe" { // uretprobe is uprobe's target declaration plus ret:
		return z.uprobeDecl(a, n, as, bad)
	}
	if kind == "tp_btf" {
		return z.tpBtfDecl(a, n, as)
	}
	if kind == "fmod_ret" { // fmod_ret (replaces the return value)
		return z.fmodRetDecl(a, n, as, bad)
	}
	if kind == "fentry" && len(as) == 3 { // fentry's struct arguments (`args:`)
		return z.structArgsDecl(a, n, as, "fentry")
	}
	shape := map[string]string{
		"fentry":    "`BPF.fentry :name, \"kernel_function\"`",
		"fexit":     "`BPF.fexit :name, \"kernel_function\", nargs: N, ret: :i32`",
		"kprobe":    "`BPF.kprobe :name, \"kernel_function\", params: {n => :u64, …}`",
		"kretprobe": "`BPF.kretprobe :name, \"kernel_function\", ret: :i32`",     // kretprobe
		"raw_tp":    "`BPF.raw_tp :name, \"tracepoint\"`",                        // raw_tp
		"ksyscall":  "`BPF.ksyscall :name, \"syscall\", params: {n => :u64, …}`", // ksyscall
	}[kind]
	want := 2
	if kind != "fentry" && kind != "raw_tp" { // raw_tp also takes only the target (no argument types are declared — the kernel does not check them)
		want = 3
	}
	if len(as) < 2 || as[0].Type != "SymbolNode" || as[1].Type != "StringNode" || as[1].Str["content"] == "" {
		return bad("a %s program is declared as %s with a Symbol and a non-empty String literal", kind, shape)
	}
	if len(as) != want || (want == 3 && as[2].Type != "KeywordHashNode") {
		return bad("a %s program is declared as %s", kind, shape)
	}
	r := rootDecl{Name: as[0].Str["value"], Kind: kind, Pos: z.pos(a, n), Target: as[1].Str["content"]}
	if want == 2 {
		return r, true
	}
	opts := map[string]*Node{}
	for _, e := range a.arr(as[2], "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || v == nil || k.Type != "SymbolNode" {
			return bad("the options of %s are `key: literal` pairs", shape)
		}
		opts[k.Str["value"]] = v
	}
	intType := func(v *Node) (string, bool) {
		if v == nil || v.Type != "SymbolNode" {
			return "", false
		}
		_, ok := recordTypes[v.Str["value"]]
		return v.Str["value"], ok
	}
	switch kind {
	case "kretprobe": // the return type (the kernel does not check it — the raw bits of rax are cut to the declared width)
		rv := opts["ret"]
		if len(opts) != 1 || rv == nil {
			return bad("%s needs exactly `ret:` (a Symbol :i8 … :u64 — the kernel does not check it; the value is the return register cut to this width)", shape)
		}
		t, ok := intType(rv)
		if !ok {
			return bad("`ret:` of %s is one of :i8 … :i64 / :u8 … :u64", shape)
		}
		r.Ret = t
	case "fexit":
		nv, rv := opts["nargs"], opts["ret"]
		if len(opts) != 2 || nv == nil || rv == nil || nv.Type != "IntegerNode" {
			return bad("%s needs exactly `nargs:` (an Integer literal 0..12) and `ret:` (a Symbol :i8 … :u64)", shape)
		}
		nb, ok := z.literal(a, nv)
		if !ok || !nb.IsInt64() || nb.Int64() < 0 || nb.Int64() > 12 {
			return bad("`nargs:` of %s is the target function's argument count, 0..12", shape)
		}
		t, ok := intType(rv)
		if !ok {
			return bad("`ret:` of %s is one of :i8 … :i64 / :u8 … :u64", shape)
		}
		r.Nargs, r.Ret = int(nb.Int64()), t
	case "kprobe", "ksyscall": // ksyscall's params are the syscall arguments (n is 1..6 — the 4th is r10, which bpf-mlir reads)
		if kind == "ksyscall" && (!tpIdent.MatchString(r.Target) || strings.HasPrefix(r.Target, "sys_") || strings.HasPrefix(r.Target, "__")) {
			return bad("the target of %s is a syscall name — a C identifier without the `sys_` / `__` prefix (the wrapper `__x64_sys_<name>` is derived), got %q", shape, r.Target)
		}
		pv := opts["params"]
		if len(opts) != 1 || pv == nil || pv.Type != "HashNode" || len(a.arr(pv, "elements")) == 0 {
			return bad("%s needs `params:` with a non-empty Hash literal of register number (1..6) => type", shape)
		}
		seenN := map[int]bool{}
		for _, e := range a.arr(pv, "elements") {
			k, v := a.ref(e, "key"), a.ref(e, "value")
			if e.Type != "AssocNode" || k == nil || k.Type != "IntegerNode" {
				return bad("each %s parameter is `n => :type` with n an Integer literal 1..6", kind)
			}
			nb, ok := z.literal(a, k)
			if !ok || !nb.IsInt64() || nb.Int64() < 1 || nb.Int64() > 6 || seenN[int(nb.Int64())] {
				return bad("a %s parameter number is 1..6 (the x86_64 argument registers, 1-origin like the schema's n) and appears once", kind)
			}
			t, ok := intType(v)
			if !ok && kind == "kprobe" && v != nil && v.Type == "SymbolNode" && v.Str["value"] == "ptr" { // a pointer argument — its target is read with `v, st = ctx.read(n, off, :type)`
				t, ok = "ptr", true
			}
			if !ok && kind == "ksyscall" && v != nil && v.Type == "SymbolNode" && (v.Str["value"] == "user_str" || v.Str["value"] == "user_str_array") { // a const char * syscall argument (passed to output_str with ctx.str_arg(n)), or a const char *const * (argv — passed to output_argv with ctx.argv_arg(n))
				t, ok = v.Str["value"], true
			}
			if !ok {
				return bad("a %s parameter type is one of :i8 … :i64 / :u8 … :u64%s%s", kind, map[bool]string{true: " or :ptr (a pointer read with `v, st = ctx.read(n, offset, :type)`)", false: ""}[kind == "kprobe"], map[bool]string{true: " or :user_str (a `const char *` — read with ctx.str_arg(n))", false: ""}[kind == "ksyscall"])
			}
			seenN[int(nb.Int64())] = true
			r.Params = append(r.Params, KParam{N: int(nb.Int64()), Type: t})
		}
	}
	return r, true
}

// spliceMsg is the message for when the line shift caused by splicing in the builtins could not be corrected.
const spliceMsg = "Spinel spliced its builtins (enumerable.rb / enumerator.rb — the code names a method that Enumerable defines, such as count or map) and shifted this file's line numbers, and the shift could not be measured from the named nodes (docs/upstream_suspects.md S11) — rename the method or avoid the call"
