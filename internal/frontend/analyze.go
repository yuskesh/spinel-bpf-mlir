package frontend

import (
	"fmt"
	"math/big"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var ebpfOnlyHelpers = map[string]bool{
	"BPF.pid_tgid": true, "BPF.ktime_ns": true,
	"BPF.fmod_return": true,
	"XdpMd#check":     true, "SkBuff#check": true, "Window#u8": true, "Window#be16": true, "Window#be32": true, "Window#le16": true, "Window#le32": true,
}

var libCallees = map[string]bool{
	"ArrayMap#atomic_add":         true,
	"ArrayMap#lookup":             true,
	"ArrayMap#update":             true,
	"MapRef#load":                 true,
	"RecordMap#lookup":            true,
	"RecordMap#update":            true,
	"RecordRef#load":              true,
	"RecordRef#atomic_add":        true,
	"RingBuf#output":              true,
	"MapRef#atomic_add":           true,
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
	"LpmTrieMap#lookup":           true,
	"FexitCtx#ret":                true,
	"KretprobeCtx#ret":            true,
	"UretprobeCtx#ret":            true,
	"SocketFilterCtx#len":         true,
	"CgroupSkb#len":               true, "CgroupSkb#check": true,
	"NfCtx#state": true, "NfCtx#skb": true,
	"FmodRetCtx#arg": true,
	"FlowCtx#check":  true, "FlowCtx#key": true, "FlowCtx#set_key": true,
	"XdpMd#ingress_ifindex": true, "SkBuff#len": true, "SkBuff#mark": true, "SkBuff#mark=": true,
	"XdpMd#adjust_head": true, "XdpMd#adjust_tail": true,
	"Config#value": true, "OptionalConfig#value": true, "Counter#value": true, "Counter#add": true,
	"KprobeCtx#arg":   true,
	"FentryCtx#arg":   true,
	"DevMap#redirect": true,
	"SockMap#assign":  true, "SkLookupCtx#local_port": true,
	"KprobeCtx#read":       true,
	"RawTpCtx#arg":         true,
	"KsyscallCtx#arg":      true,
	"KsyscallCtx#str_arg":  true,
	"KsyscallCtx#argv_arg": true, "TracepointCtx#argv_field": true, "RingBuf#output_argv": true,
	"TracepointCtx#copy":      true,
	"KPtr#addr":               true,
	"TracepointCtx#field":     true,
	"TracepointCtx#str_field": true,
	"UprobeCtx#arg":           true, "UprobeCtx#str_arg": true, "RingBuf#output_str": true, "OutputStr#status": true, "RingBuf#output_str_or_discard": true, "OutputStr#sent": true,
	"UprobeCtx#buf_arg": true, "RingBuf#output_buf": true,
	"RingBuf#output_comm": true,
	"TpBtfCtx#kptr":       true, "TpBtfCtx#kptr_or_null": true, "FentryCtx#kptr_or_null": true, "TpBtfCtx#arg": true, "KPtr#load": true, "KPtr#ptr": true, "KPtr#copy": true, "KPtr#str": true,
}

var libNames = map[string]bool{"BPF": true, "ArrayMap": true, "MapRef": true, "XdpMd": true, "Window": true, "RecordMap": true, "RecordRef": true, "RingBuf": true, "HashMap": true, "LruHashMap": true, "RecordHashMap": true, "LruRecordHashMap": true, "PerCpuArrayMap": true, "PerCpuRecordMap": true, "PerCpuHashMap": true, "PerCpuRecordHashMap": true, "LpmTrieMap": true, "DevMap": true, "SockMap": true}

var builtinReopen = map[string]bool{
	"Integer": true, "Object": true, "Kernel": true, "BasicObject": true, "Comparable": true, "Module": true, "Class": true,
	"NilClass": true, "TrueClass": true, "FalseClass": true, "Symbol": true, "String": true, "Array": true, "Hash": true, "Numeric": true,
}

var dynamicCalls = map[string]bool{
	"send": true, "public_send": true, "__send__": true, "define_method": true, "instance_eval": true, "class_eval": true,
	"module_eval": true, "instance_exec": true, "class_exec": true, "eval": true, "method": true, "instance_variable_get": true,
	"instance_variable_set": true, "const_get": true, "const_set": true, "prepend": true, "include": true, "extend": true,
	"refine": true, "using": true, "alias_method": true, "remove_method": true, "undef_method": true,
}

var threadConsts = map[string]bool{"Thread": true, "Mutex": true, "Queue": true, "SizedQueue": true, "ConditionVariable": true, "Monitor": true, "Ractor": true}

var dynamicDefs = map[string]bool{"method_missing": true, "respond_to_missing?": true}

var operators = map[string]bool{
	"+": true, "-": true, "*": true, "/": true, "%": true, "**": true, "==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
	"<=>": true, "&": true, "|": true, "^": true, "<<": true, ">>": true, "!": true, "~": true, "-@": true, "+@": true, "===": true, "[]": true, "[]=": true,
}

var xdpVerdicts = map[string]string{"XDP_ABORTED": "aborted", "XDP_DROP": "drop", "XDP_PASS": "pass", "XDP_TX": "tx"}

var tcVerdicts = map[string]string{"TC_PASS": "pass", "TC_DROP": "drop"}

var sfVerdicts = map[string]string{"SF_KEEP": "keep", "SF_DROP": "drop"}

var cgVerdicts = map[string]string{"CG_ALLOW": "allow", "CG_DENY": "deny"}

var nfVerdicts = map[string]string{"NF_ACCEPT": "accept", "NF_DROP": "drop"}

var flowVerdicts = map[string]string{"FLOW_OK": "ok", "FLOW_DROP": "drop", "FLOW_CONTINUE": "flow_dissector_continue"}

var skVerdicts = map[string]string{"SK_PASS": "pass", "SK_DROP": "drop"}

var fmodVerdicts = map[string]string{"FMOD_CALL": "done"}

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

func hasPacket(kind string) bool {
	return kind == "xdp" || kind == "sched_cls" || kind == "cgroup_skb" || kind == "flow_dissector"
}

func isTracing(kind string) bool { return verdictsOf(kind) == nil }

func attachesKernelFunc(kind string) bool { return isTracing(kind) || kind == "fmod_ret" }

func declName(kind string) string {
	if kind == "sched_cls" {
		return "tcx"
	}
	return kind
}

var relRequire = regexp.MustCompile(`^\s*(require_relative|load)\b`)

var reservedPrefix = regexp.MustCompile(`^_?spinelbpf_`)

type MapDecl struct {
	Const      string
	Name       string
	ValueBits  int
	Signed     bool
	MaxEntries uint64
	Record     *RecordDecl
	Kind       string
	Class      string
	KeyBits    int
	KeySigned  bool
	KeyRecord  *RecordDecl
	Pos        Pos
}

func (m *MapDecl) MapKind() string {
	if m.Kind == "" {
		return "array"
	}
	return m.Kind
}

func (m *MapDecl) IsHash() bool {
	return m.Kind == "hash" || m.Kind == "lru_hash" || m.Kind == "percpu_hash"
}

func (m *MapDecl) IsArray() bool { return m.Kind == "" || m.Kind == "percpu_array" }

func (m *MapDecl) PerCPU() bool { return strings.HasPrefix(m.Kind, "percpu_") }

func (m *MapDecl) ClassName() string {
	switch {
	case m.Class != "":
		return m.Class
	case m.Record != nil:
		return "RecordMap"
	}
	return "ArrayMap"
}

func (m *MapDecl) KeyTypeName() string {
	switch {
	case m.KeyRecord != nil:
		return "record:" + m.KeyRecord.Const
	case m.IsArray(), m.IsDevmap(), m.Kind == "sockmap":
		return "u32"
	case m.KeySigned:
		return fmt.Sprintf("i%d", m.KeyBits)
	}
	return fmt.Sprintf("u%d", m.KeyBits)
}

func (m *MapDecl) TypeName() string {
	if m.Record != nil {
		return "record:" + m.Record.Const
	}
	if m.Signed {
		return fmt.Sprintf("i%d", m.ValueBits)
	}
	return fmt.Sprintf("u%d", m.ValueBits)
}

type Program struct {
	Name         string
	Kind         string
	Target       string
	Nargs        int
	Ret          string
	Params       []KParam
	TArgs        []TpArg
	TFields      []TpField
	FParams      []string
	FRet         *Expr
	FBorrow      int
	FBorrowMap   *MapDecl
	FWin         int
	FWinLen      int64
	FCtx         int
	FCtxKind     string
	BinarySHA    string
	BinaryPath   string
	SysTarget    string
	Globals      []*GlobalDecl
	Pos          Pos
	DeclPos      Pos
	Body         []Stmt
	Verdict      string
	VerdictConst string
	RedirMap     *MapDecl
	RedirKey     *Expr
	GuardVerdict string
	FmodVal      *Expr
	FmodGuard    *big.Int
	VerdictPos   Pos
	EndLine      int
	Maps         []*MapDecl
	Rings        []*RingDecl
}

type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Pos      Pos    `json:"pos"`
	Dispatch string `json:"dispatch"`
}

type Result struct {
	Source      string
	Programs    []*Program
	Maps        []*MapDecl
	Rings       []*RingDecl
	Globals     []*GlobalDecl
	KernelTypes []*KernelTypeDecl
	Funcs       []*Program
	Membership  map[string][]string
	Edges       []Edge
	Diags       Diags
}

type analyzer struct {
	base        string
	text        string
	lines       []string
	userLines   int
	threadRefs  []threadRef
	lib         string
	srcDir      string
	kts         map[string]*KernelTypeDecl
	ktOrder     []*KernelTypeDecl
	ktHandles   map[string]*KernelTypeDecl
	funcs       map[string]*funcInfo
	flowsOf     map[string]*fnFlows
	siteByNode  map[int]*callSite
	anyBadFunc  bool
	plain       *Analysis
	typing      *Analysis
	diags       Diags
	maps        map[string]*MapDecl
	mapOrder    []*MapDecl
	records     map[string]*RecordDecl
	rings       map[string]*RingDecl
	ringOrder   []*RingDecl
	badRings    map[string]bool
	badMaps     map[string]bool
	globals     map[string]*GlobalDecl
	globalOrder []*GlobalDecl
	badGlobals  map[string]bool
	rootKinds   []string
	badHash     map[string]bool
	badRecs     map[string]bool
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

func userFileID(a *AST, base string) int {
	for id, p := range a.Files {
		if p == base {
			return id
		}
	}
	return -1
}

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

func Analyze(sp Spinel, work, sourcePath, text string) (*Result, error) {
	return analyze(sp, work, sourcePath, text, analyzeOpts{})
}

type analyzeOpts struct {
	inject       string
	mutateTyping func(*Types)
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

	plain, ds, err := sp.Analyze(filepath.Join(work, "plain"), base, text)
	if err != nil {
		return nil, err
	}
	if len(ds) > 0 {
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
	if _, ok := alignSplice(plain, base, text); !ok {
		z.add(Rejected, SB000Spinel, Pos{File: base}, spliceMsg)
		res.Diags = z.diags
		return res, nil
	}

	threads, err := sp.UsesThreads(filepath.Join(work, "plain"), base)
	if err != nil {
		return nil, err
	}
	if threads {
		walk(a, a.node(a.Root), func(n *Node) bool {
			if n.FileID == fid && (n.Type == "ConstantReadNode" || n.Type == "ConstantPathNode") && threadConsts[n.Str["name"]] {
				z.threadRefs = append(z.threadRefs, threadRef{name: n.Str["name"], pos: z.pos(a, n), line: n.Line})
			}
			return true
		})
	}

	roots := z.scanTop(a, fid)
	for _, r := range roots {
		z.rootKinds = append(z.rootKinds, r.Kind)
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

	var inj strings.Builder
	inj.WriteString(text)
	inj.WriteString("if false\n")
	for _, r := range roots {
		inj0 := o.inject
		if inj0 == "" {
			inj0 = "BPF::" + ctxClass[r.Kind] + ".new"
		}
		fmt.Fprintf(&inj, "  %s(%s)\n", r.Name, inj0)
	}
	inj.WriteString("end\n")
	typing, ds, err := sp.Analyze(filepath.Join(work, "typing"), base, inj.String())
	if err != nil {
		return nil, err
	}
	if _, ok := alignSplice(typing, base, inj.String()); !ok {
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

	z.checkLibDefs()

	defs := map[string]*Node{}
	for _, n := range topStatements(ta, tfid) {
		if n.Type == "DefNode" && a.ref(n, "receiver") == nil {
			defs[n.Str["name"]] = n
		}
	}
	z.scanSubprograms(ta, defs, roots)
	order := z.callGraph(ta, defs, roots)
	for _, r := range roots {
		d := defs[r.Name]
		if d == nil {
			continue
		}
		p := z.program(ta, d, r)
		if p != nil {
			res.Programs = append(res.Programs, p)
		}
	}
	for _, fi := range order {
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
	sort.Slice(res.Funcs, func(i, j int) bool { return z.funcs[res.Funcs[i].Name].Decl < z.funcs[res.Funcs[j].Name].Decl })
	z.resolveSubprograms(order, res.Programs)

	z.compareInjection(roots)

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

	res.Maps = z.mapOrder
	if len(res.Programs) > 0 {
		used := map[*MapDecl]bool{}
		for _, p := range withFuncs(res) {
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
	for _, p := range res.Programs {
		if usesKernelTypes(p) || p.Kind == "netfilter" {
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

type rootDecl struct {
	Name                  string
	Kind                  string
	Pos                   Pos
	Target                string
	Nargs                 int
	Ret                   string
	Params                []KParam
	BinarySHA, BinaryPath string
	SysTarget             string
	TArgs                 []TpArg
	TFields               []TpField
}

type KParam struct {
	N    int
	Type string
}

var rootKindOf = map[string]bool{"xdp": true, "fentry": true, "fexit": true, "kprobe": true, "tcx": true, "uprobe": true, "tp_btf": true, "kretprobe": true, "uretprobe": true, "raw_tp": true, "socket_filter": true, "cgroup_skb": true, "tracepoint": true, "ksyscall": true, "netfilter": true, "flow_dissector": true, "sk_lookup": true, "fmod_ret": true}

var ctxClass = map[string]string{"xdp": "XdpMd", "fentry": "FentryCtx", "fexit": "FexitCtx", "kprobe": "KprobeCtx", "kretprobe": "KretprobeCtx", "uretprobe": "UretprobeCtx", "sched_cls": "SkBuff", "uprobe": "UprobeCtx", "tp_btf": "TpBtfCtx", "raw_tp": "RawTpCtx", "socket_filter": "SocketFilterCtx", "cgroup_skb": "CgroupSkb", "tracepoint": "TracepointCtx", "ksyscall": "KsyscallCtx", "netfilter": "NfCtx", "flow_dissector": "FlowCtx", "sk_lookup": "SkLookupCtx", "fmod_ret": "FmodRetCtx"}

func (z *analyzer) scanTop(a *AST, fid int) []rootDecl {
	var roots []rootDecl
	seen := map[string]bool{}
	defs := map[string]*Node{}
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
			if z.globalDecl(a, n) {
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
	z.checkGlobalNames(roots)
	return out
}

func (z *analyzer) mapDecl(a *AST, n *Node) {
	v := a.ref(n, "value")
	if v == nil || v.Type != "CallNode" || v.Str["name"] != "new" || (constName(a, a.ref(v, "receiver")) != "BPF::ArrayMap" && constName(a, a.ref(v, "receiver")) != "BPF::PerCpuArrayMap" && constName(a, a.ref(v, "receiver")) != "BPF::LpmTrieMap" && constName(a, a.ref(v, "receiver")) != "BPF::DevMap" && constName(a, a.ref(v, "receiver")) != "BPF::SockMap") {
		return
	}
	kind, class := "", ""
	if constName(a, a.ref(v, "receiver")) == "BPF::PerCpuArrayMap" {
		kind, class = "percpu_array", "PerCpuArrayMap"
	} else if constName(a, a.ref(v, "receiver")) == "BPF::LpmTrieMap" {
		kind, class = "lpm_trie", "LpmTrieMap"
	} else if constName(a, a.ref(v, "receiver")) == "BPF::DevMap" {
		kind, class = "devmap", "DevMap"
	} else if constName(a, a.ref(v, "receiver")) == "BPF::SockMap" {
		kind, class = "sockmap", "SockMap"
	}
	shown := "ArrayMap"
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
	if kind == "sockmap" && as[1].Str["value"] != "u64" {
		z.add(Rejected, SB013MapDeclShape, z.pos(a, as[1]), "the value type of a sockmap is :u64 (a socket — user space puts its fd), got :%s", as[1].Str["value"])
		return
	}
	if kind == "devmap" && as[1].Str["value"] != "u32" {
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
		m.KeyRecord = lpmKey4
	}
	z.maps[c] = m
	z.mapOrder = append(z.mapOrder, m)
}

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
			if strings.HasPrefix(name, "__ebpf_") && !mutation("no-ebpf-prefix") {
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
			continue
		}
		for _, r := range rs {
			if r.File != z.lib {
				z.add(Rejected, SB011ShadowedName, Pos{File: filepath.Base(r.File), Line: r.Line, Col: r.Col + 1},
					"`%s` is defined outside ruby/lib/bpf.rb — the eBPF side's API must be the library's", k)
			}
		}
	}
}

func (z *analyzer) compareInjection(roots []rootDecl) {
	rootSet := map[string]bool{}
	for _, r := range roots {
		rootSet[r.Name] = true
	}
	d := CompareTypes(z.plain.Types, z.typing.Types, z.base, z.userLines, rootSet, z.paramReads(roots))
	z.diags = append(z.diags, d...)
}

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
		if additive[k] && k.Kind == "DefNode" {
			continue
		}
		ds = append(ds, Diag{Verdict: Rejected, Code: SB010TypingProbe, Pos: Pos{File: base, Line: k.Line, Col: k.Col + 1},
			Msg: fmt.Sprintf("the typing probe changed Spinel's inference of this %s (without: %q, with: %q) — the eBPF side's types must not depend on the injected call", k.Kind, p, t)})
	}
	return ds
}

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

func (z *analyzer) checkUserSideAPI(a *AST, fid int, roots []rootDecl, defs map[string]*Node) {
	bpf := map[*Node]bool{}
	for _, r := range roots {
		if d := defs[r.Name]; d != nil {
			bpf[d] = true
		}
	}
	for _, fi := range z.funcs {
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
				if x.Type == "MultiWriteNode" && reads(a.ref(x, "value")) {
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
		if !isRoot[name] && !done[name] {
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

type threadRef struct {
	name string
	pos  Pos
	line int
}

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
	if kind == "flow_dissector" {
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.flow_dissector` takes exactly one Symbol literal (`BPF.flow_dissector :name` — it is attached to a network namespace in user space with `obj.attach_netns`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "flow_dissector", Pos: z.pos(a, n)}, true
	}
	if kind == "sk_lookup" {
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.sk_lookup` takes exactly one Symbol literal (`BPF.sk_lookup :name`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "sk_lookup", Pos: z.pos(a, n)}, true
	}
	if kind == "netfilter" {
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.netfilter` takes exactly one Symbol literal (`BPF.netfilter :name` — the hook is chosen in user space with `obj.attach_netfilter(name, pf, hooknum, priority)`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "netfilter", Pos: z.pos(a, n)}, true
	}
	if kind == "cgroup_skb" {
		if len(as) != 2 || as[0].Type != "SymbolNode" || as[1].Type != "SymbolNode" || (as[1].Str["value"] != "ingress" && as[1].Str["value"] != "egress") {
			return bad("a cgroup_skb program is declared as `BPF.cgroup_skb :name, :ingress` or `BPF.cgroup_skb :name, :egress` (two Symbol literals — the second is the direction)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "cgroup_skb", Pos: z.pos(a, n), Target: as[1].Str["value"]}, true
	}
	if kind == "socket_filter" {
		if len(as) != 1 || as[0].Type != "SymbolNode" {
			return bad("`BPF.socket_filter` takes exactly one Symbol literal (`BPF.socket_filter :name` — it is attached to a socket in user space with `obj.attach_socket`)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "socket_filter", Pos: z.pos(a, n)}, true
	}
	if kind == "tcx" {
		if len(as) != 2 || as[0].Type != "SymbolNode" || as[1].Type != "SymbolNode" || (as[1].Str["value"] != "ingress" && as[1].Str["value"] != "egress") {
			return bad("a sched_cls program is declared as `BPF.tcx :name, :ingress` or `BPF.tcx :name, :egress` (two Symbol literals — the second is the tcx direction)")
		}
		return rootDecl{Name: as[0].Str["value"], Kind: "sched_cls", Pos: z.pos(a, n), Target: as[1].Str["value"]}, true
	}
	if kind == "tracepoint" {
		return z.tracepointDecl(a, n, as, bad)
	}
	if kind == "uprobe" || kind == "uretprobe" {
		return z.uprobeDecl(a, n, as, bad)
	}
	if kind == "tp_btf" {
		return z.tpBtfDecl(a, n, as)
	}
	if kind == "fmod_ret" {
		return z.fmodRetDecl(a, n, as, bad)
	}
	if kind == "fentry" && len(as) == 3 {
		return z.structArgsDecl(a, n, as, "fentry")
	}
	shape := map[string]string{
		"fentry":    "`BPF.fentry :name, \"kernel_function\"`",
		"fexit":     "`BPF.fexit :name, \"kernel_function\", nargs: N, ret: :i32`",
		"kprobe":    "`BPF.kprobe :name, \"kernel_function\", params: {n => :u64, …}`",
		"kretprobe": "`BPF.kretprobe :name, \"kernel_function\", ret: :i32`",
		"raw_tp":    "`BPF.raw_tp :name, \"tracepoint\"`",
		"ksyscall":  "`BPF.ksyscall :name, \"syscall\", params: {n => :u64, …}`",
	}[kind]
	want := 2
	if kind != "fentry" && kind != "raw_tp" {
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
	case "kretprobe":
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
	case "kprobe", "ksyscall":
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
			if !ok && kind == "kprobe" && v != nil && v.Type == "SymbolNode" && v.Str["value"] == "ptr" {
				t, ok = "ptr", true
			}
			if !ok && kind == "ksyscall" && v != nil && v.Type == "SymbolNode" && (v.Str["value"] == "user_str" || v.Str["value"] == "user_str_array") {
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

const spliceMsg = "Spinel spliced its builtins (enumerable.rb / enumerator.rb — the code names a method that Enumerable defines, such as count or map) and shifted this file's line numbers, and the shift could not be measured from the named nodes (docs/upstream_suspects.md S11) — rename the method or avoid the call"
