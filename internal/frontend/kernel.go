package frontend

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

type KernelField struct {
	Name   string
	Kind   string
	Bits   int
	Signed bool
	Ptr    string
	Count  int
}

type KernelTypeDecl struct {
	Const      string
	Name       string
	Fields     []KernelField
	Pos        Pos
	StructPos  Pos
	HandlePoss []Pos
}

func (k *KernelTypeDecl) field(name string) *KernelField {
	for i := range k.Fields {
		if k.Fields[i].Name == name {
			return &k.Fields[i]
		}
	}
	return nil
}

type TpArg struct {
	Idx  int
	KT   *KernelTypeDecl
	Type string
	Null bool
}

var rubyKeywords = map[string]bool{
	"BEGIN": true, "END": true, "alias": true, "and": true, "begin": true, "break": true, "case": true, "class": true, "def": true, "defined?": true,
	"do": true, "else": true, "elsif": true, "end": true, "ensure": true, "false": true, "for": true, "if": true, "in": true, "module": true, "next": true,
	"nil": true, "not": true, "or": true, "redo": true, "rescue": true, "retry": true, "return": true, "self": true, "super": true, "then": true,
	"true": true, "undef": true, "unless": true, "until": true, "when": true, "while": true, "yield": true,
}

var lowerIdent = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func (z *analyzer) kernelTypeDecl(a *AST, n *Node, structs map[string]*structInfo, ptrs map[*KernelField]*Node) {
	p := z.pos(a, n)
	as := args(a, n)
	bad := func(pos Pos, format string, x ...any) {
		z.add(Rejected, SB033KernelTypeShape, pos, format, x...)
	}
	if len(as) != 3 || as[0].Type != "ConstantReadNode" || as[1].Type != "StringNode" || as[1].Str["content"] == "" || as[2].Type != "KeywordHashNode" {
		bad(p, "a kernel struct is declared as `BPF.kernel_type(S, \"kernel_name\", member: :i32, …)` — a Struct constant, the kernel struct's name and the members read")
		return
	}
	c := as[0].Str["name"]
	s := structs[c]
	switch {
	case s == nil:
		bad(z.pos(a, as[0]), "%s is not a top-level `%s = Struct.new(:m, …)`", c, c)
		return
	case s.bad != "":
		bad(s.pos, "%s: %s", c, s.bad)
		return
	case z.records[c] != nil:
		bad(p, "%s is a record (BPF.record) — a kernel struct is its own Struct", c)
		return
	case z.kts[c] != nil:
		bad(p, "kernel struct %s is declared twice", c)
		return
	}
	d := &KernelTypeDecl{Const: c, Name: as[1].Str["content"], Pos: p, StructPos: s.pos}
	var got []string
	for _, e := range a.arr(as[2], "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || k.Type != "SymbolNode" || v == nil {
			bad(z.pos(a, e), "each member is `name: :i32`, `name: [:kptr, S]` or `name: [:u8, N]`")
			return
		}
		name := k.Str["value"]
		if !lowerIdent.MatchString(name) || rubyKeywords[name] {
			bad(z.pos(a, k), "member %s: the kernel member's name must be a lowercase Ruby identifier that is not a keyword (it becomes the Struct's accessor) — read another field, or ask bpf-mlir for an alias", name)
			return
		}
		f := KernelField{Name: name}
		switch v.Type {
		case "SymbolNode":
			if v.Str["value"] == "strptr" {
				f.Kind, f.Bits = "strptr", 64
				break
			}
			t, ok := recordTypes[v.Str["value"]]
			if !ok {
				bad(z.pos(a, v), "member %s: the type must be :i8 … :i64 / :u8 … :u64, `[:kptr, S]` or `[:u8, N]`, got :%s", name, v.Str["value"])
				return
			}
			f.Kind, f.Bits, f.Signed = "int", t[0], t[1] == 1
		case "ArrayNode":
			els := a.arr(v, "elements")
			if len(els) != 2 || els[0].Type != "SymbolNode" {
				bad(z.pos(a, v), "member %s: `[:kptr, S]` or `[:u8, N]`", name)
				return
			}
			switch {
			case els[0].Str["value"] == "kptr" && els[1].Type == "ConstantReadNode":
				f.Kind, f.Ptr, f.Bits = "kptr", els[1].Str["name"], 64
				ptrs[&f] = els[1]
			case els[0].Str["value"] == "struct" && els[1].Type == "ConstantReadNode":
				f.Kind, f.Ptr = "struct", els[1].Str["name"]
			case (els[0].Str["value"] == "u8" || els[0].Str["value"] == "i8") && els[1].Type == "IntegerNode":
				nb, ok := z.literal(a, els[1])
				if !ok || !nb.IsInt64() || nb.Int64() < 1 || nb.Int64() > 64 {
					bad(z.pos(a, els[1]), "member %s: the array length must be a literal 1..64 (bpf-mlir's kernel byte arrays — kfield.copy)", name)
					return
				}
				f.Kind, f.Bits, f.Signed, f.Count = "array", 8, els[0].Str["value"] == "i8", int(nb.Int64())
			default:
				bad(z.pos(a, v), "member %s: `[:kptr, S]` (S a kernel struct), `[:struct, S]` (an embedded kernel struct) or `[:u8, N]` / `[:i8, N]`", name)
				return
			}
		default:
			bad(z.pos(a, v), "member %s: the type is a Symbol literal or `[:kptr, S]` / `[:u8, N]`", name)
			return
		}
		got = append(got, name)
		d.Fields = append(d.Fields, f)
	}
	if len(d.Fields) == 0 {
		bad(p, "kernel struct %s reads no member", c)
		return
	}
	if strings.Join(got, ",") != strings.Join(s.names, ",") {
		bad(p, "the members of BPF.kernel_type(%s, …) (%s) must be the Struct's members in the same order (%s)", c, strings.Join(got, ", "), strings.Join(s.names, ", "))
		return
	}
	z.kts[c] = d
	z.ktOrder = append(z.ktOrder, d)
}

func (z *analyzer) kernelTypesResolve(a *AST, ptrs map[*KernelField]*Node) {
	for _, d := range append([]*KernelTypeDecl(nil), z.ktOrder...) {
		for i := range d.Fields {
			f := &d.Fields[i]
			if f.Kind != "kptr" && f.Kind != "struct" {
				continue
			}
			if z.kts[f.Ptr] == nil {
				if f.Kind == "struct" {
					z.add(Rejected, SB033KernelTypeShape, d.Pos, "member %s of %s embeds %s, which is not declared with BPF.kernel_type", f.Name, d.Const, f.Ptr)
				} else {
					z.add(Rejected, SB033KernelTypeShape, d.Pos, "member %s of %s points to %s, which is not declared with BPF.kernel_type", f.Name, d.Const, f.Ptr)
				}
				delete(z.kts, d.Const)
			}
		}
	}
	for _, d := range append([]*KernelTypeDecl(nil), z.ktOrder...) {
		if z.kts[d.Const] == nil {
			continue
		}
		if cyc := z.embedCycle(d.Const, map[string]bool{}); cyc != "" {
			z.add(Rejected, SB033KernelTypeShape, d.Pos, "kernel struct %s embeds itself by value (%s) — an embedded struct ([:struct, S]) cannot contain its container; use [:kptr, S] for a pointer", d.Const, cyc)
			delete(z.kts, d.Const)
		}
	}
	var keep []*KernelTypeDecl
	for _, d := range z.ktOrder {
		if z.kts[d.Const] != nil {
			keep = append(keep, d)
		}
	}
	z.ktOrder = keep
	_ = ptrs
}

func (z *analyzer) kernelHandleDecl(a *AST, n *Node) {
	v := a.ref(n, "value")
	h := n.Str["name"]
	as := args(a, v)
	if len(as) != 1 || as[0].Type != "CallNode" || as[0].Str["name"] != "new" {
		z.add(Rejected, SB033KernelTypeShape, z.pos(a, n), "a kernel struct's typing sample is `%s = BPF::KernelType.new(S.new(0, …))`", h)
		return
	}
	sc := constName(a, a.ref(as[0], "receiver"))
	d := z.kts[sc]
	if d == nil {
		z.add(Rejected, SB033KernelTypeShape, z.pos(a, as[0]), "%s is not declared with BPF.kernel_type", sc)
		return
	}
	sas := args(a, as[0])
	if len(sas) != len(d.Fields) {
		z.add(Rejected, SB033KernelTypeShape, z.pos(a, as[0]), "the sample must give all %d members of %s", len(d.Fields), sc)
		return
	}
	for i, x := range sas {
		f := d.Fields[i]
		if f.Kind == "struct" {
			if !z.embedSample(a, x, f.Ptr) {
				z.add(Rejected, SB033KernelTypeShape, z.pos(a, x), "the sample of the embedded struct member %s is `%s.new(0, …)` with every member's sample", f.Name, f.Ptr)
				return
			}
			continue
		}
		if f.Kind == "array" {
			xa := args(a, x)
			if x.Type != "CallNode" || x.Str["name"] != "new" || constName(a, a.ref(x, "receiver")) != "Array" || len(xa) != 2 {
				z.add(Rejected, SB033KernelTypeShape, z.pos(a, x), "the sample of the array member %s is `Array.new(%d, 0)`", f.Name, f.Count)
				return
			}
			nb, ok1 := z.literal(a, xa[0])
			zero, ok2 := z.literal(a, xa[1])
			if !ok1 || !ok2 || !nb.IsInt64() || nb.Int64() != int64(f.Count) || zero.Sign() != 0 {
				z.add(Rejected, SB033KernelTypeShape, z.pos(a, x), "the sample of the array member %s is `Array.new(%d, 0)`", f.Name, f.Count)
				return
			}
			continue
		}
		if f.Kind == "strptr" {
			if x.Type != "StringNode" || x.Str["content"] != "" {
				z.add(Rejected, SB033KernelTypeShape, z.pos(a, x), "the sample of the :strptr member %s is the empty String literal \"\"", f.Name)
				return
			}
			continue
		}
		lit, ok := big.NewInt(1), x.Type == "IntegerNode"
		if ok {
			lit, ok = z.literal(a, x)
		}
		if !ok || lit.Sign() != 0 {
			z.add(Rejected, SB033KernelTypeShape, z.pos(a, x), "the sample's members are the literal 0 — it is a sample of the type for Spinel's inference")
			return
		}
	}
	z.ktHandles[h] = d
	d.HandlePoss = append(d.HandlePoss, z.pos(a, n))
}

func (z *analyzer) tpBtfDecl(a *AST, n *Node, as []*Node) (rootDecl, bool) {
	return z.structArgsDecl(a, n, as, "tp_btf")
}

func (z *analyzer) structArgsDecl(a *AST, n *Node, as []*Node, kind string) (rootDecl, bool) {
	bad := func(format string, x ...any) (rootDecl, bool) {
		z.add(Rejected, SB033KernelTypeShape, z.pos(a, n), format, x...)
		return rootDecl{}, false
	}
	shape := "`BPF.tp_btf :name, \"tracepoint\", args: {0 => TaskT, 2 => :u32}`"
	if kind == "fentry" {
		shape = "`BPF.fentry :name, \"kernel_function\", args: {0 => [:or_null, TaskT]}`"
	}
	if len(as) != 3 || as[0].Type != "SymbolNode" || as[1].Type != "StringNode" || as[1].Str["content"] == "" || as[2].Type != "KeywordHashNode" {
		return bad("a %s program is declared as %s — the arguments it reads, by index", kind, shape)
	}
	var hv *Node
	for _, e := range a.arr(as[2], "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || k.Type != "SymbolNode" || k.Str["value"] != "args" || hv != nil {
			return bad("the options of %s are exactly `args:`", shape)
		}
		hv = v
	}
	if hv == nil || hv.Type != "HashNode" {
		return bad("%s needs `args:` with a Hash literal of argument index (0..11) => a kernel struct's sample handle or an integer type", shape)
	}
	r := rootDecl{Name: as[0].Str["value"], Kind: kind, Pos: z.pos(a, n), Target: as[1].Str["content"]}
	seen := map[int]bool{}
	for _, e := range a.arr(hv, "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || k.Type != "IntegerNode" || v == nil {
			return bad("each %s argument is `i => TaskT` or `i => :u32` with i an Integer literal 0..11", kind)
		}
		nb, ok := z.literal(a, k)
		if !ok || !nb.IsInt64() || nb.Int64() < 0 || nb.Int64() > 11 || seen[int(nb.Int64())] {
			return bad("a %s argument index is 0..11 (the u64 context slots) and appears once", kind)
		}
		i := int(nb.Int64())
		seen[i] = true
		if kind == "fentry" && v.Type == "ConstantReadNode" {
			return bad("argument %d: a fentry struct argument is always nullable — declare it `%d => [:or_null, T]` and read it with `q = ctx.kptr_or_null(%d, T)` and `if q` (an integer argument is `%d => :u32` etc., read with `ctx.arg(%d)`)", i, i, i, i, i)
		}
		switch v.Type {
		case "ConstantReadNode":
			d := z.ktHandles[v.Str["name"]]
			if d == nil {
				return bad("argument %d: %s is not a kernel struct's sample handle (`%s = BPF::KernelType.new(S.new(0, …))`)", i, v.Str["name"], v.Str["name"])
			}
			r.TArgs = append(r.TArgs, TpArg{Idx: i, KT: d})
		case "SymbolNode":
			if _, ok := recordTypes[v.Str["value"]]; !ok {
				return bad("argument %d: an integer argument's type is one of :i8 … :i64 / :u8 … :u64", i)
			}
			r.TArgs = append(r.TArgs, TpArg{Idx: i, Type: v.Str["value"]})
		case "ArrayNode":
			els := a.arr(v, "elements")
			if len(els) != 2 || els[0].Type != "SymbolNode" || els[0].Str["value"] != "or_null" || els[1].Type != "ConstantReadNode" || z.ktHandles[els[1].Str["name"]] == nil {
				return bad("argument %d: a nullable struct argument is `[:or_null, T]` with T a kernel struct's sample handle", i)
			}
			r.TArgs = append(r.TArgs, TpArg{Idx: i, KT: z.ktHandles[els[1].Str["name"]], Null: true})
		default:
			return bad("argument %d: a kernel struct's sample handle or an integer type Symbol", i)
		}
	}
	return r, true
}

func (p *Program) tpArg(i int) *TpArg {
	for k := range p.TArgs {
		if p.TArgs[k].Idx == i {
			return &p.TArgs[k]
		}
	}
	return nil
}

func (c *progCtx) kptrCall(v *Node) bool {
	if v != nil && v.Type == "CallNode" && (v.Str["name"] == "state" || v.Str["name"] == "skb") && c.isVarRead(c.a.ref(v, "receiver"), c.param) && c.prog.Kind == "netfilter" {
		return true
	}
	return v != nil && v.Type == "CallNode" && (v.Str["name"] == "kptr" || v.Str["name"] == "kptr_or_null") && c.isVarRead(c.a.ref(v, "receiver"), c.param) && c.prog.Kind == "tp_btf"
}

var nfPtrs = map[string]string{"state": "nf_hook_state", "skb": "sk_buff"}

func (c *progCtx) nfBind(w, v *Node, name string) (Stmt, bool) {
	field := v.Str["name"]
	callee, ok := c.callee(v)
	if !ok {
		return Stmt{}, false
	}
	if want := "NfCtx#" + field; callee != want {
		c.add(Rejected, SB011ShadowedName, v, "`%s` resolves to %s, not BPF::%s", field, callee, want)
		return Stmt{}, false
	}
	as := args(c.a, v)
	if len(as) != 1 || as[0].Type != "ConstantReadNode" {
		c.add(Rejected, SB033KernelTypeShape, v, "`%s.%s(T)` takes one kernel struct's sample handle (`T = BPF::KernelType.new(…)` of a `BPF.kernel_type(…, %q, …)`)", c.param, field, nfPtrs[field])
		return Stmt{}, false
	}
	h := c.z.ktHandles[as[0].Str["name"]]
	if h == nil || h.Name != nfPtrs[field] {
		got := "not a kernel struct handle"
		if h != nil {
			got = h.Name
		}
		c.add(Rejected, SB033KernelTypeShape, as[0], "`%s.%s` points to the kernel struct %s — %s is %s", c.param, field, nfPtrs[field], as[0].Str["name"], got)
		return Stmt{}, false
	}
	c.kptrs[name] = h
	return Stmt{Kind: "kptr", Var: name, Path: field, KT: h, Pos: c.z.pos(c.a, w)}, true
}

func (c *progCtx) kptrBind(w *Node, top bool) (Stmt, bool) {
	name := w.Str["name"]
	v := c.a.ref(w, "value")
	if !top {
		c.add(Rejected, SB033KernelTypeShape, w, "`%s = %s.kptr(…)` is accepted only as a statement directly in the program's body (not inside an arm or a loop) — bind the kernel pointer first", name, c.param)
		return Stmt{}, false
	}
	if _, used := c.env[name]; used || name == c.param || c.refs[name] != nil || c.wins[name] != nil || c.kptrs[name] != nil {
		c.add(Rejected, SB033KernelTypeShape, w, "`%s` is already bound — a kernel pointer is bound once to a fresh name", name)
		return Stmt{}, false
	}
	if c.prog.Kind == "netfilter" {
		return c.nfBind(w, v, name)
	}
	callee, ok := c.callee(v)
	if !ok {
		return Stmt{}, false
	}
	if callee != "TpBtfCtx#kptr" {
		c.add(Rejected, SB011ShadowedName, v, "`kptr` resolves to %s, not BPF::TpBtfCtx#kptr", callee)
		return Stmt{}, false
	}
	as := args(c.a, v)
	if len(as) != 2 || as[0].Type != "IntegerNode" || as[1].Type != "ConstantReadNode" {
		c.add(Rejected, SB033KernelTypeShape, v, "`%s.kptr(i, T)` takes an Integer literal index and a kernel struct's sample handle", c.param)
		return Stmt{}, false
	}
	nb, _ := c.z.literal(c.a, as[0])
	i := int(nb.Int64())
	ta := c.prog.tpArg(i)
	h := c.z.ktHandles[as[1].Str["name"]]
	switch {
	case ta == nil:
		c.add(Rejected, SB033KernelTypeShape, as[0], "argument %d is not declared in `BPF.tp_btf … args:`", i)
		return Stmt{}, false
	case ta.KT == nil:
		c.add(Rejected, SB033KernelTypeShape, v, "argument %d is declared as the integer :%s — read it with `%s.arg(%d)`", i, ta.Type, c.param, i)
		return Stmt{}, false
	case h == nil || h != ta.KT:
		c.add(Rejected, SB033KernelTypeShape, as[1], "argument %d is declared as %s (%s), not %s", i, ta.KT.Const, ta.KT.Name, as[1].Str["name"])
		return Stmt{}, false
	case ta.Null:
		c.add(Rejected, SB033KernelTypeShape, v, "argument %d is declared nullable (`[:or_null, T]`) — read it with `q = %s.kptr_or_null(%d, T)` and `if q`", i, c.param, i)
		return Stmt{}, false
	}
	c.kptrs[name] = ta.KT
	return Stmt{Kind: "kptr", Var: name, Len: int64(i), KT: ta.KT, Pos: c.z.pos(c.a, w)}, true
}

func (c *progCtx) kfieldRead(n, recv *Node, p Pos) *Expr {
	t := c.a.ref(recv, "receiver").Str["name"]
	d := c.kptrs[t]
	f := d.field(n.Str["name"])
	if f == nil {
		c.add(Rejected, SB033KernelTypeShape, n, "%s (%s) declares no member `%s` — declare the members it reads in BPF.kernel_type", d.Const, d.Name, n.Str["name"])
		return nil
	}
	if cs, ok := c.callee(recv); !ok || cs != "KPtr#load" {
		if ok {
			c.add(Rejected, SB011ShadowedName, recv, "`load` resolves to %s, not BPF::KPtr#load", cs)
		}
		return nil
	}
	switch {
	case len(args(c.a, n)) != 0:
		c.add(Rejected, SB002UnsupportedCall, n, "a member read takes no arguments")
		return nil
	case f.Kind == "kptr":
		c.add(Rejected, SB033KernelTypeShape, n, "member %s is a kernel pointer — follow it with `rp = %s.ptr(:%s, T)` and `if rp`", f.Name, t, f.Name)
		return nil
	case f.Kind == "array":
		c.add(Rejected, SB033KernelTypeShape, n, "member %s is a byte array — copy it into a record's byte-array member with `r.load.<member> = %s.copy(:%s)`", f.Name, t, f.Name)
		return nil
	case f.Kind == "struct":
		c.add(Rejected, SB033KernelTypeShape, n, "member %s is an embedded struct — read its integer members as `%s.load.%s.m`", f.Name, t, f.Name)
		return nil
	case f.Kind == "strptr":
		c.add(Rejected, SB033KernelTypeShape, n, "member %s is a :strptr (char *) — read the string it points to with `R.output_str(…, %s.str(:%s), …)`, not its address", f.Name, t, f.Name)
		return nil
	}
	rf := &RecordField{Name: f.Name, Bits: f.Bits, Signed: f.Signed}
	e := &Expr{Kind: "kfload", Var: t, Field: rf, Path: d.Name, Pos: p}
	if f.Bits == 64 && !f.Signed {
		e.Iv, e.Wide = iv(new(big.Int), new(big.Int).Set(u64Max)), true
	} else {
		e.Iv = widthRange(f.Bits, f.Signed)
	}
	return e
}

func (c *progCtx) kptrMisuse(n *Node, name string) {
	switch {
	case n.Type == "CallNode" && n.Str["name"] == "ptr":
		c.add(Rejected, SB005RefCheckShape, n, "`%s.ptr(:m, T)` (a pointer field — nullable) is accepted only as `rp = %s.ptr(:m, T)` followed immediately by `if rp`", name, name)
	case n.Type == "CallNode" && n.Str["name"] == "copy":
		c.add(Rejected, SB033KernelTypeShape, n, "`%s.copy(:m)` (a byte-array field) is not a value — it is accepted only as `r.load.<member> = %s.copy(:m)` inside `if r` of a record map's lookup", name, name)
	case n.Type == "CallNode" && n.Str["name"] == "load":
		c.add(Rejected, SB033KernelTypeShape, n, "`%s.load` is not a value — read an integer member `%s.load.m`", name, name)
	default:
		c.add(Rejected, SB033KernelTypeShape, n, "the kernel pointer `%s` is not a value — read its members as `%s.load.m`", name, name)
	}
}

func kernelTypesSchema(res *Result) []schemaKernelType {
	var out []schemaKernelType
	for _, d := range res.KernelTypes {
		kt := schemaKernelType{Name: d.Name, Note: "Ruby Struct " + d.Const}
		for _, f := range d.Fields {
			var t any
			switch f.Kind {
			case "int":
				t = schemaInt{"int", f.Bits, f.Signed, "little", f.Bits / 8}
			case "kptr":
				t = schemaKPtr{"kptr", res.ktName(f.Ptr)}
			case "array":
				t = schemaArray{Kind: "array", Count: f.Count, Element: schemaInt{"int", 8, f.Signed, "little", 1}}
			case "strptr":
				t = schemaUserStr{"strptr"}
			case "struct":
				t = schemaKStruct{"struct", res.ktName(f.Ptr)}
			}
			kt.Fields = append(kt.Fields, schemaKField{Name: f.Name, Type: t})
		}
		out = append(out, kt)
	}
	return out
}

func (res *Result) ktName(c string) string {
	for _, d := range res.KernelTypes {
		if d.Const == c {
			return d.Name
		}
	}
	return c
}

func tpArgsSchema(p *Program) []any {
	n := 0
	for _, a := range p.TArgs {
		if a.Idx+1 > n {
			n = a.Idx + 1
		}
	}
	out := make([]any, n)
	for _, a := range p.TArgs {
		if a.KT != nil && a.Null {
			out[a.Idx] = schemaNullStruct{"struct", a.KT.Name, true}
		} else if a.KT != nil {
			out[a.Idx] = a.KT.Name
		} else {
			out[a.Idx] = traceInt(a.Type)
		}
	}
	return out
}

func (c *progCtx) isKptrRead(n *Node) bool {
	return n != nil && n.Type == "LocalVariableReadNode" && c.kptrs[n.Str["name"]] != nil
}

func (c *progCtx) topLevel(n *Node) bool {
	p := c.a.node(c.a.Parent[n.ID])
	if p == nil || p.Type != "StatementsNode" {
		return false
	}
	return c.a.node(c.a.Parent[p.ID]) == c.def
}

func noTpBtf(res *Result) error {
	for _, p := range res.Programs {
		if p.Kind == "tp_btf" {
			return fmt.Errorf("the twin and kernel harnesses for a tp_btf program are not written here (they need the tp_btf attach and the fork trigger) — program %s", p.Name)
		}
	}
	return nil
}

func usesKernelTypes(p *Program) bool {
	return p != nil && (p.Kind == "tp_btf" || (p.Kind == "fentry" && len(p.TArgs) > 0))
}

func hasTpBtf(res *Result) bool {
	for _, p := range res.Programs {
		if usesKernelTypes(p) {
			return true
		}
	}
	return false
}

func tpBtfTwinRun(kw string, p *Program, kts []*KernelTypeDecl) string {
	byConst := map[string]*KernelTypeDecl{}
	for _, d := range kts {
		byConst[d.Const] = d
	}
	var b strings.Builder
	var ok []string
	q := func(s string) { ok = append(ok, fmt.Sprintf("%q", s)) }
	for _, a := range p.TArgs {
		if a.KT == nil || a.Null {
			q(fmt.Sprintf("a%d", a.Idx))
		}
		if a.KT == nil {
			continue
		}
		q(fmt.Sprintf("a%d@addr", a.Idx))
		for _, f := range a.KT.Fields {
			if f.Kind == "struct" {
				twinEmbedKeys(byConst, f.Ptr, fmt.Sprintf("a%d.%s", a.Idx, f.Name), q)
				continue
			}
			q(fmt.Sprintf("a%d.%s", a.Idx, f.Name))
			if f.Kind == "kptr" {
				for _, g := range byConst[f.Ptr].Fields {
					if g.Kind != "kptr" {
						q(fmt.Sprintf("a%d.%s.%s", a.Idx, f.Name, g.Name))
					}
				}
			}
		}
	}
	fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_n = Array.new(0, \"\")\n        _h_v = Array.new(0, 0)\n        _h_s = Array.new(0, \"\")\n        _h_ok = [%s]\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if !_h_ok.include?(_h_kv[0])\n            raise \"undeclared tp_btf value #{_h_kv[0]}\"\n          end\n          _h_n.push(_h_kv[0])\n          _h_v.push(_h_kv[1].to_i)\n          _h_s.push(_h_kv[1])\n          _h_i += 1\n        end\n        _h_ints = Array.new(12, 0)\n", kw, p.Name, strings.Join(ok, ", "))
	var kps, idx, nulls []string
	for _, a := range p.TArgs {
		if a.KT == nil {
			fmt.Fprintf(&b, "        _h_ints[%d] = %s\n", a.Idx, widthCut(fmt.Sprintf("_h_fv(_h_n, _h_v, %q)", fmt.Sprintf("a%d", a.Idx)), a.Type))
			continue
		}
		v := fmt.Sprintf("_h_kp%d", a.Idx)
		twinKPtr(&b, v, a.KT, fmt.Sprintf("a%d", a.Idx), "        ", byConst)
		fmt.Fprintf(&b, "        %s.set_addr(_h_fv(_h_n, _h_v, %q))\n", v, fmt.Sprintf("a%d@addr", a.Idx))
		for _, f := range a.KT.Fields {
			if f.Kind == "kptr" {
				key := fmt.Sprintf("a%d.%s", a.Idx, f.Name)
				fmt.Fprintf(&b, "        if _h_n.include?(%q)\n", key)
				twinKPtr(&b, v+"_"+f.Name, byConst[f.Ptr], key, "          ", byConst)
				fmt.Fprintf(&b, "          %s.set_ptr(:%s, %s_%s)\n        end\n", v, f.Name, v, f.Name)
			}
		}
		if a.Null {
			nulls = append(nulls, fmt.Sprintf("        if _h_n.include?(\"a%d\")\n          _h_ks[%d] = nil\n        end\n", a.Idx, len(kps)))
		}
		kps = append(kps, v)
		idx = append(idx, fmt.Sprint(a.Idx))
	}
	ctx := fmt.Sprintf("BPF::TpBtfCtx.new(_h_ks, [%s], _h_ints)", strings.Join(idx, ", "))
	if p.Kind == "fentry" {
		ctx = fmt.Sprintf("BPF::FentryCtx.new(_h_ks, [%s], _h_ints)", strings.Join(idx, ", "))
		if len(kps) == 0 {
			ctx = "BPF::FentryCtx.new(nil, nil, _h_ints)"
		}
	}
	fmt.Fprintf(&b, "        _h_ks = [%s]\n%s        %s(%s)\n        puts \"ret=0\"\n", strings.Join(kps, ", "), strings.Join(nulls, ""), p.Name, ctx)
	return b.String()
}

func twinKPtr(b *strings.Builder, v string, d *KernelTypeDecl, pre, ind string, byConst map[string]*KernelTypeDecl) {
	var vs []string
	for _, f := range d.Fields {
		switch f.Kind {
		case "struct":
			vs = append(vs, twinKStruct(byConst, f.Ptr, pre+"."+f.Name))
		case "int":
			vs = append(vs, widthCut(fmt.Sprintf("_h_fv(_h_n, _h_v, %q)", pre+"."+f.Name), intTypeName(f.Bits, f.Signed)))
		case "kptr":
			vs = append(vs, "0")
		case "array":
			vs = append(vs, fmt.Sprintf("Array.new(%d, 0)", f.Count))
		case "strptr":
			vs = append(vs, "\"\"")
		}
	}
	fmt.Fprintf(b, "%s%s = BPF::KPtr.new(%s.new(%s))\n", ind, v, d.Const, strings.Join(vs, ", "))
	for _, f := range d.Fields {
		if f.Kind == "strptr" {
			fmt.Fprintf(b, "%s%s.set_str(:%s, _h_fs(_h_n, _h_s, %q))\n", ind, v, f.Name, pre+"."+f.Name)
		}
		if f.Kind == "array" {
			fmt.Fprintf(b, "%s%s.set_arr(:%s, _h_fa(_h_n, _h_s, %q, %d))\n", ind, v, f.Name, pre+"."+f.Name, f.Count)
		}
	}
}

func intTypeName(bits int, signed bool) string {
	if signed {
		return fmt.Sprintf("i%d", bits)
	}
	return fmt.Sprintf("u%d", bits)
}

type schemaNullStruct struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Nullable bool   `json:"nullable"`
}

func (c *progCtx) kcheckCall(v *Node) bool {
	if v == nil || v.Type != "CallNode" {
		return false
	}
	if v.Str["name"] == "kptr_or_null" && c.isVarRead(c.a.ref(v, "receiver"), c.param) && usesKernelTypes(c.prog) {
		return true
	}
	return v.Str["name"] == "ptr" && c.isKptrRead(c.a.ref(v, "receiver"))
}

func (c *progCtx) kcheckStmt(w, ifn *Node, refVar string) (Stmt, bool) {
	name := w.Str["name"]
	v := c.a.ref(w, "value")
	if _, used := c.env[name]; used || name == c.param || c.refs[name] != nil || c.wins[name] != nil || c.kptrs[name] != nil || c.kchecked[name] {
		c.add(Rejected, SB033KernelTypeShape, w, "`%s` is already bound — a kernel pointer is bound once to a fresh name", name)
		return Stmt{}, false
	}
	callee, ok := c.callee(v)
	if !ok {
		return Stmt{}, false
	}
	as := args(c.a, v)
	s := Stmt{Kind: "kcheck", Var: name, Pos: c.z.pos(c.a, w), IfPos: c.z.pos(c.a, ifn)}
	if v.Str["name"] == "kptr_or_null" {
		if want := map[string]string{"tp_btf": "TpBtfCtx#kptr_or_null", "fentry": "FentryCtx#kptr_or_null"}[c.prog.Kind]; callee != want {
			c.add(Rejected, SB011ShadowedName, v, "`kptr_or_null` resolves to %s, not BPF::%s", callee, want)
			return Stmt{}, false
		}
		if !c.topLevel(w) {
			c.add(Rejected, SB033KernelTypeShape, w, "`%s = %s.kptr_or_null(…)` is accepted only as a statement directly in the program's body", name, c.param)
			return Stmt{}, false
		}
		if len(as) != 2 || as[0].Type != "IntegerNode" || as[1].Type != "ConstantReadNode" {
			c.add(Rejected, SB033KernelTypeShape, v, "`%s.kptr_or_null(i, T)` takes an Integer literal index and a kernel struct's sample handle", c.param)
			return Stmt{}, false
		}
		nb, _ := c.z.literal(c.a, as[0])
		i := int(nb.Int64())
		ta := c.prog.tpArg(i)
		h := c.z.ktHandles[as[1].Str["name"]]
		switch {
		case ta == nil:
			c.add(Rejected, SB033KernelTypeShape, as[0], "argument %d is not declared in `BPF.%s … args:`", i, c.prog.Kind)
			return Stmt{}, false
		case ta.KT == nil:
			c.add(Rejected, SB033KernelTypeShape, v, "argument %d is declared as the integer :%s — read it with `%s.arg(%d)`", i, ta.Type, c.param, i)
			return Stmt{}, false
		case !ta.Null:
			c.add(Rejected, SB033KernelTypeShape, v, "argument %d is declared non-null — read it with `t = %s.kptr(%d, T)` (declare `%d => [:or_null, T]` if the tracepoint passes NULL)", i, c.param, i, i)
			return Stmt{}, false
		case h == nil || h != ta.KT:
			c.add(Rejected, SB033KernelTypeShape, as[1], "argument %d is declared as %s (%s), not %s", i, ta.KT.Const, ta.KT.Name, as[1].Str["name"])
			return Stmt{}, false
		}
		s.KT, s.Len, s.Path = ta.KT, int64(i), ""
	} else {
		t := c.a.ref(v, "receiver").Str["name"]
		d := c.kptrs[t]
		if callee != "KPtr#ptr" {
			c.add(Rejected, SB011ShadowedName, v, "`ptr` resolves to %s, not BPF::KPtr#ptr", callee)
			return Stmt{}, false
		}
		if len(as) != 2 || as[0].Type != "SymbolNode" || as[1].Type != "ConstantReadNode" {
			c.add(Rejected, SB033KernelTypeShape, v, "`%s.ptr(:m, T)` takes a member Symbol and the pointee's sample handle", t)
			return Stmt{}, false
		}
		f := d.field(as[0].Str["value"])
		h := c.z.ktHandles[as[1].Str["name"]]
		switch {
		case f == nil:
			c.add(Rejected, SB033KernelTypeShape, as[0], "%s (%s) declares no member `%s`", d.Const, d.Name, as[0].Str["value"])
			return Stmt{}, false
		case f.Kind != "kptr":
			c.add(Rejected, SB033KernelTypeShape, as[0], "member %s is not a kernel pointer (`[:kptr, S]`) — read it with `%s.load.%s`", f.Name, t, f.Name)
			return Stmt{}, false
		case h == nil || h.Const != f.Ptr:
			c.add(Rejected, SB033KernelTypeShape, as[1], "member %s points to %s, not the struct of %s", f.Name, f.Ptr, as[1].Str["name"])
			return Stmt{}, false
		}
		s.KT, s.Path, s.PtrOf, s.PtrOfKT = h, f.Name, t, d
	}
	if !c.typed(c.a.ref(ifn, "predicate")) {
		return Stmt{}, false
	}
	c.kchecked[name] = true
	pre := c.env
	c.env = copyEnv(pre)
	c.kptrs[name] = s.KT
	var then []*Node
	if st := c.a.ref(ifn, "statements"); st != nil {
		then = c.a.arr(st, "body")
	}
	s.Then = c.stmts(then, refVar)
	delete(c.kptrs, name)
	thenEnv := c.env
	c.env = copyEnv(pre)
	if sub := c.a.ref(ifn, "subsequent"); sub != nil {
		if sub.Type != "ElseNode" {
			c.add(Rejected, SB005RefCheckShape, sub, "`elsif` is not accepted after `if %s`", name)
			return Stmt{}, false
		}
		var els []*Node
		if st := c.a.ref(sub, "statements"); st != nil {
			els = c.a.arr(st, "body")
		}
		s.Else = c.stmts(els, refVar)
	}
	c.env = joinArms(pre, thenEnv, c.env, escapes(s.Then), escapes(s.Else))
	return s, true
}

func (c *progCtx) kcheckedRoot(n *Node) string {
	for n != nil && n.Type == "CallNode" {
		n = c.a.ref(n, "receiver")
	}
	if n != nil && n.Type == "LocalVariableReadNode" && c.kchecked[n.Str["name"]] && c.kptrs[n.Str["name"]] == nil {
		return n.Str["name"]
	}
	return ""
}

func (c *progCtx) kcopyStmt(n, cp *Node, ref string, m *MapDecl, rf *RecordField) (Stmt, bool) {
	t := c.a.ref(cp, "receiver").Str["name"]
	d := c.kptrs[t]
	callee, ok := c.callee(cp)
	if !ok {
		return Stmt{}, false
	}
	if callee != "KPtr#copy" {
		c.add(Rejected, SB011ShadowedName, cp, "`copy` resolves to %s, not BPF::KPtr#copy", callee)
		return Stmt{}, false
	}
	as := args(c.a, cp)
	if len(as) != 1 || as[0].Type != "SymbolNode" {
		c.add(Rejected, SB033KernelTypeShape, cp, "`%s.copy(:m)` takes one member Symbol", t)
		return Stmt{}, false
	}
	kf := d.field(as[0].Str["value"])
	switch {
	case kf == nil:
		c.add(Rejected, SB033KernelTypeShape, as[0], "%s (%s) declares no member `%s`", d.Const, d.Name, as[0].Str["value"])
		return Stmt{}, false
	case kf.Kind != "array":
		c.add(Rejected, SB033KernelTypeShape, as[0], "member %s is not a byte array (`[:u8, N]`) — read it with `%s.load.%s`", kf.Name, t, kf.Name)
		return Stmt{}, false
	case rf.Count == 0 || rf.Bits != 8:
		c.add(Rejected, SB033KernelTypeShape, n, "record member %s of %s is not an 8-bit array — `%s.copy(:%s)` copies %d bytes into a `[:u8, %d]` member", rf.Name, m.Record.Const, t, kf.Name, kf.Count, kf.Count)
		return Stmt{}, false
	case rf.Count != kf.Count:
		c.add(Rejected, SB033KernelTypeShape, n, "record member %s has %d elements but %s.%s has %d — the copy is a fixed N bytes, declare the same N", rf.Name, rf.Count, d.Const, kf.Name, kf.Count)
		return Stmt{}, false
	}
	return Stmt{Kind: "kcopy", Var: ref, Map: m, Field: rf, Path: kf.Name, PtrOf: t, PtrOfKT: d, Pos: c.z.pos(c.a, n)}, true
}

var nfTwinMembers = map[string]map[string]bool{"nf_hook_state": {"hook": true, "pf": true}, "sk_buff": {"len": true}}

func nfTwinCheck(res *Result) error {
	any := false
	for _, p := range res.Programs {
		any = any || p.Kind == "netfilter"
	}
	if !any {
		return nil
	}
	for _, d := range res.KernelTypes {
		ok, nf := nfTwinMembers[d.Name]
		if !nf {
			continue
		}
		for _, f := range d.Fields {
			if !ok[f.Name] {
				return fmt.Errorf("the twin harness cannot model %s.%s (%s) — a netfilter twin gives only nf_hook_state.hook / pf and sk_buff.len", d.Name, f.Name, d.Const)
			}
		}
	}
	return nil
}

func nfTwinRun(kw string, p *Program, kts []*KernelTypeDecl) string {
	var b strings.Builder
	fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_d = _h_hex(_h_f[2])\n        _h_hk = _h_f[3].to_i\n        _h_pf = _h_f[4].to_i\n        _h_len = _h_d.length\n", kw, p.Name)
	if !mutation("nf-len-l2") {
		b.WriteString("        if _h_hk != 3\n          _h_len = _h_d.length - 14\n        end\n")
	}
	vals := map[string]string{"hook": "_h_hk", "pf": "_h_pf", "len": "_h_len"}
	ptr := map[string]string{"nf_hook_state": "nil", "sk_buff": "nil"}
	for _, d := range kts {
		if _, nf := nfTwinMembers[d.Name]; !nf {
			continue
		}
		var vs []string
		for _, f := range d.Fields {
			vs = append(vs, vals[f.Name])
		}
		v := "_h_nf_" + strings.ReplaceAll(d.Name, "_", "")
		fmt.Fprintf(&b, "        %s = BPF::KPtr.new(%s.new(%s))\n", v, d.Const, strings.Join(vs, ", "))
		ptr[d.Name] = v
	}
	fmt.Fprintf(&b, "        puts \"ret=#{%s(BPF::NfCtx.new(%s, %s))}\"\n", p.Name, ptr["nf_hook_state"], ptr["sk_buff"])
	return b.String()
}

func (z *analyzer) embedCycle(c string, seen map[string]bool) string {
	var walk func(cur string, path []string) string
	walk = func(cur string, path []string) string {
		d := z.kts[cur]
		if d == nil || seen[cur] {
			return ""
		}
		seen[cur] = true
		defer delete(seen, cur)
		for _, f := range d.Fields {
			if f.Kind != "struct" {
				continue
			}
			next := append(append([]string(nil), path...), f.Ptr)
			if f.Ptr == c {
				return strings.Join(next, " -> ")
			}
			if r := walk(f.Ptr, next); r != "" {
				return r
			}
		}
		return ""
	}
	return walk(c, []string{c})
}

type schemaKStruct struct {
	Kind   string `json:"kind"`
	Struct string `json:"struct"`
}

func (c *progCtx) kpathRead(n *Node, p Pos) (*Expr, bool) {
	var segs []*Node
	cur := n
	for cur != nil && cur.Type == "CallNode" && cur.Str["name"] != "load" {
		if !memberLike(cur.Str["name"]) {
			return nil, false
		}
		segs = append([]*Node{cur}, segs...)
		cur = c.a.ref(cur, "receiver")
	}
	if cur == nil || cur.Type != "CallNode" || cur.Str["name"] != "load" || !c.isKptrRead(c.a.ref(cur, "receiver")) || len(segs) < 2 {
		return nil, false
	}
	t := c.a.ref(cur, "receiver").Str["name"]
	if cs, ok := c.callee(cur); !ok || cs != "KPtr#load" {
		if ok {
			c.add(Rejected, SB011ShadowedName, cur, "`load` resolves to %s, not BPF::KPtr#load", cs)
		}
		return nil, true
	}
	root := c.kptrs[t]
	if len(segs) > 3 {
		c.add(Rejected, SB033KernelTypeShape, n, "`%s.load` reads at most 3 members deep (a.b.c — bpf-mlir's kfield paths), got %d", t, len(segs))
		return nil, true
	}
	d := root
	var names []string
	for i, s := range segs {
		name := s.Str["name"]
		if len(args(c.a, s)) != 0 {
			c.add(Rejected, SB002UnsupportedCall, s, "a member read takes no arguments")
			return nil, true
		}
		f := d.field(name)
		if f == nil {
			c.add(Rejected, SB033KernelTypeShape, s, "%s (%s) declares no member `%s` — declare the members it reads in BPF.kernel_type", d.Const, d.Name, name)
			return nil, true
		}
		names = append(names, name)
		if i < len(segs)-1 {
			if f.Kind != "struct" {
				c.add(Rejected, SB033KernelTypeShape, s, "member %s of %s is not an embedded struct ([:struct, S]) — a member path goes only through embedded structs", name, d.Const)
				return nil, true
			}
			d = c.z.kts[f.Ptr]
			continue
		}
		if f.Kind != "int" {
			c.add(Rejected, SB033KernelTypeShape, s, "`%s.load.%s` reads an integer member only — %s is a %s member (pointers, byte arrays and strings through a member path are not accepted yet)", t, strings.Join(names, "."), name, f.Kind)
			return nil, true
		}
		rf := &RecordField{Name: strings.Join(names, "."), Bits: f.Bits, Signed: f.Signed}
		e := &Expr{Kind: "kfload", Var: t, Field: rf, Path: root.Name, Pos: p}
		if f.Bits == 64 && !f.Signed {
			e.Iv, e.Wide = iv(new(big.Int), new(big.Int).Set(u64Max)), true
		} else {
			e.Iv = widthRange(f.Bits, f.Signed)
		}
		return e, true
	}
	return nil, true
}

func twinEmbedKeys(byConst map[string]*KernelTypeDecl, c, pre string, q func(string)) {
	d := byConst[c]
	if d == nil {
		return
	}
	for _, f := range d.Fields {
		switch f.Kind {
		case "int":
			q(pre + "." + f.Name)
		case "struct":
			twinEmbedKeys(byConst, f.Ptr, pre+"."+f.Name, q)
		}
	}
}

func twinKStruct(byConst map[string]*KernelTypeDecl, c, pre string) string {
	d := byConst[c]
	if d == nil {
		return "nil"
	}
	var vs []string
	for _, f := range d.Fields {
		switch f.Kind {
		case "int":
			vs = append(vs, widthCut(fmt.Sprintf("_h_fv(_h_n, _h_v, %q)", pre+"."+f.Name), intTypeName(f.Bits, f.Signed)))
		case "struct":
			vs = append(vs, twinKStruct(byConst, f.Ptr, pre+"."+f.Name))
		case "kptr":
			vs = append(vs, "0")
		case "array":
			vs = append(vs, fmt.Sprintf("Array.new(%d, 0)", f.Count))
		case "strptr":
			vs = append(vs, "\"\"")
		}
	}
	return fmt.Sprintf("%s.new(%s)", d.Const, strings.Join(vs, ", "))
}

func (z *analyzer) embedSample(a *AST, x *Node, c string) bool {
	d := z.kts[c]
	if d == nil || x.Type != "CallNode" || x.Str["name"] != "new" || constName(a, a.ref(x, "receiver")) != c {
		return false
	}
	xs := args(a, x)
	if len(xs) != len(d.Fields) {
		return false
	}
	for i, y := range xs {
		f := d.Fields[i]
		switch f.Kind {
		case "struct":
			if !z.embedSample(a, y, f.Ptr) {
				return false
			}
		case "array":
			ya := args(a, y)
			if y.Type != "CallNode" || y.Str["name"] != "new" || constName(a, a.ref(y, "receiver")) != "Array" || len(ya) != 2 {
				return false
			}
			nb, ok1 := z.literal(a, ya[0])
			zero, ok2 := z.literal(a, ya[1])
			if !ok1 || !ok2 || !nb.IsInt64() || nb.Int64() != int64(f.Count) || zero.Sign() != 0 {
				return false
			}
		case "strptr":
			if y.Type != "StringNode" || y.Str["content"] != "" {
				return false
			}
		default:
			if y.Type != "IntegerNode" {
				return false
			}
			if lit, ok := z.literal(a, y); !ok || lit.Sign() != 0 {
				return false
			}
		}
	}
	return true
}

func (c *progCtx) kptrPathRecv(recv *Node) bool {
	segs := 0
	cur := recv
	for cur != nil && cur.Type == "CallNode" && cur.Str["name"] != "load" {
		if !memberLike(cur.Str["name"]) {
			return false
		}
		segs++
		cur = c.a.ref(cur, "receiver")
	}
	return segs >= 1 && cur != nil && cur.Type == "CallNode" && cur.Str["name"] == "load" && c.isKptrRead(c.a.ref(cur, "receiver"))
}
