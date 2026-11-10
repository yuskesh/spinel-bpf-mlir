package frontend

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type funcInfo struct {
	Name      string
	Def       *Node
	Params    []string
	Decl      int
	ArgIv     []Ival
	Path      []string
	Prog      *Program
	Bad       bool
	Called    bool
	BorrowIdx int
	BorrowMap *MapDecl
	WinIdx    int
	WinLen    int64
	CtxIdx    int
	CtxKind   string
	shapeErr  string
	W         map[int]map[string]bool
	RMaps     map[string]bool
	RParam    map[int]bool
}

type flowSrc struct {
	Maps   map[string]bool
	Params map[int]bool
	Rets   map[int]bool
}

type flow struct {
	Src  flowSrc
	Sink string
	Pos  Pos
	Path []string
}

type callSite struct {
	ID     int
	Caller string
	Callee *funcInfo
	Args   []flowSrc
	Pos    Pos
	Path   []string
}

type fnFlows struct {
	flows []flow
	sites []*callSite
}

func (z *analyzer) scanSubprograms(a *AST, defs map[string]*Node, roots []rootDecl) {
	z.funcs = map[string]*funcInfo{}
	z.flowsOf = map[string]*fnFlows{}
	z.siteByNode = map[int]*callSite{}
	isRoot := map[string]bool{}
	for _, r := range roots {
		isRoot[r.Name] = true
	}
	var names []string
	for name := range defs {
		if !isRoot[name] {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool { return defs[names[i]].ID < defs[names[j]].ID })
	for i, name := range names {
		d := defs[name]
		fi := &funcInfo{Name: name, Def: d, Decl: i, BorrowIdx: -1, WinIdx: -1, CtxIdx: -1, W: map[int]map[string]bool{}, RMaps: map[string]bool{}, RParam: map[int]bool{}}
		pn := a.ref(d, "parameters")
		if pn != nil {
			for _, k := range []string{"optionals", "keywords"} {
				if len(a.arr(pn, k)) > 0 {
					fi.shapeErr = fmt.Sprintf("the eBPF-side function `%s` takes only required positional Integer arguments (no optional or keyword arguments)", name)
				}
			}
			for _, k := range []string{"rest", "keyword_rest", "block"} {
				if a.ref(pn, k) != nil {
					fi.shapeErr = fmt.Sprintf("the eBPF-side function `%s` takes only required positional Integer arguments (no rest, keyword-rest or block argument)", name)
				}
			}
			for _, p := range a.arr(pn, "requireds") {
				fi.Params = append(fi.Params, p.Str["name"])
			}
		}
		if len(fi.Params) > 5 && fi.shapeErr == "" {
			fi.shapeErr = fmt.Sprintf("the eBPF-side function `%s` takes %d arguments — a BPF subprogram takes at most 5", name, len(fi.Params))
		}
		z.funcs[name] = fi
	}
}

func (z *analyzer) userCall(a *AST, n *Node) *funcInfo {
	if n == nil || n.Type != "CallNode" || a.ref(n, "receiver") != nil {
		return nil
	}
	return z.funcs[n.Str["name"]]
}

func (z *analyzer) callGraph(a *AST, defs map[string]*Node, roots []rootDecl) []*funcInfo {
	callees := map[string][]string{}
	edgeFrom := func(name string) []string {
		if v, ok := callees[name]; ok {
			return v
		}
		seen := map[string]bool{}
		var out []string
		if d := defs[name]; d != nil {
			walk(a, d, func(x *Node) bool {
				if fi := z.userCall(a, x); fi != nil && !seen[fi.Name] {
					seen[fi.Name] = true
					out = append(out, fi.Name)
				}
				return true
			})
		}
		callees[name] = out
		return out
	}
	state := map[string]int{}
	var stack []string
	reported := map[string]bool{}
	var dfs func(string)
	dfs = func(n string) {
		state[n] = 1
		stack = append(stack, n)
		for _, m := range edgeFrom(n) {
			switch state[m] {
			case 0:
				z.funcs[m].Path = append(append([]string{}, stack...), m)
				dfs(m)
			case 1:
				i := 0
				for k, s := range stack {
					if s == m {
						i = k
					}
				}
				cyc := append(append([]string{}, stack[i:]...), m)
				if !reported[m] {
					reported[m] = true
					d := defs[m]
					z.diags = append(z.diags, Diag{Verdict: Rejected, Code: SB035Recursion, Pos: z.pos(a, d), Path: append([]string{}, stack...),
						Msg: fmt.Sprintf("recursion is not accepted on the eBPF side: %s (BPF subprograms are non-recursive)", strings.Join(cyc, " → "))})
				}
				for _, s := range cyc {
					if fi := z.funcs[s]; fi != nil {
						fi.Bad = true
					}
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[n] = 2
	}
	for _, r := range roots {
		if state[r.Name] == 0 {
			dfs(r.Name)
		}
	}
	indeg := map[string]int{}
	reach := map[string]bool{}
	for n := range state {
		if z.funcs[n] != nil {
			reach[n] = true
		}
	}
	for n := range state {
		for _, m := range edgeFrom(n) {
			if reach[m] {
				indeg[m]++
			}
		}
	}
	var ready []*funcInfo
	for _, r := range roots {
		for _, m := range edgeFrom(r.Name) {
			indeg[m]--
		}
	}
	for n := range reach {
		if indeg[n] == 0 {
			ready = append(ready, z.funcs[n])
		}
	}
	var order []*funcInfo
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return ready[i].Decl < ready[j].Decl })
		f := ready[0]
		ready = ready[1:]
		order = append(order, f)
		for _, m := range edgeFrom(f.Name) {
			indeg[m]--
			if indeg[m] == 0 {
				ready = append(ready, z.funcs[m])
			}
		}
	}
	for n := range reach {
		fi := z.funcs[n]
		if rec, cnt := z.typing.Types.TypeOf(a, fi.Def); !fi.Bad && fi.shapeErr == "" && cnt == 1 && !integerSig(rec.Signature) {
			hint := sigHint(rec.Signature)
			if strings.HasSuffix(rec.Signature, "-> untyped") {
				hint = "; if the last expression is arithmetic on a record member, assign it to a local first (`x = r.load.m & 0xFF` then `x`)"
			}
			fi.shapeErr = fmt.Sprintf("Spinel types the eBPF-side function `%s` as %s — its arguments and its value must be Integer (no true / false, nil or other types)%s", fi.Name, rec.Signature, hint)
		}
		if fi.shapeErr != "" {
			z.add(Rejected, SB034SubprogramShape, z.pos(a, fi.Def), "%s", fi.shapeErr)
			fi.Bad = true
		}
	}
	for _, fi := range z.funcs {
		if fi.Bad {
			z.anyBadFunc = true
		}
	}
	return order
}

func (c *progCtx) fn() *fnFlows {
	f := c.z.flowsOf[c.name]
	if f == nil {
		f = &fnFlows{}
		c.z.flowsOf[c.name] = f
	}
	return f
}

func (c *progCtx) resolveSrc(n *Node) flowSrc {
	s := flowSrc{Maps: map[string]bool{}, Params: map[int]bool{}, Rets: map[int]bool{}}
	for r := range c.derivedRefs(n) {
		switch {
		case strings.HasPrefix(r, "@p"):
			i, _ := strconv.Atoi(r[2:])
			s.Params[i] = true
		case strings.HasPrefix(r, "@r"):
			i, _ := strconv.Atoi(r[2:])
			s.Rets[i] = true
		case strings.HasPrefix(r, "@g"):
			s.Maps["g:"+r[2:]] = true
		case c.refMap[r] != nil:
			s.Maps["m:"+c.refMap[r].Name] = true
		}
	}
	return s
}

func (c *progCtx) noteFlow(val *Node, m *MapDecl, at *Node) {
	k := ""
	if m != nil {
		k = "m:" + m.Name
	}
	c.noteFlowKey(val, k, at)
}

func (c *progCtx) noteFlowKey(val *Node, k string, at *Node) {
	if val == nil || c.z.flowsOf == nil {
		return
	}
	c.fn().flows = append(c.fn().flows, flow{Src: c.resolveSrc(val), Sink: k, Pos: c.z.pos(c.a, at), Path: c.path()})
}

func (c *progCtx) path() []string {
	if c.fpath != nil {
		return c.fpath
	}
	return []string{c.name}
}

func (c *progCtx) subCall(n *Node, fi *funcInfo, refVar string) *Expr {
	if fi.Bad {
		return nil
	}
	callee, ok := c.callee(n)
	if !ok {
		return nil
	}
	if callee != fi.Name {
		c.add(Rejected, SB011ShadowedName, n, "`%s` resolves to %q, not the top-level def %s", fi.Name, callee, fi.Name)
		return nil
	}
	if c.a.ref(n, "block") != nil {
		c.add(Rejected, SB034SubprogramShape, n, "a call of the eBPF-side function `%s` takes no block", fi.Name)
		return nil
	}
	as := args(c.a, n)
	if len(as) != len(fi.Params) {
		c.add(Rejected, SB034SubprogramShape, n, "`%s` takes %d arguments, called with %d", fi.Name, len(fi.Params), len(as))
		return nil
	}
	e := &Expr{Kind: "call", Var: fi.Name, Iv: fullI64, Pos: c.z.pos(c.a, n)}
	var srcs []flowSrc
	borrows := 0
	special := 0
	for i, x := range as {
		if x.Type == "LocalVariableReadNode" && (c.refs[x.Str["name"]] != nil || c.wins[x.Str["name"]] != nil || (c.param != "" && x.Str["name"] == c.param)) {
			special++
			if special > 1 {
				c.add(Rejected, SB034SubprogramShape, x, "`%s` takes at most one argument that is not an Integer (a borrowed map value, a checked packet window or the context)", fi.Name)
				return nil
			}
		}
		if x.Type == "LocalVariableReadNode" && c.wins[x.Str["name"]] != nil {
			wn := x.Str["name"]
			n := c.wins[wn].len
			switch {
			case c.prog.Kind == "func" && c.winParam(wn):
				c.add(Rejected, SB034SubprogramShape, x, "the window argument `%s` is not forwarded to another eBPF-side function in this stage — read it here", wn)
				return nil
			case fi.WinIdx >= 0 && (fi.WinIdx != i || fi.WinLen != n):
				c.add(Rejected, SB034SubprogramShape, x, "`%s` is called with a %d-byte window as argument %d, but another call passes a %d-byte window as argument %d — every call passes the same window length in the same place", fi.Name, n, i+1, fi.WinLen, fi.WinIdx+1)
				return nil
			}
			fi.WinIdx, fi.WinLen = i, n
			e.Args = append(e.Args, &Expr{Kind: "winarg", Ref: wn, Len: n, Pos: c.z.pos(c.a, x)})
			srcs = append(srcs, flowSrc{Maps: map[string]bool{}, Params: map[int]bool{}, Rets: map[int]bool{}})
			continue
		}
		if c.param != "" && c.isVarRead(x, c.param) {
			k := c.ctxKindOf()
			switch {
			case c.prog.Kind == "func":
				c.add(Rejected, SB034SubprogramShape, x, "the context argument `%s` is not forwarded to another eBPF-side function in this stage — check the packet here", c.param)
				return nil
			case !hasPacket(k) || k == "cgroup_skb":
				c.add(Rejected, SB034SubprogramShape, x, "the %s context is not passed to an eBPF-side function — its reads depend on the attach point; read the values in the program and pass Integers", k)
				return nil
			case fi.CtxIdx >= 0 && (fi.CtxIdx != i || fi.CtxKind != k):
				c.add(Rejected, SB034SubprogramShape, x, "`%s` is called with the %s context as argument %d, but another call passes the %s context as argument %d — one function takes one kind of context in one place", fi.Name, k, i+1, fi.CtxKind, fi.CtxIdx+1)
				return nil
			}
			fi.CtxIdx, fi.CtxKind = i, k
			e.Args = append(e.Args, &Expr{Kind: "ctxarg", Var: k, Pos: c.z.pos(c.a, x)})
			srcs = append(srcs, flowSrc{Maps: map[string]bool{}, Params: map[int]bool{}, Rets: map[int]bool{}})
			continue
		}
		if x.Type == "LocalVariableReadNode" && c.refs[x.Str["name"]] != nil {
			ref := x.Str["name"]
			m := c.refMap[ref]
			borrows++
			switch {
			case c.prog.Kind == "func" && c.borrowParam(ref):
				c.add(Rejected, SB034SubprogramShape, x, "the borrowed argument `%s` is not forwarded to another eBPF-side function in this stage — do the access here", ref)
				return nil
			case borrows > 1:
				c.add(Rejected, SB034SubprogramShape, x, "`%s` takes at most one borrowed map value", fi.Name)
				return nil
			case fi.BorrowIdx >= 0 && (fi.BorrowIdx != i || fi.BorrowMap != m):
				c.add(Rejected, SB034SubprogramShape, x, "`%s` is called with a borrowed value of %s as argument %d, but another call passes %s as argument %d — every call passes the same map value in the same place", fi.Name, m.Name, i+1, fi.BorrowMap.Name, fi.BorrowIdx+1)
				return nil
			}
			fi.BorrowIdx, fi.BorrowMap = i, m
			e.Args = append(e.Args, &Expr{Kind: "refarg", Ref: ref, Map: m, Pos: c.z.pos(c.a, x)})
			srcs = append(srcs, flowSrc{Maps: map[string]bool{}, Params: map[int]bool{}, Rets: map[int]bool{}})
			continue
		}
		v := c.expr(x, refVar)
		if v == nil {
			return nil
		}
		if v.Bool {
			c.add(Rejected, SB034SubprogramShape, x, "argument %d of `%s` is true / false — an eBPF-side function takes Integer arguments", i+1, fi.Name)
			return nil
		}
		if v.Wide {
			c.add(Rejected, SB014SemanticGap, x, "argument %d of `%s` is a u64 value %s that does not fit Ruby's Integer — narrow it first (`x & M` or `x >> K`)", i+1, fi.Name, v.Iv)
			return nil
		}
		e.Args = append(e.Args, v)
		srcs = append(srcs, c.resolveSrc(x))
	}
	for i, v := range e.Args {
		if v.Kind == "refarg" || v.Kind == "winarg" || v.Kind == "ctxarg" {
			continue
		}
		if len(fi.ArgIv) == 0 {
			fi.ArgIv = make([]Ival, len(fi.Params))
		}
		if fi.ArgIv[i].Lo == nil {
			fi.ArgIv[i] = v.Iv
		} else {
			fi.ArgIv[i] = union(fi.ArgIv[i], v.Iv)
		}
	}
	fi.Called = true
	s := &callSite{ID: n.ID, Caller: c.name, Callee: fi, Args: srcs, Pos: c.z.pos(c.a, n), Path: c.path()}
	c.fn().sites = append(c.fn().sites, s)
	c.z.siteByNode[n.ID] = s
	return e
}

func (z *analyzer) function(a *AST, fi *funcInfo) *Program {
	d := fi.Def
	c := &progCtx{z: z, a: a, t: z.typing.Types, def: d, name: fi.Name, fpath: fi.Path, refs: map[string]*Node{}, statusReported: map[string]bool{}, refMap: map[string]*MapDecl{}, refKey: map[string]*Expr{}, wins: map[string]*winInfo{},
		used: map[*MapDecl]bool{}, usedGlobals: map[*GlobalDecl]bool{}, usedRings: map[*RingDecl]bool{}, badBind: map[string]bool{}, ostrs: map[string]bool{}, ostrLive: map[string]bool{}, kptrs: map[string]*KernelTypeDecl{}, kchecked: map[string]bool{}, poisoned: map[string]bool{}, skipIfs: map[int]bool{}, env: map[string]*varInfo{}, blockLocals: map[string]bool{}}
	c.prog = &Program{Name: fi.Name, Kind: "func", Pos: z.pos(a, d), EndLine: d.EndLine, FParams: fi.Params, FBorrow: fi.BorrowIdx, FBorrowMap: fi.BorrowMap, FWin: fi.WinIdx, FWinLen: fi.WinLen, FCtx: fi.CtxIdx, FCtxKind: fi.CtxKind}
	before := len(z.diags)
	bad := false
	walk(a, d, func(x *Node) bool {
		if bad {
			return false
		}
		switch {
		case x.Type == "ReturnNode":
			c.add(Rejected, SB034SubprogramShape, x, "`return` is not accepted in the eBPF-side function `%s` — its last expression is its value (use if / else)", fi.Name)
			bad = true
		case x.Type == "ConstantPathNode" && verdictKindOf(constName(a, x)) != "":
			c.add(Rejected, SB034SubprogramShape, x, "%s is a program verdict — an eBPF-side function returns an Integer; return the verdict from the program", constName(a, x))
			bad = true
		}
		return !bad
	})
	if bad {
		return nil
	}
	refVar := ""
	for i, p := range fi.Params {
		if i == fi.WinIdx {
			c.wins[p] = &winInfo{len: fi.WinLen, active: true}
			continue
		}
		if i == fi.CtxIdx {
			c.param, c.ctxKind = p, fi.CtxKind
			continue
		}
		if i == fi.BorrowIdx {
			c.refs[p] = a.arr(a.ref(d, "parameters"), "requireds")[i]
			c.refMap[p] = fi.BorrowMap
			c.refKey[p] = nil
			refVar = p
			continue
		}
		iv := fullI64
		if i < len(fi.ArgIv) && fi.ArgIv[i].Lo != nil {
			iv = fi.ArgIv[i]
		}
		c.env[p] = &varInfo{Iv: iv, From: map[string]bool{fmt.Sprintf("@p%d", i): true}}
	}
	body := a.ref(d, "body")
	var stmts []*Node
	if body != nil {
		if body.Type != "StatementsNode" {
			c.add(Rejected, SB034SubprogramShape, body, "the body of the eBPF-side function `%s` must be a plain sequence of statements (no rescue / ensure)", fi.Name)
			return nil
		}
		stmts = a.arr(body, "body")
	}
	if len(stmts) == 0 {
		c.add(Rejected, SB034SubprogramShape, d, "the eBPF-side function `%s` must end with an Integer expression (its value)", fi.Name)
		return nil
	}
	last := stmts[len(stmts)-1]
	switch last.Type {
	case "LocalVariableWriteNode", "IfNode", "UnlessNode", "WhileNode", "UntilNode", "CaseNode", "MultiWriteNode", "LocalVariableOperatorWriteNode":
		c.add(Rejected, SB034SubprogramShape, last, "the last statement of the eBPF-side function `%s` must be an Integer expression (its value), not %s", fi.Name, last.Type)
		return nil
	}
	if last.Type == "CallNode" && c.isStmtOnlyCall(last) {
		c.add(Rejected, SB034SubprogramShape, last, "the last statement of the eBPF-side function `%s` must be an Integer expression (its value), not the map / global call `%s`", fi.Name, last.Str["name"])
		return nil
	}
	c.prog.Body = c.stmts(stmts[:len(stmts)-1], refVar)
	ret := c.expr(last, refVar)
	if ret == nil {
		return nil
	}
	if ret.Bool {
		c.add(Rejected, SB034SubprogramShape, last, "the eBPF-side function `%s` returns true / false — it returns an Integer", fi.Name)
		return nil
	}
	if ret.Wide {
		c.add(Rejected, SB014SemanticGap, last, "the eBPF-side function `%s` returns a u64 value that does not fit Ruby's Integer — narrow it first (`x & M` or `x >> K`)", fi.Name)
		return nil
	}
	c.prog.FRet = ret
	c.prog.VerdictPos = c.z.pos(a, last)
	c.noteFlow(last, nil, last)
	for _, m := range z.mapOrder {
		if c.used[m] {
			c.prog.Maps = append(c.prog.Maps, m)
		}
	}
	for _, r := range z.ringOrder {
		if c.usedRings[r] {
			c.prog.Rings = append(c.prog.Rings, r)
		}
	}
	for _, g := range z.globalOrder {
		if c.usedGlobals[g] {
			c.prog.Globals = append(c.prog.Globals, g)
		}
	}
	if len(z.diags) > before && z.diags[before:].Blocking() {
		return nil
	}
	return c.prog
}

func (c *progCtx) isStmtOnlyCall(n *Node) bool {
	r := c.a.ref(n, "receiver")
	if r == nil || r.Type != "ConstantReadNode" {
		return false
	}
	name := n.Str["name"]
	if c.z.maps[r.Str["name"]] != nil && (name == "update" || name == "atomic_add") {
		return true
	}
	return c.z.globals[r.Str["name"]] != nil && name == "add"
}

func (z *analyzer) resolveSubprograms(order []*funcInfo, programs []*Program) {
	if z.flowsOf == nil {
		return
	}
	noSummary := mutation("no-summary")
	reported := map[string]bool{}
	report := func(p Pos, path []string, msg string) {
		k := p.String() + msg
		if reported[k] {
			return
		}
		reported[k] = true
		z.diags = append(z.diags, Diag{Verdict: Rejected, Code: SB019SharedReadModifyWrite, Pos: p, Path: path, Msg: msg})
	}
	var sitesByID = map[int]*callSite{}
	for _, f := range z.flowsOf {
		for _, s := range f.sites {
			sitesByID[s.ID] = s
		}
	}
	var expand func(src flowSrc, depth int) (map[string]bool, map[int]bool, map[string]bool)
	expand = func(src flowSrc, depth int) (map[string]bool, map[int]bool, map[string]bool) {
		maps, params, viaRet := map[string]bool{}, map[int]bool{}, map[string]bool{}
		for m := range src.Maps {
			maps[m] = true
		}
		for p := range src.Params {
			params[p] = true
		}
		if noSummary || depth > 16 {
			return maps, params, viaRet
		}
		for id := range src.Rets {
			s := sitesByID[id]
			if s == nil {
				continue
			}
			g := s.Callee
			for m := range g.RMaps {
				maps[m], viaRet[m] = true, true
			}
			for j := range g.RParam {
				if j < len(s.Args) {
					m2, p2, v2 := expand(s.Args[j], depth+1)
					for m := range m2 {
						maps[m], viaRet[m] = true, true
					}
					for p := range p2 {
						params[p] = true
					}
					for m := range v2 {
						viaRet[m] = true
					}
				}
			}
		}
		return maps, params, viaRet
	}
	byName := map[string]*MapDecl{}
	for _, m := range z.mapOrder {
		byName[m.Name] = m
	}
	exempt := func(k string) bool { return strings.HasPrefix(k, "m:") && perCPUExempt(byName[k[2:]], z.rootKinds) }
	objName := func(k string) string {
		if strings.HasPrefix(k, "g:") {
			return "Counter " + k[2:]
		}
		return k[2:]
	}
	process := func(name string, fi *funcInfo) {
		f := z.flowsOf[name]
		if f == nil {
			return
		}
		for _, s := range f.sites {
			g := s.Callee
			if noSummary {
				continue
			}
			for j, a := range s.Args {
				maps, params, _ := expand(a, 0)
				for m := range g.W[j] {
					if maps[m] && !exempt(m) {
						report(s.Pos, s.Path, fmt.Sprintf("`%s(…)` argument %d carries a value read from %s, and `%s` writes %s — concurrent CPUs lose updates across the call; use atomic_add on the entry with a delta that does not read it", g.Name, j+1, objName(m), g.Name, objName(m)))
					}
					if fi != nil {
						for p := range params {
							if fi.W[p] == nil {
								fi.W[p] = map[string]bool{}
							}
							fi.W[p][m] = true
						}
					}
				}
			}
		}
		for _, fl := range f.flows {
			maps, params, viaRet := expand(fl.Src, 0)
			if fl.Sink == "" {
				if fi != nil {
					for m := range maps {
						fi.RMaps[m] = true
					}
					for p := range params {
						fi.RParam[p] = true
					}
				}
				continue
			}
			if viaRet[fl.Sink] && !exempt(fl.Sink) {
				report(fl.Pos, fl.Path, fmt.Sprintf("the value written to %s comes from an eBPF-side function that reads %s — concurrent CPUs lose updates across the call; use atomic_add on the entry with a delta that does not read it", objName(fl.Sink), objName(fl.Sink)))
			}
			if fi != nil {
				for p := range params {
					if fi.W[p] == nil {
						fi.W[p] = map[string]bool{}
					}
					fi.W[p][fl.Sink] = true
				}
			}
		}
	}
	for i := len(order) - 1; i >= 0; i-- {
		process(order[i].Name, order[i])
	}
	for _, p := range programs {
		process(p.Name, nil)
	}
}

func withFuncs(res *Result) []*Program {
	return append(append([]*Program{}, res.Programs...), res.Funcs...)
}

func integerSig(sig string) bool {
	if sig == "" {
		return true
	}
	i, j := strings.Index(sig, "("), strings.Index(sig, ") -> ")
	if i != 0 || j < 0 {
		return false
	}
	if inner := sig[1:j]; inner != "" {
		refs := 0
		for _, p := range strings.Split(inner, ", ") {
			if p == "MapRef" || p == "RecordRef" || p == "Window" || p == "XdpMd" || p == "SkBuff" {
				refs++
				continue
			}
			if p != "Integer" {
				return false
			}
		}
		if refs > 1 {
			return false
		}
	}
	return sig[j+5:] == "Integer"
}

func (c *progCtx) callsBadFunc(n *Node) bool {
	if !c.z.anyBadFunc {
		return false
	}
	bad := false
	walk(c.a, n, func(x *Node) bool {
		if fi := c.z.userCall(c.a, x); fi != nil && fi.Bad {
			bad = true
		}
		return !bad
	})
	return bad
}

func (c *progCtx) ringPath(f *funcInfo, seen map[string]bool) []string {
	if seen[f.Name] {
		return nil
	}
	seen[f.Name] = true
	var out []string
	walk(c.a, f.Def, func(x *Node) bool {
		if out != nil {
			return false
		}
		if c.isOutput(x) || c.isOutputStr(x) {
			out = []string{f.Name, c.a.ref(x, "receiver").Str["name"] + "." + x.Str["name"]}
			return false
		}
		if g := c.z.userCall(c.a, x); g != nil {
			if p := c.ringPath(g, seen); p != nil {
				out = append([]string{f.Name}, p...)
				return false
			}
		}
		return true
	})
	return out
}

func (c *progCtx) borrowParam(ref string) bool {
	fi := c.z.funcs[c.name]
	return fi != nil && fi.BorrowIdx >= 0 && fi.BorrowIdx < len(fi.Params) && fi.Params[fi.BorrowIdx] == ref
}

func (c *progCtx) borrowArgUse(x *Node) bool {
	p := c.a.node(c.a.Parent[x.ID])
	if p == nil || p.Type != "ArgumentsNode" {
		return false
	}
	return c.z.userCall(c.a, c.a.node(c.a.Parent[p.ID])) != nil
}

func (c *progCtx) winParam(wn string) bool {
	fi := c.z.funcs[c.name]
	return fi != nil && fi.WinIdx >= 0 && fi.WinIdx < len(fi.Params) && fi.Params[fi.WinIdx] == wn
}

func (c *progCtx) ctxKindOf() string {
	if c.prog != nil && c.prog.Kind == "func" {
		if c.ctxKind != "" {
			return c.ctxKind
		}
		return "func"
	}
	if c.prog == nil {
		return ""
	}
	return c.prog.Kind
}

func sigHint(sig string) string {
	j := strings.Index(sig, ") -> ")
	if !strings.HasPrefix(sig, "(") || j < 0 {
		return ""
	}
	special, tracing, untyped := 0, "", false
	for _, p := range strings.Split(sig[1:j], ", ") {
		switch p {
		case "MapRef", "RecordRef", "Window", "XdpMd", "SkBuff":
			special++
		case "FentryCtx", "FexitCtx", "KprobeCtx", "UprobeCtx", "TpBtfCtx", "KretprobeCtx", "UretprobeCtx", "RawTpCtx", "SocketFilterCtx", "TracepointCtx", "KsyscallCtx":
			tracing = p
		case "untyped":
			untyped = true
		}
	}
	switch {
	case tracing != "":
		return fmt.Sprintf("; the %s context is not passed to an eBPF-side function — its reads depend on the attach point: read the values in the program and pass Integers", tracing)
	case special > 1:
		return "; a function takes at most one argument that is not an Integer (a borrowed map value, a checked packet window or a packet context)"
	case untyped:
		return "; an argument has different types at different calls (for example the xdp and the sched_cls context, or a window and an Integer) — pass one type in one place"
	}
	return ""
}
