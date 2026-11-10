package frontend

import (
	"regexp"
	"strings"
)

type TpField struct {
	Name   string
	Offset int64
	Type   string
	N      int
}

var tpIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const tpMaxCtx = 8192

const tracepointShape = "`BPF.tracepoint :name, \"category/event\", fields: {name => [offset, :type], …}`"

func (z *analyzer) tracepointDecl(a *AST, n *Node, as []*Node, bad func(string, ...any) (rootDecl, bool)) (rootDecl, bool) {
	if len(as) != 3 || as[0].Type != "SymbolNode" || as[1].Type != "StringNode" || as[2].Type != "KeywordHashNode" {
		return bad("a tracepoint program is declared as %s — the event's fields it reads, with the offset and type from the tracefs format", tracepointShape)
	}
	tp := as[1].Str["content"]
	cat, ev, _ := strings.Cut(tp, "/")
	if strings.Count(tp, "/") != 1 || !tpIdent.MatchString(cat) || !tpIdent.MatchString(ev) {
		return bad("the target of %s is a tracefs event `category/event` (two C identifiers and one `/`), got %q", tracepointShape, tp)
	}
	var hv *Node
	for _, e := range a.arr(as[2], "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || k.Type != "SymbolNode" || k.Str["value"] != "fields" || hv != nil {
			return bad("the options of %s are exactly `fields:`", tracepointShape)
		}
		hv = v
	}
	if hv == nil || hv.Type != "HashNode" || len(a.arr(hv, "elements")) == 0 {
		return bad("%s needs `fields:` with a non-empty Hash literal of field name => [offset, :type]", tracepointShape)
	}
	r := rootDecl{Name: as[0].Str["value"], Kind: "tracepoint", Pos: z.pos(a, n), Target: tp}
	seenN, seenO := map[string]bool{}, map[int64]bool{}
	for _, e := range a.arr(hv, "elements") {
		k, v := a.ref(e, "key"), a.ref(e, "value")
		if e.Type != "AssocNode" || k == nil || k.Type != "SymbolNode" || v == nil || v.Type != "ArrayNode" {
			return bad("each tracepoint field is `name: [offset, :type]` — a Symbol name and a two-element Array literal")
		}
		name := k.Str["value"]
		els := a.arr(v, "elements")
		if len(els) == 2 && els[0].Type == "IntegerNode" && els[1].Type == "ArrayNode" {
			f, ok := z.tpArrayField(a, name, els, bad)
			if !ok {
				return rootDecl{}, false
			}
			if !tpIdent.MatchString(name) || seenN[name] || seenO[f.Offset] {
				return bad("field %s at offset %d: field names are C identifiers and neither a name nor an offset appears twice", name, f.Offset)
			}
			seenN[name], seenO[f.Offset] = true, true
			r.TFields = append(r.TFields, f)
			continue
		}
		if len(els) != 2 || els[0].Type != "IntegerNode" || els[1].Type != "SymbolNode" {
			return bad("field %s: write `%s: [offset, :type]` — an Integer literal offset and a type Symbol :i8 … :u64", name, name)
		}
		t := els[1].Str["value"]
		rt, ok := recordTypes[t]
		if t == "user_str" || t == "user_str_array" {
			rt, ok = [2]int{64, 0}, true
		}
		if !ok {
			return bad("field %s: the type is one of :i8 … :i64 / :u8 … :u64 (the format's size and signed) or :user_str (a `char *` field — read with ctx.str_field), got :%s", name, t)
		}
		nb, ok := z.literal(a, els[0])
		w := int64(rt[0] / 8)
		if !ok || !nb.IsInt64() || nb.Int64() < 8 || nb.Int64()%w != 0 || nb.Int64()+w > tpMaxCtx {
			return bad("field %s: the offset is an Integer ≥ 8 (the first 8 bytes are not readable from BPF), a multiple of the field's %d bytes, and offset + size ≤ %d", name, w, tpMaxCtx)
		}
		o := nb.Int64()
		if !tpIdent.MatchString(name) || seenN[name] || seenO[o] {
			return bad("field %s at offset %d: field names are C identifiers and neither a name nor an offset appears twice", name, o)
		}
		seenN[name], seenO[o] = true, true
		if mutation("tpfield-shift") && name == "fd" {
			o += 8
		}
		r.TFields = append(r.TFields, TpField{Name: name, Offset: o, Type: t})
	}
	return r, true
}

func (z *analyzer) tpArrayField(a *AST, name string, els []*Node, bad func(string, ...any) (rootDecl, bool)) (TpField, bool) {
	ae := a.arr(els[1], "elements")
	if len(ae) != 2 || ae[0].Type != "SymbolNode" || ae[1].Type != "IntegerNode" || (ae[0].Str["value"] != "u8" && ae[0].Str["value"] != "i8") {
		bad("field %s: a byte array is `%s: [offset, [:u8, N]]` (or :i8) with an Integer literal N of 1..64 — the tracefs format's `__u8 %s[N]`", name, name, name)
		return TpField{}, false
	}
	nb, ok := z.literal(a, ae[1])
	if !ok || !nb.IsInt64() || nb.Int64() < 1 || nb.Int64() > 64 {
		bad("field %s: a byte array is `%s: [offset, [:u8, N]]` (or :i8) with an Integer literal N of 1..64 — the tracefs format's `__u8 %s[N]`", name, name, name)
		return TpField{}, false
	}
	n := nb.Int64()
	ob, ok := z.literal(a, els[0])
	if !ok || !ob.IsInt64() || ob.Int64() < 8 || ob.Int64()+n > tpMaxCtx {
		bad("field %s: the offset is an Integer ≥ 8 (the first 8 bytes are not readable from BPF) and offset + %d ≤ %d", name, n, tpMaxCtx)
		return TpField{}, false
	}
	return TpField{Name: name, Offset: ob.Int64(), Type: ae[0].Str["value"], N: int(n)}, true
}
