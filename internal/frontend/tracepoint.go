package frontend

import (
	"regexp"
	"strings"
)

// Tracepoint programs: `BPF.tracepoint :name, "category/event", fields: {name => [offset, :type], …}`. The author copies each field's
// offset and type from tracefs's `events/<category>/<event>/format` (they change with the kernel version — before load, bpf-mlir
// checks the requirements tpfield lines against the target's tracefs and stops on a mismatch and when it cannot decide). The frontend
// only checks the shape of the declaration (the rules for fields in bpf-mlir's schema).

// TpField is a field declared by a tracepoint program (name, byte offset from the start of the record, and type Symbol :u8 … :i64).
type TpField struct {
	Name   string
	Offset int64
	Type   string
	// N is the element count of a fixed-size byte array (`[off, [:u8, N]]`; Type is u8 / i8; 0 means not an array). ctx.copy(:f)
	// copies it into an array member of a record (bpf-mlir's tp.field.copy)
	N int
}

var tpIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// tpMaxCtx is the size limit of a tracepoint's ctx (bpf-mlir's kTracepointMaxCtx — the kernel's PERF_MAX_TRACE_SIZE).
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
		if len(els) == 2 && els[0].Type == "IntegerNode" && els[1].Type == "ArrayNode" { // a fixed-size byte array `[off, [:u8, N]]`
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
		if t == "user_str" || t == "user_str_array" { // a char * field — an 8-byte user pointer (into output_str through ctx.str_field(:f)); a char ** (argv — into output_argv through ctx.argv_field(:f))
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
		if mutation("tpfield-shift") && name == "fd" { // mutation: add 8 to both the declared and the read offset of fd (an error on which the schema and the op agree)
			o += 8
		}
		r.TFields = append(r.TFields, TpField{Name: name, Offset: o, Type: t})
	}
	return r, true
}

// tpArrayField reads `name: [off, [:u8, N]]` (bpf-mlir's schema `{kind: array, elem: u8|i8, n: N}`): elem is :u8 / :i8, N is a
// literal 1..64, and offset is a literal ≥ 8 (alignment 1 — the array has byte width) with offset + N ≤ 8192.
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
