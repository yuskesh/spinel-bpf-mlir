package frontend

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// This file reads the JSON that Spinel's `--emit-types` writes (third_party/spinel/docs/emit-types.md) and joins its records to
// the AST's nodes. The JSON carries no node id, so a record is matched by the key (file, line, col, end_line, end_col, kind).
// Two or more records under one key make the match ambiguous (SB015); no record means the node has no type (unknown and void
// are not written to the JSON — the two are not told apart, and both stop the compile).

// TypeRec is one record of the types list.
type TypeRec struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Col       int    `json:"col"`
	EndLine   int    `json:"end_line"`
	EndCol    int    `json:"end_col"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	RBS       string `json:"rbs"`
	Owner     string `json:"owner"`
	Signature string `json:"signature"`
	Singleton bool   `json:"singleton"`
	Widened   bool   `json:"widened"`
}

// CodegenRec is one record of the codegen list (how a call is dispatched and what it calls).
type CodegenRec struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Col        int      `json:"col"`
	EndLine    int      `json:"end_line"`
	EndCol     int      `json:"end_col"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Dispatch   string   `json:"dispatch"`
	Callee     string   `json:"callee"`
	Candidates []string `json:"candidates"`
	Inlined    *bool    `json:"inlined"`
}

// DiagRec is one Spinel diagnostic (a widening warning or a rejection error).
type DiagRec struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Severity string `json:"severity"`
	Method   string `json:"method"`
	Slot     string `json:"slot"`
	Param    string `json:"param"`
	Message  string `json:"message"`
}

// Types is the JSON as read.
type Types struct {
	Types       []TypeRec    `json:"types"`
	Diagnostics []DiagRec    `json:"diagnostics"`
	Codegen     []CodegenRec `json:"codegen"`

	byKey   map[spanKey][]int
	cgByKey map[spanKey][]int
}

type spanKey struct {
	File                       string
	Line, Col, EndLine, EndCol int
	Kind                       string
}

// ParseTypes reads the JSON and builds the key index. Unknown fields are ignored (so fields Spinel adds later do not break it),
// but a record missing its required shape is an error. The whole document is first checked under the rules of
// requirements.DecodeStrictJSON (duplicate keys, nul, invalid UTF-8, trailing bytes, depth), so a duplicate key is not silently
// read as its last value.
//
// A type record without an end (end_line and end_col both absent) is always refused here; only the AST-bound
// ParseTypesWithAST may accept one (a block parameter Spinel renamed).
func ParseTypes(data []byte) (*Types, error) {
	t, _, err := decodeTypes(data, false)
	if err != nil {
		return nil, err
	}
	reindex(t)
	return t, nil
}

// decodeTypes is ParseTypes' shared decode and row check. With candidates false, every row failing the check is refused (the
// first one, by index). With candidates true, a row whose end_line and end_col are both absent as keys (a key
// with null is not absent) is not refused but returned as a candidate; every other row is checked exactly as before, so a
// malformed or unrelated row is still refused with its own error.
func decodeTypes(data []byte, candidates bool) (*Types, []int, error) {
	var all any
	if err := requirements.DecodeStrictJSON(data, &all); err != nil {
		return nil, nil, fmt.Errorf("spinel --emit-types JSON: %w", err)
	}
	var t Types
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, nil, fmt.Errorf("spinel --emit-types JSON: %w", err)
	}
	var noEnd []bool // read only once a row fails the check, so a document whose rows all pass is handled exactly as before
	var cand []int
	for i, r := range t.Types {
		if r.File == "" || r.Kind == "" || r.EndLine == 0 {
			if candidates && noEnd == nil {
				noEnd = typesWithoutEnd(data, len(t.Types))
			}
			if candidates && noEnd[i] && r.File != "" && r.Kind != "" {
				cand = append(cand, i)
				continue
			}
			return nil, nil, fmt.Errorf("spinel --emit-types JSON: type record %d has no file / kind / end", i)
		}
	}
	return &t, cand, nil
}

// typesWithoutEnd reports, for each row the decode gave, whether the row had neither an end_line nor an end_col key. It decodes the
// document a second time into a probe of the same shape as Types, so encoding/json picks the keys exactly as it did for Types
// (case-insensitive names, which of two "types" keys wins); a key present with null counts as present. A probe whose row count
// differs from the decode's gives no candidate (all false), so the rows are refused as before.
func typesWithoutEnd(data []byte, n int) []bool {
	var p struct {
		Types []struct {
			EndLine keyPresent `json:"end_line"`
			EndCol  keyPresent `json:"end_col"`
		} `json:"types"`
	}
	out := make([]bool, n)
	if json.Unmarshal(data, &p) != nil || len(p.Types) != n {
		return out
	}
	for i, r := range p.Types {
		out[i] = !bool(r.EndLine) && !bool(r.EndCol)
	}
	return out
}

// keyPresent becomes true when its key is in the object, whatever the value (null included).
type keyPresent bool

func (k *keyPresent) UnmarshalJSON([]byte) error { *k = true; return nil }

// renameBase matches the names Spinel gives a block parameter the block rebinds (9978ee9c2, e26aebe3d: `|i| i = 2` becomes
// `|i__bpin| i = i__bpin`, with the write named i__bp<digits>); the submatch is the parameter's name.
var renameBase = regexp.MustCompile(`^([a-z_][A-Za-z0-9_]*)__bp(?:in|[0-9]+)$`)

// ParseTypesWithAST is ParseTypes for the analysis path: a type record without an end is accepted only as the rename of a
// block parameter, and is then dropped from the type rows before the index is built. Every complete type row and every codegen row
// is kept unchanged. The AST must be the one from the same Spinel invocation. It returns the dropped rows, in order.
//
// A candidate is selected only when all hold: its kind is LocalVariableWriteNode or LocalVariableReadNode; its name has the rename
// form, giving the base; its file, line and col are those of exactly one RequiredParameterNode that sits in the requireds of a
// ParametersNode that is the parameters of a BlockParametersNode that is the parameters of a BlockNode; and that node's name is
// the base. Otherwise the candidate is refused, with the message ParseTypes gives and the reason.
func ParseTypesWithAST(data []byte, a *AST) (*Types, []TypeRec, error) {
	t, cand, err := decodeTypes(data, true)
	if err != nil {
		return nil, nil, err
	}
	if len(cand) == 0 {
		reindex(t)
		return t, nil, nil
	}
	drop := map[int]bool{}
	var sel []TypeRec
	for _, i := range cand {
		r := t.Types[i]
		if why := renameRefusal(a, r); why != "" {
			return nil, nil, fmt.Errorf("spinel --emit-types JSON: type record %d has no file / kind / end (%s %s at %s:%d:%d is not a block parameter's rename: %s)", i, r.Kind, r.Name, r.File, r.Line, r.Col, why)
		}
		drop[i] = true
		sel = append(sel, r)
	}
	kept := make([]TypeRec, 0, len(t.Types)-len(drop))
	for i, r := range t.Types {
		if !drop[i] {
			kept = append(kept, r)
		}
	}
	t.Types = kept
	reindex(t)
	return t, sel, nil
}

// renameRefusal is "" when r is a block parameter's rename in a, and otherwise the reason it is not.
func renameRefusal(a *AST, r TypeRec) string {
	if a == nil {
		return "no AST"
	}
	if r.Kind != "LocalVariableWriteNode" && r.Kind != "LocalVariableReadNode" {
		return "the kind"
	}
	m := renameBase.FindStringSubmatch(r.Name)
	if m == nil {
		return "the name has no rename form"
	}
	var at []*Node
	for _, n := range a.Nodes {
		if n.Type == "RequiredParameterNode" && a.File(n) == r.File && n.Line == r.Line && n.Col == r.Col && a.isBlockParam(n) {
			at = append(at, n)
		}
	}
	switch {
	case len(at) == 0:
		return "no block parameter at its position"
	case len(at) > 1:
		return "two or more block parameters at its position"
	case at[0].Str["name"] != m[1]:
		return "the base is not the parameter's name"
	}
	return ""
}

// isBlockParam: n is in the requireds of a ParametersNode that is the parameters of a BlockParametersNode that is the parameters of
// a BlockNode.
func (a *AST) isBlockParam(n *Node) bool {
	in := func(child *Node, wantType, field string, arr bool) *Node {
		pid, ok := a.Parent[child.ID]
		if !ok {
			return nil
		}
		p := a.Nodes[pid]
		if p == nil || p.Type != wantType {
			return nil
		}
		if arr {
			for _, c := range p.Arr[field] {
				if c == child.ID {
					return p
				}
			}
			return nil
		}
		if id, ok := p.Ref[field]; ok && id == child.ID {
			return p
		}
		return nil
	}
	q := in(n, "ParametersNode", "requireds", true)
	if q == nil {
		return false
	}
	bp := in(q, "BlockParametersNode", "parameters", false)
	return bp != nil && in(bp, "BlockNode", "parameters", false) != nil
}

// reindex rebuilds the key index.
func reindex(t *Types) {
	t.byKey = map[spanKey][]int{}
	for i, r := range t.Types {
		k := spanKey{r.File, r.Line, r.Col, r.EndLine, r.EndCol, r.Kind}
		t.byKey[k] = append(t.byKey[k], i)
	}
	t.cgByKey = map[spanKey][]int{}
	for i, r := range t.Codegen {
		k := spanKey{r.File, r.Line, r.Col, r.EndLine, r.EndCol, r.Kind}
		t.cgByKey[k] = append(t.cgByKey[k], i)
	}
}

func keyOf(a *AST, n *Node) spanKey {
	return spanKey{a.File(n), n.Line, n.Col, n.EndLine, n.EndCol, n.Type}
}

// TypeOf returns the type record of a node: (nil, 0) when there is none, (nil, count) when the match is ambiguous.
func (t *Types) TypeOf(a *AST, n *Node) (*TypeRec, int) {
	ids := t.byKey[keyOf(a, n)]
	if len(ids) != 1 {
		return nil, len(ids)
	}
	return &t.Types[ids[0]], 1
}

// CodegenOf returns the codegen record of a call node: (nil, 0) when there is none, (nil, count) when the match is ambiguous.
func (t *Types) CodegenOf(a *AST, n *Node) (*CodegenRec, int) {
	ids := t.cgByKey[keyOf(a, n)]
	if len(ids) != 1 {
		return nil, len(ids)
	}
	return &t.Codegen[ids[0]], 1
}

// Errors returns Spinel's rejections (the diagnostics with severity error).
func (t *Types) Errors() []DiagRec {
	var out []DiagRec
	for _, d := range t.Diagnostics {
		if d.Severity == "error" {
			out = append(out, d)
		}
	}
	return out
}
