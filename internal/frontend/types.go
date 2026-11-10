package frontend

import (
	"encoding/json"
	"fmt"

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
func ParseTypes(data []byte) (*Types, error) {
	var all any
	if err := requirements.DecodeStrictJSON(data, &all); err != nil {
		return nil, fmt.Errorf("spinel --emit-types JSON: %w", err)
	}
	var t Types
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("spinel --emit-types JSON: %w", err)
	}
	for i, r := range t.Types {
		if r.File == "" || r.Kind == "" || r.EndLine == 0 {
			return nil, fmt.Errorf("spinel --emit-types JSON: type record %d has no file / kind / end", i)
		}
	}
	reindex(&t)
	return &t, nil
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
