package frontend

import (
	"fmt"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// The driver seam (where the driver takes spinel-mlir's consumer output instead of this Go frontend's) reads back the domain the
// consumer wrote — its bytes matched this package's DomainGraph on every case of the comparison corpus — and uses its roots (to check
// the uprobe targets) and its diagnostics (printed as the Go path prints them). The reader is strict: an unknown key, a duplicate or a
// wrong type stops it.

// DomainRoot is an element of the domain's roots (the name, kind, and declaration and definition positions of a Go Result.Programs entry).
type DomainRoot = domainRoot

// ReadDomainGraph reads a DomainGraph JSON document and returns its roots and its diagnostics (Diags, in the domain's order).
func ReadDomainGraph(b []byte) ([]DomainRoot, Diags, error) {
	var doc struct {
		Source    string       `json:"source"`
		Roots     []domainRoot `json:"roots"`
		Functions []domainFunc `json:"functions"`
		Edges     []Edge       `json:"edges"`
		Diags     []domainDiag `json:"diagnostics"`
	}
	if err := requirements.DecodeStrictJSON(b, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Roots == nil || doc.Functions == nil || doc.Edges == nil || doc.Diags == nil {
		return nil, nil, fmt.Errorf("roots, functions, edges and diagnostics must all be arrays")
	}
	var ds Diags
	for i, d := range doc.Diags {
		v, ok := parseVerdict(d.Verdict)
		if !ok {
			return nil, nil, fmt.Errorf("diagnostics[%d]: unknown verdict %q", i, d.Verdict)
		}
		if _, ok := codeNames[d.Code]; !ok || d.Code.Name() != d.Name {
			return nil, nil, fmt.Errorf("diagnostics[%d]: code %q with name %q is not in the reason code table", i, d.Code, d.Name)
		}
		ds = append(ds, Diag{Verdict: v, Code: d.Code, Pos: d.Pos, Path: d.Path, Msg: d.Message})
	}
	return doc.Roots, ds, nil
}

func parseVerdict(s string) (Verdict, bool) {
	for _, v := range []Verdict{Verified, Rejected, Conditional, Unknown} {
		if v.String() == s {
			return v, true
		}
	}
	return 0, false
}
