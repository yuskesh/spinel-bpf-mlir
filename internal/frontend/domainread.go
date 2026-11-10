package frontend

import (
	"fmt"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

type DomainRoot = domainRoot

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
