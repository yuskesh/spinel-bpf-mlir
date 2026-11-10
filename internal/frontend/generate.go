package frontend

import (
	"fmt"
	"os"
	"sort"
)

func sortStrings(s []string) { sort.Strings(s) }

type Output struct {
	Result  *Result
	MLIR    string
	Schema  []byte
	Maps    []byte
	Domain  []byte
	Records string
}

func Generate(sp Spinel, work, sourcePath string) (*Output, error) {
	text, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, err
	}
	res, err := Analyze(sp, work, sourcePath, string(text))
	if err != nil {
		return nil, err
	}
	out := &Output{Result: res}
	if out.Domain, err = DomainGraph(res); err != nil {
		return nil, err
	}
	if res.Diags.Blocking() {
		return out, &Error{Diags: res.Diags}
	}
	if len(res.Programs) == 0 {
		return out, fmt.Errorf("internal: no program and no blocking diagnostic")
	}
	if out.MLIR, err = Lower(res); err != nil {
		return out, &Error{Diags: Diags{{Verdict: Rejected, Code: SB017InternalEmitter, Pos: Pos{File: res.Source}, Msg: err.Error()}}}
	}
	if out.Schema, err = Schema(res); err != nil {
		return nil, err
	}
	if out.Maps, err = MapsJSON(res); err != nil {
		return nil, err
	}
	out.Records = RecordsTable(res)
	return out, nil
}
