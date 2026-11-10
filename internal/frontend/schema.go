package frontend

import (
	"encoding/json"
)

// This file writes three outputs: the schema (docs/schema_format.md of bpf-mlir v0.8.0 — the same shape that mojo-bpf-mlir generates),
// maps.json (the shape of bindrt.MapDecls — the declarations the loader checks in its stage 2'), and the domain graph
// (roots, reachability, Membership, edges, verdicts). The same input gives byte-identical output (maps in declaration order,
// JSON keys in struct field order).

type schemaInt struct {
	Kind       string `json:"kind"`
	Bits       int    `json:"bits"`
	Signed     bool   `json:"signed"`
	Endianness string `json:"endianness"`
	Alignment  int    `json:"alignment"`
}

type schemaMap struct {
	Symbol     string `json:"symbol"`
	Kind       string `json:"kind"`
	Key        any    `json:"key"`   // schemaInt or schemaRecordRef (a record key of a hash map)
	Value      any    `json:"value"` // schemaInt or schemaRecordRef
	MaxEntries uint64 `json:"max_entries"`
	Flags      int    `json:"flags"`
	Record     string `json:"record"`
	Note       string `json:"note"`
}

type schemaRecordRef struct {
	Kind   string `json:"kind"`
	Symbol string `json:"symbol"`
}

type schemaField struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Expose string `json:"expose"`
	Note   string `json:"note"`
	Type   any    `json:"type"` // schemaInt or schemaArray
}

// schemaArray is the type of an array member (bpf-mlir's type(array): count ≥ 1, integer elements).
type schemaArray struct {
	Kind    string    `json:"kind"`
	Count   int       `json:"count"`
	Element schemaInt `json:"element"`
}

type schemaRecord struct {
	Symbol          string        `json:"symbol"`
	ID              int           `json:"id"`
	Size            int           `json:"size"`
	MinSize         int           `json:"min_size"`
	Alignment       int           `json:"alignment"`
	RequiredThrough string        `json:"required_through"`
	Note            string        `json:"note"`
	Fields          []schemaField `json:"fields"`
}

// usedRecords returns the records the maps use (in map order, without duplicates — the order of the records in the schema
// and in maps.json).
func usedRecords(res *Result) []*RecordDecl {
	var out []*RecordDecl
	seen := map[*RecordDecl]bool{}
	for _, m := range res.Maps {
		for _, r := range []*RecordDecl{m.KeyRecord, m.Record} { // the key record comes first
			if r != nil && !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	for _, r := range res.Rings {
		if !seen[r.Record] {
			seen[r.Record] = true
			out = append(out, r.Record)
		}
	}
	return out
}

// schemaRing is a ring buffer map (bpf-mlir's shape: no key or value; record holds the name of the event record).
type schemaRing struct {
	Symbol     string `json:"symbol"`
	Kind       string `json:"kind"`
	MaxEntries uint64 `json:"max_entries"`
	Flags      int    `json:"flags"`
	Record     string `json:"record"`
	Note       string `json:"note"`
}

type schemaProgram struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	AttachTarget string `json:"attach_target"`
	// tracing (schema_format.md §programs): fexit's nargs and ret, kprobe's arch and params (the xdp JSON does not change —
	// these are omitted for it)
	Nargs        *int            `json:"nargs,omitempty"`
	Ret          *schemaInt      `json:"ret,omitempty"`
	Maps         []string        `json:"maps"`
	Arch         string          `json:"arch,omitempty"`
	Params       []schemaParam   `json:"params,omitempty"`
	BinarySHA256 string          `json:"binary_sha256,omitempty"` // uprobe
	Args         []any           `json:"args,omitempty"`          // tp_btf (an array by position; an argument the program does not read is null)
	Fields       []schemaTpField `json:"fields,omitempty"`        // tracepoint (in declaration order)
	Note         string          `json:"note"`
}

// schemaTpField declares one field of a tracepoint event (core.programs[].fields[] in schema_format.md).
type schemaTpField struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Type   any    `json:"type"` // schemaInt for an integer; :user_str is {kind: user_str}
}

// schemaParam is a kprobe argument (n is the 1-based register number — the same as ctx.arg(n) in Ruby).
// schemaKernelType is an element of core.kernel_types.
type schemaKernelType struct {
	Name   string         `json:"name"`
	Note   string         `json:"note"`
	Fields []schemaKField `json:"fields"`
}

type schemaKField struct {
	Name string `json:"name"`
	Type any    `json:"type"`
}

type schemaKPtr struct {
	Kind   string `json:"kind"`
	Struct string `json:"struct"`
}

type schemaParam struct {
	N    int `json:"n"`
	Type any `json:"type"` // schemaInt; uprobe's :user_str is schemaUserStr
}

// schemaUserStr is type(user_str) in params and kprobe's type(ptr) (schema_format.md — its only key is kind).
type schemaUserStr struct {
	Kind string `json:"kind"`
}

// schemaTpArray is the type of a tracepoint field that is a fixed-size byte array (bpf-mlir's `{kind: array, elem: u8|i8, n: N}`).
type schemaTpArray struct {
	Kind string `json:"kind"`
	Elem string `json:"elem"`
	N    int    `json:"n"`
}

// traceInt returns the schema integer for a type name such as :i32.
func traceInt(t string) schemaInt {
	rt := recordTypes[t]
	return schemaInt{"int", rt[0], rt[1] == 1, "little", rt[0] / 8}
}

// schemaGlobal is an element of core.globals (schema_format.md — name, section, type).
type schemaGlobal struct {
	Name    string    `json:"name"`
	Section string    `json:"section"`
	Type    schemaInt `json:"type"`
	Note    string    `json:"note"`
}

type schemaDoc struct {
	Version  int `json:"version"`
	Coverage struct {
		Programs  string `json:"programs"`
		Maps      string `json:"maps"`
		Records   string `json:"records"`
		Telemetry string `json:"telemetry"`
	} `json:"coverage"`
	Core struct {
		KernelTypes []schemaKernelType `json:"kernel_types,omitempty"` // local types for CO-RE (compile once, run everywhere) — only when a tp_btf program exists; a schema without one is byte-identical to before
		Records     []any              `json:"records"`
		Maps        []any              `json:"maps"` // schemaMap or schemaRing
		Programs    []schemaProgram    `json:"programs"`
		Globals     []schemaGlobal     `json:"globals,omitempty"` // only when a used global exists (the schema of a program without one is byte-identical to before)
	} `json:"core"`
	Telemetry struct {
		Clocks     []any `json:"clocks"`
		ValueMaps  []any `json:"value_maps"`
		BoundsSets []any `json:"bounds_sets"`
		Signals    []any `json:"signals"`
	} `json:"telemetry"`
	Extensions struct{} `json:"extensions"`
}

func uint32T() schemaInt { return schemaInt{"int", 32, false, "little", 4} }

// Schema returns the schema JSON (with a trailing newline). It holds no source positions (adding an unrelated line must not
// change the schema — the project's reproducibility rule).
func Schema(res *Result) ([]byte, error) {
	var d schemaDoc
	d.Version = 1
	d.Coverage.Programs, d.Coverage.Maps, d.Coverage.Records, d.Coverage.Telemetry = "complete", "complete", "complete", "complete"
	d.Core.Records = []any{}
	d.Core.Maps = []any{}
	d.Core.Programs = []schemaProgram{}
	d.Telemetry.Clocks, d.Telemetry.ValueMaps, d.Telemetry.BoundsSets, d.Telemetry.Signals = []any{}, []any{}, []any{}, []any{}
	for i, r := range usedRecords(res) {
		sr := schemaRecord{Symbol: r.Const, ID: i, Size: r.Size, MinSize: r.Size, Alignment: r.Align, RequiredThrough: "", Note: "Ruby Struct " + r.Const, Fields: []schemaField{}}
		for _, f := range r.Fields {
			if f.Pad {
				continue // padding is not written to the schema (a hole — record.make zeroes it)
			}
			var t any = schemaInt{"int", f.Bits, f.Signed, "little", f.Bits / 8}
			if f.Count > 0 {
				t = schemaArray{"array", f.Count, schemaInt{"int", f.Bits, f.Signed, "little", f.Bits / 8}}
			}
			sr.Fields = append(sr.Fields, schemaField{Name: f.Name, Offset: f.Offset, Expose: "int", Type: t})
		}
		d.Core.Records = append(d.Core.Records, sr)
	}
	for _, m := range res.Maps {
		var v any = schemaInt{"int", m.ValueBits, m.Signed, "little", m.ValueBits / 8}
		if m.Record != nil {
			v = schemaRecordRef{Kind: "record_ref", Symbol: m.Record.Const}
		}
		var k any = uint32T()
		switch {
		case m.KeyRecord != nil:
			k = schemaRecordRef{Kind: "record_ref", Symbol: m.KeyRecord.Const}
		case m.IsHash():
			k = schemaInt{"int", m.KeyBits, m.KeySigned, "little", m.KeyBits / 8}
		}
		d.Core.Maps = append(d.Core.Maps, schemaMap{Symbol: m.Name, Kind: m.MapKind(), Key: k, Value: v, MaxEntries: m.MaxEntries, Flags: int(m.Flags()), Record: "", Note: "Ruby constant " + m.Const})
	}
	for _, r := range res.Rings {
		d.Core.Maps = append(d.Core.Maps, schemaRing{Symbol: r.Name, Kind: "ringbuf", MaxEntries: ringSize(r), Record: r.Record.Const, Note: "Ruby constant " + r.Const})
	}
	d.Core.KernelTypes = kernelTypesSchema(res) // CO-RE local types
	for _, p := range res.Programs {
		sp := schemaProgram{Name: p.Name, Kind: p.Kind, AttachTarget: p.Target, Maps: []string{}, Note: "Ruby def " + p.Name}
		switch p.Kind {
		case "fexit":
			n, r := p.Nargs, traceInt(p.Ret)
			sp.Nargs, sp.Ret = &n, &r
		case "fmod_ret": // nargs and ret are required (the requirements retsig line); args holds integers and null (farg)
			n, r := p.Nargs, traceInt(p.Ret)
			sp.Nargs, sp.Ret = &n, &r
			sp.Args = fmodArgsSchema(p)
		case "kretprobe": // arch only (no params)
			sp.Arch = "x86_64"
		case "uretprobe": // arch and binary_sha256 (no params)
			sp.Arch, sp.BinarySHA256 = "x86_64", p.BinarySHA
		case "kprobe", "uprobe", "ksyscall": // ksyscall also has arch and params (the syscall's arguments)
			sp.Arch = "x86_64"
			for _, kp := range p.Params {
				if kp.Type == "ptr" { // a kprobe pointer argument (the requirements line kprobearg … ptr)
					sp.Params = append(sp.Params, schemaParam{N: kp.N, Type: schemaUserStr{"ptr"}})
					continue
				}
				if kp.Type == "user_str" || kp.Type == "user_str_array" || kp.Type == "user_buf" { // user strings, string arrays and user_buf
					sp.Params = append(sp.Params, schemaParam{N: kp.N, Type: schemaUserStr{kp.Type}})
					continue
				}
				sp.Params = append(sp.Params, schemaParam{N: kp.N, Type: traceInt(kp.Type)})
			}
			sp.BinarySHA256 = p.BinarySHA
		case "tp_btf": // typed (BTF) tracepoint
			sp.Args = tpArgsSchema(p)
		case "tracepoint": // classic tracepoint: the event's fields
			for _, f := range p.TFields {
				var t any = traceInt(f.Type)
				if f.Type == "user_str" || f.Type == "user_str_array" { // a user string or string array
					t = schemaUserStr{f.Type}
				}
				if f.N > 0 { // a fixed-size byte array
					t = schemaTpArray{Kind: "array", Elem: f.Type, N: f.N}
				}
				sp.Fields = append(sp.Fields, schemaTpField{Name: f.Name, Offset: f.Offset, Type: t})
			}
		case "fentry": // only an fentry with args (without them the output is byte-identical to before)
			if len(p.TArgs) > 0 {
				sp.Args = tpArgsSchema(p)
			}
		}
		for _, m := range p.Maps {
			sp.Maps = append(sp.Maps, m.Name)
		}
		d.Core.Programs = append(d.Core.Programs, sp)
	}
	for _, g := range res.Globals {
		d.Core.Globals = append(d.Core.Globals, schemaGlobal{Name: g.Name, Section: g.Section, Type: schemaInt{"int", g.Bits, g.Signed, "little", g.Bits / 8}, Note: "Ruby constant " + g.Const + " (" + g.Class + ")"})
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// mapDeclJSON has the same JSON shape as bindrt.MapDecl (the loader passes it to go/bindrt).
type mapDeclJSON struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	MaxEntries uint64 `json:"max_entries"`
	Flags      uint64 `json:"flags,omitempty"` // lpm_trie's BPF_F_NO_PREALLOC (bml, the bpf-mlir loader, checks the declared flags against the ELF's; kinds with
	// flags 0 do not write the key, so existing documents stay byte-identical)
}

// MapsJSON returns the map declaration document (the shape of bindrt.MapDecls — §12 of the spec docs/requirements_format.md).
func MapsJSON(res *Result) ([]byte, error) {
	type member struct {
		Name   string `json:"name"`
		Offset int    `json:"offset"`
		Type   string `json:"type"`
	}
	type shape struct {
		Size    int      `json:"size"`
		Members []member `json:"members"`
	}
	doc := struct {
		Records map[string]shape `json:"records,omitempty"` // spec §12 — bindrt.CheckMapDecls checks them against the ELF's BTF
		Maps    []mapDeclJSON    `json:"maps"`
		Globals []globalJSON     `json:"globals,omitempty"` // spec §12 — when present, checked both ways against the ELF's DATASEC
	}{Maps: []mapDeclJSON{}}
	for _, r := range usedRecords(res) {
		if doc.Records == nil {
			doc.Records = map[string]shape{}
		}
		sh := shape{Size: r.Size, Members: []member{}}
		for _, f := range r.Fields {
			if !f.Pad {
				sh.Members = append(sh.Members, member{f.Name, f.Offset, f.DeclType()})
			}
		}
		doc.Records[r.Const] = sh
	}
	for _, m := range res.Maps {
		fl := m.Flags()
		if mutation("lpm-no-flags") { // mutation control (a deliberate defect that shows the tests catch it; test builds only): drop the flags from the embedded declaration
			fl = 0
		}
		doc.Maps = append(doc.Maps, mapDeclJSON{Name: m.Name, Kind: m.MapKind(), Key: m.KeyTypeName(), Value: m.TypeName(), MaxEntries: m.MaxEntries, Flags: fl})
	}
	for _, g := range res.Globals {
		doc.Globals = append(doc.Globals, globalJSON{Name: g.Name, Section: g.Section, Type: g.TypeName()})
	}
	for _, r := range res.Rings {
		doc.Maps = append(doc.Maps, mapDeclJSON{Name: r.Name, Kind: "ringbuf", Key: "-", Value: "record:" + r.Record.Const, MaxEntries: ringSize(r)})
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

type domainFunc struct {
	Name       string   `json:"name"`
	Membership []string `json:"membership"`
}

type domainRoot struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Decl Pos    `json:"decl"`
	Def  Pos    `json:"def"`
}

type domainDiag struct {
	Verdict string   `json:"verdict"`
	Code    Code     `json:"code"`
	Name    string   `json:"name"`
	Pos     Pos      `json:"pos"`
	Path    []string `json:"path,omitempty"`
	Message string   `json:"message"`
}

// DomainGraph returns the JSON of the per-stage artifact `--emit=domain-graph`. It contains source positions (unlike the schema,
// it is for diagnostics).
func DomainGraph(res *Result) ([]byte, error) {
	doc := struct {
		Source    string       `json:"source"`
		Roots     []domainRoot `json:"roots"`
		Functions []domainFunc `json:"functions"`
		Edges     []Edge       `json:"edges"`
		Diags     []domainDiag `json:"diagnostics"`
	}{Source: res.Source, Roots: []domainRoot{}, Functions: []domainFunc{}, Edges: []Edge{}, Diags: []domainDiag{}}
	for _, p := range res.Programs {
		doc.Roots = append(doc.Roots, domainRoot{Name: p.Name, Kind: p.Kind, Decl: p.DeclPos, Def: p.Pos})
	}
	var names []string
	for n := range res.Membership {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		doc.Functions = append(doc.Functions, domainFunc{Name: n, Membership: res.Membership[n]})
	}
	if res.Edges != nil {
		doc.Edges = res.Edges
	}
	for _, d := range res.Diags.Sorted() {
		doc.Diags = append(doc.Diags, domainDiag{Verdict: d.Verdict.String(), Code: d.Code, Name: d.Code.Name(), Pos: d.Pos, Path: d.Path, Message: d.Msg})
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ringSize returns the ring buffer size written to the schema and to maps.json. The mutation control ring-size (test builds
// only) doubles it (a frontend that gets the size wrong — the twin counts with the declared size).
func ringSize(r *RingDecl) uint64 {
	if mutation("ring-size") {
		return r.Size * 2
	}
	return r.Size
}

// globalJSON is an element of globals in maps.json ({name, section, type} — the same keys as bml's strict reader).
type globalJSON struct {
	Name    string `json:"name"`
	Section string `json:"section"`
	Type    string `json:"type"`
}
