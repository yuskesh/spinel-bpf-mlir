// Package frontend turns the eBPF side of a Ruby (Spinel) program into .mlir in bpf-mlir's ebpf dialect (stage ①) and a schema.
//
// It does not parse Ruby itself. It reads Spinel's text AST (`--dump-ast --emit-types`) and inferred types (the JSON of
// `--emit-types`), so Spinel plays the role that go/types plays for Go. Only the shapes in the frontend's table of accepted forms
// are accepted; anything else stops loudly with its position (fail closed).
package frontend

import (
	"fmt"
	"sort"
	"strings"
)

// Verdict is the four-valued judgement (the same meaning as bpf-mlir's CheckResult, and the same shape as in go-bpf-mlir and
// mojo-bpf-mlir). Anything other than Verified and Conditional stops generation.
type Verdict int

const (
	Verified Verdict = iota
	Rejected
	Conditional
	Unknown
)

func (v Verdict) String() string {
	switch v {
	case Verified:
		return "verified"
	case Rejected:
		return "rejected"
	case Conditional:
		return "conditional"
	case Unknown:
		return "unknown"
	}
	return fmt.Sprintf("verdict(%d)", int(v))
}

// Code is a reason code. **Codes may be added, but a code's meaning never changes.**
//
// Priority of reasons (which one to report when several apply to one line — a table written to keep five mistakes found when the
// record frontend was first run from recurring):
//
//  1. A declaration error (SB013 / SB024 — a map or record declaration) is reported once, at the declaration. Code that uses a map
//     whose declaration was rejected gets no further reason on top (such as SB011 at the lookup)
//  2. Syntactic shape (SB005 for an alias, SB019 for read-modify-write) is checked before the value interval (SB014) — an interval
//     error is reported only when the shape is right (otherwise the range error hides the RMW)
//  3. Whether a name exists (SB002 for an unknown member) comes before the callee checks (SB004 from Spinel's codegen, SB011 for the
//     callee) — a name for which Spinel emits no record is not reported as "a call that is not static"
//  4. An alias shape (a method that uses the value itself — dup, == and the like) is reported only by the walk's SB005, with no
//     missing-member SB002 on top
//  5. A suggested fix shows only shapes that are accepted (never `_pad0: :u24`, a type that does not exist — the negative examples
//     check the wording of the suggestions too)
//  6. AST field names are confirmed with Spinel's --dump-ast (Prism's CallOperatorWriteNode has `name`, not read_name)
//  7. A statement that drops a status, and a status local that is never read or assigned twice (SB026), come before the checks
//     of the arguments (key / value) — the argument errors are reported after the accepted shape is fixed. A double assignment
//     is reported once, at the first assignment
type Code string

const (
	SB000Spinel                Code = "SB000" // Spinel rejected the program, or its output could not be read
	SB001UnsupportedConstruct  Code = "SB001" // a construct, type or value not in the table
	SB002UnsupportedCall       Code = "SB002" // a call or callee not in the table
	SB003CrossDomainUse        Code = "SB003" // misuse of a {User, BPF} function or of the API across the two sides
	SB004UnknownEdge           Code = "SB004" // an edge that cannot be followed statically (switch / boxed / a call with no record)
	SB005RefCheckShape         Code = "SB005" // outside the shape of the presence check
	SB006NonConstant           Code = "SB006" // a non-constant where a constant is needed
	SB007ReservedName          Code = "SB007" // a reserved prefix (_spinelbpf_ / spinelbpf_)
	SB008ProgramShape          Code = "SB008" // shape of the BPF.xdp declaration and the def
	SB009OperatorRedefined     Code = "SB009" // a builtin operator call got a callee (the user redefined it)
	SB010TypingProbe           Code = "SB010" // the check that injects typing for the root
	SB011ShadowedName          Code = "SB011" // a name of bpf.rb reopened, a class with the same name, or a callee not in bpf.rb
	SB012ThreadInUserSide      Code = "SB012" // retired (Thread on the user side is now allowed; programs using Thread and the like used to be stopped)
	SB013MapDeclShape          Code = "SB013" // shape of a map declaration (name and string differ, two declarations with the same string, arguments)
	SB014SemanticGap           Code = "SB014" // a difference in meaning between Ruby and BPF (literal ranges)
	SB015AmbiguousType         Code = "SB015" // records of two or more types at one node (specialisation)
	SB016DynamicProgram        Code = "SB016" // a reopened builtin, method_missing / define_method / send / eval and the like (they break the assumption of static callees)
	SB017InternalEmitter       Code = "SB017" // an internal frontend error (verify-bpf-world and the like)
	SB018LogicalSideEffect     Code = "SB018" // a side effect in the right operand of && or || (Ruby short-circuits)
	SB019SharedReadModifyWrite Code = "SB019" // a value loaded from a map passed to an update of the same map (loses counts on multiple CPUs)
	SB020KeyOutOfRange         Code = "SB020" // a map key's interval does not fit [0, max_entries − 1] (an array update fails silently)
	SB021CompileWarning        Code = "SB021" // an ebpf-compile warning with rc 0 (since bpf-mlir v0.10.0 — Conditional, the build does not stop)
	SB022WindowIndex           Code = "SB022" // a window length outside [1, 65535], or a read index outside the window
	SB025DroppedEvent          Code = "SB025" // the result of a ring buffer output (whether the reservation succeeded) is dropped — only an if / unless condition or `_ = …` is accepted
	SB024RecordShape           Code = "SB024" // shape of a record declaration (Struct and BPF.record agree, implicit padding, the sample, every member given)
	SB023PacketOffset          Code = "SB023" // a window offset's interval does not fit [0, 65535 − N]
	SB031IndexRange            Code = "SB031" // the index into a record's array member cannot be shown to lie in [0, N−1] (out of range, negative or variable)
	SB032UprobeTarget          Code = "SB032" // build-time check of the uprobe target (the uprobe Unmet of bpf-mlir's Precheck — symbol, argument types, calling convention, sha256. An early error for convenience — it does not replace the check at load time)
	SB033KernelTypeShape       Code = "SB033" // shape of CO-RE kernel struct declarations, tp_btf arguments and kernel pointer use (correct widths, signs and names are guarded by the check at load time)
	SB034SubprogramShape       Code = "SB034" // shape of an eBPF-side subprogram (def) — parameter count and types, return value, return, program-only ops
	SB035Recursion             Code = "SB035" // a cycle in the subprogram call graph (with its path)
	SB030LoopShape             Code = "SB030" // outside the shape of a bounded loop (times / each) — the bound, nesting, where break / next sit, ops not allowed in the body, references across the loop
	SB029GlobalShape           Code = "SB029" // shape of global variable (Config / OptionalConfig / Counter) declarations and uses
	SB028TracingKind           Code = "SB028" // a tracing kind mix-up (an xdp verdict, packet, ctx.ret / ctx.arg outside their kinds, an index not in params)
	SB027ThreadInBPFSide       Code = "SB027" // a reference to Thread and the like inside a function the eBPF side reaches (separate from SB012 — it stays after SB012 was retired)
	SB026StatusIgnored         Code = "SB026" // the status of a hash map operation (0 or a negative errno) is dropped — only a local assigned once and read, a comparison operand or `_ = …` is accepted
)

var codeNames = map[Code]string{
	SB000Spinel:                "Spinel",
	SB001UnsupportedConstruct:  "UnsupportedConstruct",
	SB002UnsupportedCall:       "UnsupportedCall",
	SB003CrossDomainUse:        "CrossDomainUse",
	SB004UnknownEdge:           "UnknownEdge",
	SB005RefCheckShape:         "RefCheckShape",
	SB006NonConstant:           "NonConstant",
	SB007ReservedName:          "ReservedName",
	SB008ProgramShape:          "ProgramShape",
	SB009OperatorRedefined:     "OperatorRedefined",
	SB010TypingProbe:           "TypingProbe",
	SB011ShadowedName:          "ShadowedName",
	SB012ThreadInUserSide:      "ThreadInUserSide",
	SB027ThreadInBPFSide:       "ThreadInBPFSide",
	SB028TracingKind:           "TracingKind",
	SB029GlobalShape:           "GlobalShape",
	SB030LoopShape:             "LoopShape",
	SB031IndexRange:            "IndexRange",
	SB032UprobeTarget:          "UprobeTarget",
	SB033KernelTypeShape:       "KernelTypeShape",
	SB034SubprogramShape:       "SubprogramShape",
	SB035Recursion:             "Recursion",
	SB013MapDeclShape:          "MapDeclShape",
	SB014SemanticGap:           "SemanticGap",
	SB015AmbiguousType:         "AmbiguousType",
	SB016DynamicProgram:        "DynamicProgram",
	SB017InternalEmitter:       "InternalEmitter",
	SB018LogicalSideEffect:     "LogicalSideEffect",
	SB019SharedReadModifyWrite: "SharedReadModifyWrite",
	SB020KeyOutOfRange:         "KeyOutOfRange",
	SB021CompileWarning:        "CompileWarning",
	SB022WindowIndex:           "WindowIndex",
	SB023PacketOffset:          "PacketOffset",
	SB024RecordShape:           "RecordShape",
	SB025DroppedEvent:          "DroppedEvent",
	SB026StatusIgnored:         "StatusIgnored",
}

// Name is the code's name (SB001 → UnsupportedConstruct).
func (c Code) Name() string { return codeNames[c] }

// Pos is a position in the user's file (lines from 1, columns from 1 — 1 is added to the 0-based column of Spinel / Prism).
type Pos struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Col  int    `json:"col"`
}

func (p Pos) String() string {
	if p.File == "" {
		return "-"
	}
	if p.Line == 0 {
		return p.File
	}
	return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Col)
}

// Diag is one judgement result (the single result type — all wording is built from it).
type Diag struct {
	Verdict Verdict  `json:"-"`
	Code    Code     `json:"code"`
	Pos     Pos      `json:"pos"`
	Path    []string `json:"path,omitempty"` // the call path (from the root)
	Msg     string   `json:"message"`
}

func (d Diag) String() string {
	s := fmt.Sprintf("%s: %s %s (%s): %s", d.Pos, d.Verdict, d.Code, d.Code.Name(), d.Msg)
	if len(d.Path) > 0 {
		s += " [path: " + strings.Join(d.Path, " -> ") + "]"
	}
	return s
}

// Diags is a list of judgement results.
type Diags []Diag

// Blocking reports whether any result stops generation (Rejected / Unknown).
func (ds Diags) Blocking() bool {
	for _, d := range ds {
		if d.Verdict == Rejected || d.Verdict == Unknown {
			return true
		}
	}
	return false
}

// Sorted returns a copy sorted by position (by code at the same position).
func (ds Diags) Sorted() Diags {
	out := append(Diags(nil), ds...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Pos, out[j].Pos
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// Error is the set of judgements that stopped generation (a generation error).
type Error struct{ Diags Diags }

func (e *Error) Error() string {
	var b strings.Builder
	for i, d := range e.Diags.Sorted() {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(d.String())
	}
	return b.String()
}
