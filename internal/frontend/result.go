package frontend

import (
	"fmt"
	"sort"
	"strings"
)

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

type Code string

const (
	SB000Spinel                Code = "SB000"
	SB001UnsupportedConstruct  Code = "SB001"
	SB002UnsupportedCall       Code = "SB002"
	SB003CrossDomainUse        Code = "SB003"
	SB004UnknownEdge           Code = "SB004"
	SB005RefCheckShape         Code = "SB005"
	SB006NonConstant           Code = "SB006"
	SB007ReservedName          Code = "SB007"
	SB008ProgramShape          Code = "SB008"
	SB009OperatorRedefined     Code = "SB009"
	SB010TypingProbe           Code = "SB010"
	SB011ShadowedName          Code = "SB011"
	SB012ThreadInUserSide      Code = "SB012"
	SB013MapDeclShape          Code = "SB013"
	SB014SemanticGap           Code = "SB014"
	SB015AmbiguousType         Code = "SB015"
	SB016DynamicProgram        Code = "SB016"
	SB017InternalEmitter       Code = "SB017"
	SB018LogicalSideEffect     Code = "SB018"
	SB019SharedReadModifyWrite Code = "SB019"
	SB020KeyOutOfRange         Code = "SB020"
	SB021CompileWarning        Code = "SB021"
	SB022WindowIndex           Code = "SB022"
	SB025DroppedEvent          Code = "SB025"
	SB024RecordShape           Code = "SB024"
	SB023PacketOffset          Code = "SB023"
	SB031IndexRange            Code = "SB031"
	SB032UprobeTarget          Code = "SB032"
	SB033KernelTypeShape       Code = "SB033"
	SB034SubprogramShape       Code = "SB034"
	SB035Recursion             Code = "SB035"
	SB030LoopShape             Code = "SB030"
	SB029GlobalShape           Code = "SB029"
	SB028TracingKind           Code = "SB028"
	SB027ThreadInBPFSide       Code = "SB027"
	SB026StatusIgnored         Code = "SB026"
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

func (c Code) Name() string { return codeNames[c] }

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

type Diag struct {
	Verdict Verdict  `json:"-"`
	Code    Code     `json:"code"`
	Pos     Pos      `json:"pos"`
	Path    []string `json:"path,omitempty"`
	Msg     string   `json:"message"`
}

func (d Diag) String() string {
	s := fmt.Sprintf("%s: %s %s (%s): %s", d.Pos, d.Verdict, d.Code, d.Code.Name(), d.Msg)
	if len(d.Path) > 0 {
		s += " [path: " + strings.Join(d.Path, " -> ") + "]"
	}
	return s
}

type Diags []Diag

func (ds Diags) Blocking() bool {
	for _, d := range ds {
		if d.Verdict == Rejected || d.Verdict == Unknown {
			return true
		}
	}
	return false
}

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
