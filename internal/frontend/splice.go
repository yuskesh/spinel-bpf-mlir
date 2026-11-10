package frontend

import (
	"strings"
)

// Correcting the line shift caused by Spinel splicing in its builtins (docs/upstream_suspects.md S11; the frontend used to stop with
// SB000 on every such input, and now corrects the shift instead).
// When the source contains the name of an Enumerable method, Spinel splices in builtins/enumerable.rb (and then enumerator.rb) and
// adds require lines at the top of the source, so the node_line of the nodes of the user's file (FILE 0) is reported k lines too large.
// The added require nodes do not remain in the AST — k is measured by matching the positions of named nodes against the source text.
// The --emit-types records of the same Spinel run are shifted by the same amount — the AST and the records are moved back by the same
// k (so the keys for type lookup stay aligned).

// spliceMaxShift is the largest candidate shift k that measureShift tries (it tries 0..spliceMaxShift); it is a search limit,
// not a measurement. Spinel splices in two builtins today (enumerable and enumerator), and the largest shift measured on real
// sources was +2 (both measured sources gave k = 2; no shift of 3 or more has been seen), so this limit leaves a margin of 2.
// Beyond it no k matches and the input gets SB000.
const spliceMaxShift = 4

// spliced reports whether the AST holds a file of Spinel's builtins.
func spliced(a *AST) bool {
	// Not only enumerable and enumerator but also integer and comparable add a require at the top of the source (found when the
	// library's local variable `digits` spliced in integer.rb)
	for _, p := range a.Files {
		if strings.Contains(p, "/builtins/") {
			return true
		}
	}
	return false
}

// anchors returns the named nodes of FILE fid, each with the source text that should start at its column of its source line.
func anchors(a *AST, fid int) []struct {
	n    *Node
	want string
} {
	var out []struct {
		n    *Node
		want string
	}
	add := func(n *Node, w string) {
		if w != "" {
			out = append(out, struct {
				n    *Node
				want string
			}{n, w})
		}
	}
	for _, n := range a.Nodes {
		if n == nil || n.FileID != fid || n.Line <= 0 {
			continue
		}
		switch n.Type {
		case "ConstantWriteNode", "ConstantReadNode", "LocalVariableWriteNode":
			add(n, n.Str["name"])
		case "DefNode":
			add(n, "def")
		case "CallNode":
			// Only calls without a receiver (the column of a call with a receiver is where the receiver starts). Operator names are skipped
			if _, has := n.Ref["receiver"]; !has && n.Str["name"] != "" && !strings.ContainsAny(n.Str["name"], "=[]+-*/<>!%&|^~") {
				add(n, n.Str["name"])
			}
		}
	}
	return out
}

// measureShift returns the k in 0..spliceMaxShift for which the text of every anchor starts at its col on source line (line − k).
// Unless exactly one k matches, ok = false.
func measureShift(a *AST, fid int, lines []string) (int, bool) {
	as := anchors(a, fid)
	if len(as) == 0 {
		return 0, false
	}
	found, k := 0, -1
	for c := 0; c <= spliceMaxShift; c++ {
		all := true
		for _, x := range as {
			l := x.n.Line - c
			if l < 1 || l > len(lines) || x.n.Col < 0 || x.n.Col > len(lines[l-1]) || !strings.HasPrefix(lines[l-1][x.n.Col:], x.want) {
				all = false
				break
			}
		}
		if all {
			found++
			k = c
		}
	}
	return k, found == 1
}

// shiftUser moves the nodes of FILE fid, and the lines of that file's type, codegen and diagnostic records, back by k, and rebuilds
// the type lookup.
func shiftUser(an *Analysis, fid, k int) {
	if k == 0 {
		return
	}
	a := an.AST
	for _, n := range a.Nodes {
		if n != nil && n.FileID == fid {
			n.Line -= k
			if n.EndLine > 0 {
				n.EndLine -= k
			}
		}
	}
	path := a.Files[fid]
	t := an.Types
	for i := range t.Types {
		if t.Types[i].File == path {
			t.Types[i].Line -= k
			t.Types[i].EndLine -= k
		}
	}
	for i := range t.Codegen {
		if t.Codegen[i].File == path {
			t.Codegen[i].Line -= k
			t.Codegen[i].EndLine -= k
		}
	}
	for i := range t.Diagnostics {
		if t.Diagnostics[i].File == path {
			t.Diagnostics[i].Line -= k
		}
	}
	reindex(t)
}

// alignSplice measures k and moves the lines back when builtins were spliced in. Without a splice it does nothing (ok). When k
// cannot be measured, ok = false (the caller reports SB000).
func alignSplice(an *Analysis, base, text string) (k int, ok bool) {
	if an == nil || an.AST == nil || !spliced(an.AST) {
		return 0, true
	}
	fid := userFileID(an.AST, base)
	if fid < 0 {
		return 0, false
	}
	k, ok = measureShift(an.AST, fid, strings.Split(text, "\n"))
	if !ok {
		return 0, false
	}
	shiftUser(an, fid, k)
	return k, true
}
