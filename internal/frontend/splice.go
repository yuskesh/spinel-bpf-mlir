package frontend

import (
	"strings"
)

const spliceMaxShift = 4

func spliced(a *AST) bool {
	for _, p := range a.Files {
		if strings.Contains(p, "/builtins/") {
			return true
		}
	}
	return false
}

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
			if _, has := n.Ref["receiver"]; !has && n.Str["name"] != "" && !strings.ContainsAny(n.Str["name"], "=[]+-*/<>!%&|^~") {
				add(n, n.Str["name"])
			}
		}
	}
	return out
}

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
