package frontend

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// A reader for Spinel's text AST (third_party/spinel/docs/internals/AST.md).
// One record per line: `ROOT <id>`, `SOURCE_FILE <path>`, `FILE <fid> <path>`, `N <id> <Type>`, `S|I|F <id> <field> <value>`,
// `R <id> <field> <id|-1>`, `A <id> <field> <id,…>`.
// With `--dump-ast --emit-types` the nodes carry `node_end_line` / `node_end_col` (a node without them is treated as a read error).

// Node is one AST node. Columns count from 0, as in Prism (the Ruby parser Spinel uses).
type Node struct {
	ID      int
	Type    string
	Str     map[string]string
	Int     map[string]int64
	IntText map[string]string // the source text of an I value (for checking out-of-range literals — to see whether Spinel rounded it)
	Ref     map[string]int
	Arr     map[string][]int
	FileID  int
	Line    int
	Col     int
	EndLine int
	EndCol  int
}

// AST is the tree that was read.
type AST struct {
	Root       int
	SourceFile string
	Files      map[int]string
	Nodes      map[int]*Node
	Parent     map[int]int
}

func (a *AST) node(id int) *Node {
	if id < 0 {
		return nil
	}
	return a.Nodes[id]
}

// File returns the path of the node's file.
func (a *AST) File(n *Node) string { return a.Files[n.FileID] }

// ref returns the single child in field (nil if there is none).
func (a *AST) ref(n *Node, field string) *Node {
	id, ok := n.Ref[field]
	if !ok {
		return nil
	}
	return a.node(id)
}

// arr returns the list of children in field.
func (a *AST) arr(n *Node, field string) []*Node {
	var out []*Node
	for _, id := range n.Arr[field] {
		if c := a.node(id); c != nil {
			out = append(out, c)
		}
	}
	return out
}

// ParseAST reads a text AST. A malformed record is an error (it is never skipped silently).
func ParseAST(text string) (*AST, error) {
	a := &AST{Root: -1, Files: map[int]string{}, Nodes: map[int]*Node{}, Parent: map[int]int{}}
	get := func(id int) *Node {
		n := a.Nodes[id]
		if n == nil {
			n = &Node{ID: id, Str: map[string]string{}, Int: map[string]int64{}, IntText: map[string]string{}, Ref: map[string]int{}, Arr: map[string][]int{}, FileID: -1}
			a.Nodes[id] = n
		}
		return n
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if line == "" {
			continue
		}
		bad := func(why string) error { return fmt.Errorf("spinel AST line %d: %s: %q", ln, why, line) }
		tag, rest, _ := strings.Cut(line, " ")
		switch tag {
		case "ROOT":
			id, err := strconv.Atoi(rest)
			if err != nil {
				return nil, bad("ROOT id")
			}
			a.Root = id
		case "SOURCE_FILE":
			a.SourceFile = unescape(rest)
		case "FILE":
			fid, p, ok := strings.Cut(rest, " ")
			id, err := strconv.Atoi(fid)
			if !ok || err != nil {
				return nil, bad("FILE record")
			}
			a.Files[id] = unescape(p)
		case "N", "S", "I", "F", "R", "A":
			f := strings.SplitN(rest, " ", 3)
			id, err := strconv.Atoi(f[0])
			if err != nil || len(f) < 2 {
				return nil, bad("record id")
			}
			n := get(id)
			if tag == "N" {
				if n.Type != "" {
					return nil, bad("node declared twice")
				}
				n.Type = f[1]
				continue
			}
			field, val := f[1], ""
			if len(f) == 3 {
				val = f[2]
			}
			switch tag {
			case "S", "F":
				n.Str[field] = unescape(val)
			case "I":
				v, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					// keep the source text of an integer that does not fit in 64 bits (literal ranges are checked on the source text — do not
					// trust Spinel's rounding)
					n.IntText[field] = val
					continue
				}
				n.IntText[field] = val
				switch field {
				case "node_file":
					n.FileID = int(v)
				case "node_line":
					n.Line = int(v)
				case "node_col":
					n.Col = int(v)
				case "node_end_line":
					n.EndLine = int(v)
				case "node_end_col":
					n.EndCol = int(v)
				default:
					n.Int[field] = v
				}
			case "R":
				c, err := strconv.Atoi(val)
				if err != nil {
					return nil, bad("R child id")
				}
				n.Ref[field] = c
				if c >= 0 {
					a.Parent[c] = id
				}
			case "A":
				var ids []int
				if val != "" {
					for _, s := range strings.Split(val, ",") {
						c, err := strconv.Atoi(s)
						if err != nil {
							return nil, bad("A child id")
						}
						ids = append(ids, c)
						a.Parent[c] = id
					}
				}
				n.Arr[field] = ids
			}
		default:
			return nil, bad("unknown record tag")
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if a.Root < 0 || a.Nodes[a.Root] == nil {
		return nil, fmt.Errorf("spinel AST: no ROOT node")
	}
	for id, n := range a.Nodes {
		if n.Type == "" {
			return nil, fmt.Errorf("spinel AST: node %d has attributes but no N record", id)
		}
		// A node without a position (such as BlockParametersNode, which has neither node_line nor an end position) can be read. In
		// the type join it becomes a node without a type (if it appears in an accepted form, analysis stops with Unknown)
		if n.FileID < 0 {
			continue
		}
		if _, ok := a.Files[n.FileID]; !ok {
			return nil, fmt.Errorf("spinel AST: node %d names file id %d with no FILE record", id, n.FileID)
		}
	}
	return a, nil
}

// unescape is the inverse of escape_str in spinel_parse.c. The implementation is `%XX` percent encoding (`%` → %25, newline → %0A,
// CR → %0D, tab → %09, space → %20, NUL → %00).
// docs/internals/AST.md says backslash escapes, which differs from the implementation (docs/upstream_suspects.md S4 — found from the
// operator name `%25` of `%`).
// `%` is always escaped, so every `%XX` may be decoded.
func unescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
