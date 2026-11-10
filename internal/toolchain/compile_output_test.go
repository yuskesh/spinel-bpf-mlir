package toolchain

import (
	"strings"
	"testing"
)

const (
	wIdx  = `the index of ebpf.ref.index can be a constant on one path and a non-constant value on another — loaders without CAP_PERFMON were observed to reject this pointer arithmetic on some kernels; keep the default out of the index (put the ref.index inside the present region) or make the default non-constant`
	wLoop = `the index of ebpf.ref.index is a value carried by an ebpf.loop without unroll`
)

func TestParseCompileOutput(t *testing.T) {
	for _, c := range []struct {
		name, stderr string
		want         []string
	}{
		{"empty", "", nil},
		{"const", `loc("idx.rb":19:11): warning: ` + wIdx + "\n" + `loc("idx.rb":12:10): note: the constant index comes from here` + "\n",
			[]string{"idx.rb:19:11|idx.rb:12:10"}},
		{"mdim", `loc("g.rb":49:11): warning: ` + wIdx + "\n" + `loc("g.rb":33:10): note: the constant index comes from here` + "\n" +
			`loc("g.rb":49:11): warning: ` + wIdx + "\n" + `loc("g.rb":11:10): note: the constant index comes from here` + "\n",
			[]string{"g.rb:49:11|g.rb:33:10", "g.rb:49:11|g.rb:11:10"}},
		{"loop", `loc("x.rb":11:12): warning: ` + wLoop + "\n" + `loc("x.rb":22:13): warning: ` + wLoop + "\n",
			[]string{"x.rb:11:12|", "x.rb:22:13|"}},
		{"sub dir", `loc("a/b.rb":1:2): warning: w` + "\n", []string{"a/b.rb:1:2|"}},
	} {
		ws, err := ParseCompileOutput("", c.stderr)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var got []string
		for _, w := range ws {
			var ns []string
			for _, n := range w.Notes {
				ns = append(ns, n.Loc.String())
				if n.Msg != "the constant index comes from here" {
					t.Errorf("%s: note message %q", c.name, n.Msg)
				}
			}
			got = append(got, w.Loc.String()+"|"+strings.Join(ns, ","))
			if w.Msg != wIdx && w.Msg != wLoop && w.Msg != "w" {
				t.Errorf("%s: message %q", c.name, w.Msg)
			}
		}
		if strings.Join(got, ";") != strings.Join(c.want, ";") {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestParseCompileOutputFailsClosed(t *testing.T) {
	for _, c := range []struct{ name, stdout, stderr, line string }{
		{"error line", "", `loc("idx.rb":3:4): error: boom` + "\n", `error: boom`},
		{"no loc", "", "some new output\n", "some new output"},
		{"note first", "", `loc("idx.rb":12:10): note: the constant index comes from here` + "\n", "note: the constant"},
		{"absolute loc", "", `loc("/abs/idx.rb":1:1): warning: w` + "\n", "/abs/idx.rb"},
		{"blank line", "", `loc("idx.rb":1:1): warning: w` + "\n\n", `""`},
		{"remark", "", `loc("idx.rb":1:1): remark: r` + "\n", "remark: r"},
		{"stdout", "hello\n", "", "hello"},
	} {
		_, err := ParseCompileOutput(c.stdout, c.stderr)
		if err == nil || !strings.Contains(err.Error(), "a new output shape of ebpf-compile; update spinelbpf's reader") || !strings.Contains(err.Error(), c.line) {
			t.Errorf("%s: want a fail-closed error naming %q, got %v", c.name, c.line, err)
		}
	}
}
