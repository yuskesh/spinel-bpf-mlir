package frontend

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoundaries(t *testing.T) {
	head := "require \"bpf\"\n\nOut = BPF::ArrayMap.new(\"Out\", :i64, 4)\nU = BPF::ArrayMap.new(\"U\", :u32, 4)\nI = BPF::ArrayMap.new(\"I\", :i32, 4)\nW = BPF::ArrayMap.new(\"W\", :u64, 4)\n\ndef prog(ctx)\n"
	tail := "  BPF::XDP_PASS\nend\nBPF.xdp :prog\n"
	cases := []struct {
		name, body string
		want       Code
	}{
		{"add fits", "  a = 9223372036854775806\n  Out.update(0, a + 1)\n", ""},
		{"add overflows", "  a = 9223372036854775806\n  Out.update(0, a + 2)\n", SB014SemanticGap},
		{"sub fits", "  a = -9223372036854775807\n  Out.update(0, a - 1)\n", ""},
		{"sub overflows", "  a = -9223372036854775807\n  Out.update(0, a - 2)\n", SB014SemanticGap},
		{"mul fits", "  a = 3037000499\n  Out.update(0, a * a)\n", ""},
		{"mul overflows", "  a = 3037000500\n  Out.update(0, a * a)\n", SB014SemanticGap},
		{"neg fits", "  a = -9223372036854775807\n  Out.update(0, -a)\n", ""},
		{"neg overflows", "  a = -9223372036854775807 - 1\n  Out.update(0, -a)\n", SB014SemanticGap},
		{"shl fits", "  a = 1\n  Out.update(0, a << 62)\n", ""},
		{"shl overflows", "  a = 2\n  Out.update(0, a << 62)\n", SB014SemanticGap},
		{"floor div of MinInt by -1 overflows", "  a = -9223372036854775807 - 1\n  Out.update(0, a / -1)\n", SB014SemanticGap},
		{"u32 store max", "  U.update(0, 4294967295)\n", ""},
		{"u32 store max+1", "  U.update(0, 4294967296)\n", SB014SemanticGap},
		{"u32 store masked sum", "  a = 4294967295\n  U.update(0, (a + 1) & 0xFFFF_FFFF)\n", ""},
		{"u32 store unmasked sum", "  a = 4294967295\n  U.update(0, a + 1)\n", SB014SemanticGap},
		{"u32 store negative", "  U.update(0, -1)\n", SB014SemanticGap},
		{"i32 store min", "  I.update(0, -2147483648)\n", ""},
		{"i32 store min-1", "  I.update(0, -2147483649)\n", SB014SemanticGap},
		{"i32 store max", "  I.update(0, 2147483647)\n", ""},
		{"i32 store max+1", "  I.update(0, 2147483648)\n", SB014SemanticGap},
		{"u64 store max", "  W.update(0, 9223372036854775807)\n", ""},
		{"u64 store negative", "  W.update(0, -1)\n", SB014SemanticGap},
		{"i64 store MinInt", "  a = -9223372036854775807 - 1\n  Out.update(0, a)\n", ""},
		{"key max", "  U.update(3, 1)\n", ""},
		{"key max+1", "  U.update(4, 1)\n", SB020KeyOutOfRange},
		{"key masked", "  a = 12345\n  U.update(a & 3, 1)\n", ""},
		{"key masked too wide", "  a = 12345\n  U.update(a & 7, 1)\n", SB020KeyOutOfRange},
		{"key modulo", "  a = 12345\n  U.update(a % 4, 1)\n", ""},
	}
	sp := testSpinel(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "b.rb")
			text := head + tc.body + tail
			os.WriteFile(src, []byte(text), 0o644)
			res, err := Analyze(sp, filepath.Join(dir, "work"), src, text)
			if err != nil {
				t.Fatal(err)
			}
			var blocking []Diag
			for _, d := range res.Diags {
				if d.Verdict == Rejected || d.Verdict == Unknown {
					blocking = append(blocking, d)
				}
			}
			if tc.want == "" {
				if len(blocking) > 0 {
					t.Fatalf("want accepted, got:\n%v", (&Error{Diags: res.Diags}).Error())
				}
				out, err := Generate(sp, filepath.Join(dir, "work2"), src)
				if err != nil {
					t.Fatal(err)
				}
				compileAll(t, out)
				return
			}
			if len(blocking) == 0 {
				t.Fatalf("want %s, accepted", tc.want)
			}
			for _, d := range blocking {
				if d.Code != tc.want {
					t.Errorf("want only %s, got %s", tc.want, d)
				}
			}
		})
	}
}
