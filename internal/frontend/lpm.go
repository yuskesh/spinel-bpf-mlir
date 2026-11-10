package frontend

import (
	"fmt"
	"math/big"
	"strings"
)

var lpmKey4 = &RecordDecl{
	Const:  "spinelbpf_lpm_key4",
	Fields: []RecordField{{Name: "prefixlen", Bits: 32, Offset: 0}, {Name: "addr", Bits: 8, Offset: 4, Count: 4}},
	Size:   8,
	Align:  4,
}

var lpmAddrByte = RecordField{Name: "addr", Bits: 8}

func (m *MapDecl) IsLpm() bool { return m.Kind == "lpm_trie" }

func (m *MapDecl) Flags() uint64 {
	if m.IsLpm() {
		return 1
	}
	return 0
}

func (c *progCtx) lpmKey(call *Node, m *MapDecl, as []*Node, refVar string) *Expr {
	if len(as) != 4 {
		c.add(Rejected, SB002UnsupportedCall, call, "`%s.lookup` takes the 4 bytes of an IPv4 address (`%s.lookup(a0, a1, a2, a3)` — e.g. `w.u8(30)` … `w.u8(33)`)", m.Const, m.Const)
		return nil
	}
	km := &MapDecl{Name: m.Name, Record: lpmKey4}
	bs := &Expr{Kind: "earr", Pos: c.z.pos(c.a, call)}
	for _, x := range as {
		e := c.fieldValue(x, &lpmAddrByte, km, refVar)
		if e == nil {
			return nil
		}
		bs.Args = append(bs.Args, e)
	}
	plen := big.NewInt(32)
	if mutation("lpm-plen24") {
		plen = big.NewInt(24)
	}
	return &Expr{Kind: "rmake", Map: km, Args: []*Expr{{Kind: "lit", Lit: plen, Iv: point(plen), Pos: c.z.pos(c.a, call)}, bs}, Pos: c.z.pos(c.a, call)}
}

func valueTypesText(kind string) string {
	if kind == "lpm_trie" {
		return ":u32|:i32"
	}
	return ":u32|:u64|:i32|:i64"
}

func valueTypesWords(kind string) string {
	if kind == "lpm_trie" {
		return ":u32 or :i32"
	}
	return ":u32, :u64, :i32 or :i64"
}

const lpmFuncs = `def _h_lkey(s)
  f = s.split(" ")[0].split("/")
  p = f[0].split(".")
  (((p[0].to_i << 24) | (p[1].to_i << 16) | (p[2].to_i << 8) | p[3].to_i) << 6) | f[1].to_i
end

def _h_lsort(a)
  out = [""]
  out.pop
  i = 0
  while i < a.length
    out.push(a[i])
    i += 1
  end
  i = 0
  while i < out.length
    j = i + 1
    while j < out.length
      if _h_lkey(out[j]) < _h_lkey(out[i])
        t = out[i]
        out[i] = out[j]
        out[j] = t
      end
      j += 1
    end
    i += 1
  end
  out
end
`

func hasLpm(res *Result) bool {
	for _, m := range res.Maps {
		if m.IsLpm() {
			return true
		}
	}
	return false
}

func lpmSetup(res *Result, kernel bool) string {
	if !hasLpm(res) {
		return ""
	}
	var b strings.Builder
	b.WriteString(lpmFuncs)
	for _, m := range res.Maps {
		if !m.IsLpm() || kernel {
			continue
		}
		if mutation("lpm-shortest") {
			fmt.Fprintf(&b, "%s._h_shortest\n", m.Const)
		}
		if mutation("lpm-full-overwrite") {
			fmt.Fprintf(&b, "%s._h_full_overwrite\n", m.Const)
		}
	}
	return b.String()
}

func lpmList(m *MapDecl, kernel bool) string {
	if kernel {
		return fmt.Sprintf("_h_obj.lpm_list(%s)", m.Const)
	}
	return m.Const + "._h_list"
}

func lpmReset(m *MapDecl, kernel bool) string {
	if !kernel {
		return fmt.Sprintf("      %s.reset\n", m.Const)
	}
	return fmt.Sprintf("      _h_ll = %s\n      _h_li = 0\n      while _h_li < _h_ll.length\n        _h_obj.lpm_remove(%s, _h_ll[_h_li].split(\" \")[0])\n        _h_li += 1\n      end\n", lpmList(m, true), m.Const)
}

func lpmDump(m *MapDecl, kernel bool) string {
	return fmt.Sprintf("      _h_ll = _h_lsort(%s)\n      _h_li = 0\n      while _h_li < _h_ll.length\n        puts \"%s{#{_h_ll[_h_li]}}\"\n        _h_li += 1\n      end\n", lpmList(m, kernel), m.Name)
}

func lpmCmds(res *Result, kernel bool) string {
	var b strings.Builder
	for _, m := range res.Maps {
		if !m.IsLpm() {
			continue
		}
		if kernel {
			fmt.Fprintf(&b, "    elsif _h_cmd == \"lput\" && _h_f[1] == %q\n      begin\n        _h_obj.lpm_put(%s, _h_f[2], _h_f[3].to_i)\n        puts \"lput=0\"\n      rescue SpinelBPF::Other => _h_le\n        if _h_le.message.include?(\"ENOSPC\")\n          puts \"lput=-28\"\n        else\n          puts \"lput=err=SpinelBPF::Other\"\n        end\n      end\n", m.Name, m.Const)
			fmt.Fprintf(&b, "    elsif _h_cmd == \"lremove\" && _h_f[1] == %q\n      if _h_obj.lpm_remove(%s, _h_f[2])\n        puts \"lremove=0\"\n      else\n        puts \"lremove=-2\"\n      end\n", m.Name, m.Const)
			fmt.Fprintf(&b, "    elsif _h_cmd == \"lmatch\" && _h_f[1] == %q\n      begin\n        puts \"lmatch=#{_h_obj.lpm_match(%s, _h_f[2])}\"\n      rescue SpinelBPF::NotFound\n        puts \"lmatch=absent\"\n      end\n", m.Name, m.Const)
			fmt.Fprintf(&b, "    elsif _h_cmd == \"lhas\" && _h_f[1] == %q\n      puts \"lhas=#{_h_obj.lpm_has(%s, _h_f[2])}\"\n", m.Name, m.Const)
			continue
		}
		fmt.Fprintf(&b, "    elsif _h_cmd == \"lput\" && _h_f[1] == %q\n      puts \"lput=#{%s._h_put(_h_f[2], _h_f[3].to_i)}\"\n", m.Name, m.Const)
		fmt.Fprintf(&b, "    elsif _h_cmd == \"lremove\" && _h_f[1] == %q\n      puts \"lremove=#{%s._h_remove(_h_f[2])}\"\n", m.Name, m.Const)
		fmt.Fprintf(&b, "    elsif _h_cmd == \"lmatch\" && _h_f[1] == %q\n      puts \"lmatch=#{%s._h_match(_h_f[2])}\"\n", m.Name, m.Const)
		fmt.Fprintf(&b, "    elsif _h_cmd == \"lhas\" && _h_f[1] == %q\n      puts \"lhas=#{%s._h_match(_h_f[2]) != \"absent\"}\"\n", m.Name, m.Const)
	}
	return b.String()
}
