package frontend

import (
	"fmt"
	"strings"
)

func keptSource(text string, res *Result) (string, error) {
	if len(res.Programs) == 0 {
		return "", fmt.Errorf("no program")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keep := make([]bool, len(lines))
	mark := func(from, to int) {
		if from == to && from >= 1 {
			depth := 0
			for l := from; l <= len(lines); l++ {
				depth += parenDelta(lines[l-1])
				to = l
				if depth <= 0 {
					break
				}
			}
		}
		for l := from; l <= to && l <= len(lines); l++ {
			if l >= 1 {
				keep[l-1] = true
			}
		}
	}
	for _, p := range res.Programs {
		mark(p.Pos.Line, p.EndLine)
		mark(p.DeclPos.Line, p.DeclPos.Line)
	}
	for _, f := range res.Funcs {
		mark(f.Pos.Line, f.EndLine)
	}
	for _, m := range res.Maps {
		mark(m.Pos.Line, m.Pos.Line)
		for _, r := range []*RecordDecl{m.Record, m.KeyRecord} {
			if r != nil {
				mark(r.StructPos.Line, r.StructPos.Line)
				mark(r.Pos.Line, r.Pos.Line)
			}
		}
	}
	for _, l := range ringLines(res) {
		mark(l, l)
	}
	for _, d := range res.KernelTypes {
		mark(d.StructPos.Line, d.StructPos.Line)
		mark(d.Pos.Line, d.Pos.Line)
		for _, h := range d.HandlePoss {
			mark(h.Line, h.Line)
		}
	}
	for _, g := range res.Globals {
		mark(g.Pos.Line, g.Pos.Line)
	}
	for i, l := range lines {
		if requireBPF.MatchString(l) {
			keep[i] = true
		}
	}
	var b strings.Builder
	for i, l := range lines {
		if keep[i] {
			b.WriteString(l)
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func harness(res *Result, prelude, put, run, runPkt, get string, kernel bool, extra ...string) string {
	var b strings.Builder
	b.WriteString(prelude)
	b.WriteString(hexFunc)
	b.WriteString(recordPokeFuncs(res, kernel))
	b.WriteString(ringSetup(res, kernel))
	b.WriteString(hashSetup(res, kernel))
	b.WriteString(pcpuSetup(res, kernel))
	b.WriteString(lpmSetup(res, kernel))
	b.WriteString("while (_h_line = $stdin.gets)\n  _h_f = _h_line.split(\" \")\n  _h_cmd = _h_f[0]\n  begin\n")
	b.WriteString("    if _h_cmd == \"reset\"\n")
	for _, m := range res.Maps {
		if m.IsDevmap() && kernel {
			continue
		}
		if m.Kind == "sockmap" && kernel {
			continue
		}
		if m.IsLpm() {
			b.WriteString(lpmReset(m, kernel))
			continue
		}
		if m.PerCPU() && m.IsArray() && kernel {
			b.WriteString(pcpuArrayReset(m))
			continue
		}
		if m.IsHash() {
			b.WriteString(hashReset(m, kernel))
			continue
		}
		if m.Record != nil {
			b.WriteString(recordReset(m, kernel))
			continue
		}
		fmt.Fprintf(&b, "      _h_k = 0\n      while _h_k < %d\n        %s\n        _h_k += 1\n      end\n", m.MaxEntries, fmt.Sprintf(put, m.Const, "_h_k", "0"))
	}
	for _, r := range res.Rings {
		b.WriteString(ringDrain(r, kernel, false))
	}
	b.WriteString("      puts \"ok\"\n    elsif _h_cmd == \"poke\"\n")
	for i, m := range res.Maps {
		kw := "if"
		if i > 0 {
			kw = "elsif"
		}
		if m.IsLpm() {
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        raise \"poke is not for lpm_trie maps (lput)\"\n", kw, m.Name)
			continue
		}
		if m.Kind == "sockmap" {
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        raise \"poke is not for sockmaps (sput)\"\n", kw, m.Name)
			continue
		}
		if m.PerCPU() && (m.IsHash() || m.Record != nil) {
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        raise \"poke is for per-CPU integer arrays\"\n", kw, m.Name)
			continue
		}
		if m.PerCPU() && kernel {
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_pv = Array.new(_h_ncpu, 0)\n        _h_pv[0] = _h_f[3].to_i\n        _h_obj.percpu_put(%s, _h_f[2].to_i, _h_pv)\n", kw, m.Name, m.Const)
			continue
		}
		if m.IsHash() {
			if m.KeyRecord == nil && m.Record == nil {
				put := "%s.update(_h_f[2].to_i, _h_f[3].to_i)"
				if kernel {
					put = "_h_obj.hash_put(%s, _h_f[2].to_i, _h_f[3].to_i)"
				}
				fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        "+put+"\n", kw, m.Name, m.Const)
			} else {
				fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        raise \"poke is for integer-keyed, integer-valued hash maps\"\n", kw, m.Name)
			}
			continue
		}
		if m.Record != nil {
			obj := ""
			if kernel {
				obj = "_h_obj, "
			}
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_rpoke_%s(%s_h_f[2].to_i, _h_f[3], _h_f[4].to_i)\n", kw, m.Name, m.Name, obj)
			continue
		}
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        %s\n", kw, m.Name, fmt.Sprintf(put, m.Const, "_h_f[2].to_i", "_h_f[3].to_i"))
	}
	if len(res.Maps) > 0 {
		b.WriteString("      end\n")
	}
	if kernel {
		b.WriteString("      puts \"ok\"\n    elsif _h_cmd == \"task\"\n      puts \"ok\"\n    elsif _h_cmd == \"run\"\n")
	} else {
		b.WriteString("      puts \"ok\"\n    elsif _h_cmd == \"task\"\n      BPF::TASK[0] = _h_f[1].to_i\n      puts \"ok\"\n")
		if hasComm(res) {
			b.WriteString("    elsif _h_cmd == \"comm\"\n      BPF.set_comm(_h_f[1])\n      puts \"comm=#{_h_hexs(BPF::TASK_COMM, 0, 16)}\"\n")
		}
		b.WriteString("    elsif _h_cmd == \"run\"\n")
	}
	for i, p := range res.Programs {
		kw := "if"
		if i > 0 {
			kw = "elsif"
		}
		if p.Kind == "sched_cls" {
			runPktTC, runTC := "%s(BPF::SkBuff.new(_h_hex(_h_f[2])))", "%s(BPF::SkBuff.new(Array.new(64, 0)))"
			if kernel {
				runPktTC, runTC = "_h_obj.test_run_tc_packet(%q, _h_hex(_h_f[2]))", "_h_obj.test_run_tc_packet(%q, Array.new(64, 0))"
			}
			fmt.Fprintf(&b, "      %s _h_f[1] == %q && _h_f.length > 2\n        puts \"ret=#{%s}\"\n", kw, p.Name, fmt.Sprintf(runPktTC, p.Name))
			fmt.Fprintf(&b, "      elsif _h_f[1] == %q\n        puts \"ret=#{%s}\"\n", p.Name, fmt.Sprintf(runTC, p.Name))
			continue
		}
		if p.Kind == "flow_dissector" {
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_d = Array.new(64, 0)\n        if _h_f.length > 2\n          _h_d = _h_hex(_h_f[2])\n        end\n", kw, p.Name)
			if kernel {
				fmt.Fprintf(&b, "        _h_k = _h_obj.test_run_flow_dissector(%q, _h_d)\n        puts \"ret=#{_h_k[0]} keys=#{_h_k[1, 20].join(\",\")}\"\n", p.Name)
			} else {
				clamp := 1
				if mutation("flow-noclamp") {
					clamp = 0
				}
				fmt.Fprintf(&b, "        _h_c = BPF::FlowCtx.new(_h_d)\n        _h_r = %s(_h_c)\n        puts \"ret=#{_h_r} keys=#{_h_c._h_keys(%d).join(\",\")}\"\n", p.Name, clamp)
			}
			continue
		}
		if p.Kind == "sk_lookup" {
			b.WriteString(skRun(kw, p, kernel))
			continue
		}
		if p.Kind == "netfilter" {
			if kernel {
				fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        puts \"ret=#{_h_obj.test_run_netfilter(%q, _h_hex(_h_f[2]), _h_f[4].to_i, _h_f[3].to_i)}\"\n", kw, p.Name, p.Name)
			} else {
				b.WriteString(nfTwinRun(kw, p, res.KernelTypes))
			}
			continue
		}
		if p.Kind == "cgroup_skb" {
			hdr := 14
			if mutation("cg-win-l2") {
				hdr = 0
			}
			runPktCG, runCG := fmt.Sprintf("%%s(BPF::CgroupSkb.new(_h_hex(_h_f[2]), %d))", hdr), fmt.Sprintf("%%s(BPF::CgroupSkb.new(Array.new(64, 0), %d))", hdr)
			if kernel {
				runPktCG, runCG = "_h_obj.test_run_skb_packet(%q, _h_hex(_h_f[2]))", "_h_obj.test_run_skb_packet(%q, Array.new(64, 0))"
			}
			fmt.Fprintf(&b, "      %s _h_f[1] == %q && _h_f.length > 2\n        puts \"ret=#{%s}\"\n", kw, p.Name, fmt.Sprintf(runPktCG, p.Name))
			fmt.Fprintf(&b, "      elsif _h_f[1] == %q\n        puts \"ret=#{%s}\"\n", p.Name, fmt.Sprintf(runCG, p.Name))
			continue
		}
		if p.Kind == "socket_filter" {
			hdr := 14
			if mutation("sf-len-l2") {
				hdr = 0
			}
			runPktSF, runSF := fmt.Sprintf("%%s(BPF::SocketFilterCtx.new(_h_hex(_h_f[2]).length, %d))", hdr), fmt.Sprintf("%%s(BPF::SocketFilterCtx.new(64, %d))", hdr)
			if kernel {
				runPktSF, runSF = "_h_obj.test_run_skb_packet(%q, _h_hex(_h_f[2]))", "_h_obj.test_run_skb_packet(%q, Array.new(64, 0))"
			}
			fmt.Fprintf(&b, "      %s _h_f[1] == %q && _h_f.length > 2\n        puts \"ret=#{%s}\"\n", kw, p.Name, fmt.Sprintf(runPktSF, p.Name))
			fmt.Fprintf(&b, "      elsif _h_f[1] == %q\n        puts \"ret=#{%s}\"\n", p.Name, fmt.Sprintf(runSF, p.Name))
			continue
		}
		if usesKernelTypes(p) && !kernel {
			b.WriteString(tpBtfTwinRun(kw, p, res.KernelTypes))
			continue
		}
		if p.Kind == "uprobe" || (kernel && p.Kind == "uretprobe") {
			if kernel {
				fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        if HUprobe.h_send(_h_f[2, _h_f.length - 2].join(\" \")) < 0\n          raise \"the uprobe target's child process did not answer\"\n        end\n", kw, p.Name)
				if p.Kind == "uretprobe" || hasPtrParam(p) {
					b.WriteString("        puts \"rv=#{HUprobe.h_last_value}\"\n")
				}
				b.WriteString("        puts \"ret=0\"\n")
			} else {
				b.WriteString(uprobeTwinRun(kw, p))
			}
			continue
		}
		if p.Kind != "xdp" {
			if kernel {
				b.WriteString(tracingKernelRun(kw, p))
			} else {
				b.WriteString(tracingTwinRun(kw, p))
			}
			continue
		}
		fmt.Fprintf(&b, "      %s _h_f[1] == %q && _h_f.length > 2\n        puts \"ret=#{%s}\"\n", kw, p.Name, fmt.Sprintf(runPkt, p.Name))
		fmt.Fprintf(&b, "      elsif _h_f[1] == %q\n        puts \"ret=#{%s}\"\n", p.Name, fmt.Sprintf(run, p.Name))
	}
	b.WriteString("      end\n    elsif _h_cmd == \"echo\"\n      puts \"## #{_h_f[1]}\"\n    elsif _h_cmd == \"dump\"\n")
	b.WriteString(globalDump(res, kernel))
	for _, m := range res.Maps {
		if m.IsDevmap() {
			continue
		}
		if m.Kind == "sockmap" {
			continue
		}
		if m.IsLpm() {
			b.WriteString(lpmDump(m, kernel))
			continue
		}
		if m.PerCPU() && m.IsArray() {
			b.WriteString(pcpuArrayDump(m, kernel))
			continue
		}
		if m.IsHash() {
			b.WriteString(hashDump(m, kernel))
			continue
		}
		if m.Record != nil {
			b.WriteString(recordDump(m, kernel))
			continue
		}
		fmt.Fprintf(&b, "      _h_k = 0\n      while _h_k < %d\n        begin\n          puts \"%s[#{_h_k}]=#{%s}\"\n        rescue => _h_e2\n          puts \"%s[#{_h_k}]=err=#{_h_e2.class}\"\n        end\n        _h_k += 1\n      end\n", m.MaxEntries, m.Name, fmt.Sprintf(get, m.Const, "_h_k"), m.Name)
	}
	for _, r := range res.Rings {
		fmt.Fprintf(&b, "    elsif _h_cmd == \"drain\" && _h_f[1] == %q\n", r.Name)
		b.WriteString(ringDrain(r, kernel, true))
	}
	b.WriteString(lpmCmds(res, kernel))
	b.WriteString(skCmds(res, kernel))
	for _, x := range extra {
		b.WriteString(x)
	}
	b.WriteString("    end\n  rescue => _h_e\n    puts \"err=#{_h_e.class}\"\n  end\n  $stdout.flush\nend\n")
	return b.String()
}

const hexFunc = `def _h_fa(names, strs, key, n)
  out = Array.new(n, 0)
  i = 0
  while i < names.length
    if names[i] == key
      h = strs[i]
      if h.length > 2 * n
        raise "#{key}: more than #{n} bytes"
      end
      j = 0
      while j + 1 < h.length
        out[j / 2] = h[j, 2].to_i(16)
        j += 2
      end
    end
    i += 1
  end
  out
end

# the string bytes of a strptr field (the hex length as is — without the NUL; empty if absent)
def _h_fs(names, strs, key)
  out = Array.new(0, 0)
  i = 0
  while i < names.length
    if names[i] == key
      h = strs[i]
      j = 0
      while j + 1 < h.length
        out.push(h[j, 2].to_i(16))
        j += 2
      end
    end
    i += 1
  end
  out
end

def _h_fv(names, vals, key)
  i = 0
  while i < names.length
    if names[i] == key
      return vals[i]
    end
    i += 1
  end
  0
end

def _h_hexs(a, off, n)
  d = "0123456789abcdef"
  s = ""
  i = 0
  while i < n
    x = a[off + i]
    s += d[x >> 4] + d[x & 15]
    i += 1
  end
  s
end

def _h_hex(hex)
  out = Array.new(0, 0)
  if hex == "-"
    return out
  end
  i = 0
  while i + 1 < hex.length
    out.push(hex[i, 2].to_i(16))
    i += 2
  end
  out
end
`

func tracingTwinRun(kw string, p *Program) string {
	var b strings.Builder
	if p.Kind == "fmod_ret" {
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_args = Array.new(12, 0)\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if false\n", kw, p.Name)
		for _, a := range p.TArgs {
			fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            _h_args[%d] = %s\n", a.Idx, a.Idx, widthCut("_h_kv[1].to_i", a.Type))
		}
		b.WriteString("          else\n            raise \"undeclared fmod_ret argument #{_h_kv[0]}\"\n          end\n          _h_i += 1\n        end\n")
		fmt.Fprintf(&b, "        puts \"ret=#{%s(BPF::FmodRetCtx.new(_h_args))}\"\n", p.Name)
		return b.String()
	}
	if p.Kind == "tracepoint" {
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_tpf = {", kw, p.Name)
		for i, f := range p.TFields {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q => 0", f.Name)
		}
		b.WriteString("}\n        _h_tps = {\"\" => BPF::UserStr.new(Array.new(0, 0), true)}\n        _h_tpa = {\"\" => " + argvTwinEmpty + "}\n        _h_tpb = {\"\" => Array.new(0, 0)}\n")
		for _, f := range p.TFields {
			if f.Type == "user_str" {
				fmt.Fprintf(&b, "        _h_tps[%q] = BPF::UserStr.new(Array.new(0, 0), true)\n", f.Name)
			}
			if f.Type == "user_str_array" {
				fmt.Fprintf(&b, "        _h_tpa[%q] = %s\n", f.Name, argvTwinEmpty)
			}
			if f.N > 0 {
				fmt.Fprintf(&b, "        _h_tpb[%q] = Array.new(%d, 0)\n", f.Name, f.N)
			}
		}
		b.WriteString("        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if false\n")
		for _, f := range p.TFields {
			if f.N > 0 {
				fmt.Fprintf(&b, "          elsif _h_kv[0] == %q\n            _h_bs = _h_kv[1].split(\",\")\n            _h_j = 0\n            while _h_j < _h_bs.length && _h_j < %d\n              _h_tpb[%q][_h_j] = _h_bs[_h_j].to_i & 255\n              _h_j += 1\n            end\n", f.Name, f.N, f.Name)
				continue
			}
			if f.Type == "user_str_array" {
				fmt.Fprintf(&b, "          elsif _h_kv[0] == %q\n%s", f.Name, argvTwinParse(fmt.Sprintf("_h_tpa[%q]", f.Name)))
				continue
			}
			if f.Type == "user_str" {
				fmt.Fprintf(&b, "          elsif _h_kv[0] == %q\n            if _h_kv[1] == \"@null\"\n              _h_tps[%q] = BPF::UserStr.new(Array.new(0, 0), true)\n            elsif _h_kv[1] == \"@empty\"\n              _h_tps[%q] = BPF::UserStr.new(Array.new(0, 0), false)\n            else\n              _h_tps[%q] = BPF::UserStr.new(_h_kv[1].bytes, false)\n            end\n", f.Name, f.Name, f.Name, f.Name)
				continue
			}
			fmt.Fprintf(&b, "          elsif _h_kv[0] == %q\n            _h_tpf[%q] = %s\n", f.Name, f.Name, widthCut("_h_kv[1].to_i", f.Type))
		}
		b.WriteString("          else\n            raise \"undeclared tracepoint field #{_h_kv[0]}\"\n          end\n          _h_i += 1\n        end\n")
		fmt.Fprintf(&b, "        %s(BPF::TracepointCtx.new(_h_tpf, _h_tps, _h_tpa, _h_tpb))\n        puts \"ret=0\"\n", p.Name)
		return b.String()
	}
	if p.Kind == "raw_tp" {
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_args = Array.new(12, 0)\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n", kw, p.Name)
		b.WriteString("          _h_n = -1\n          _h_j = 0\n          while _h_j < 12\n            if _h_kv[0] == \"a#{_h_j}\"\n              _h_n = _h_j\n            end\n            _h_j += 1\n          end\n          if _h_n < 0\n            raise \"undeclared context value #{_h_kv[0]}\"\n          end\n          _h_args[_h_n] = _h_kv[1].to_i\n          _h_i += 1\n        end\n")
		fmt.Fprintf(&b, "        %s(BPF::RawTpCtx.new(_h_args))\n", p.Name)
		b.WriteString("        puts \"ret=0\"\n")
		return b.String()
	}
	reads := ""
	if p.Kind == "kprobe" {
		reads = "        _h_reads = {\"\" => [0, 0]}\n"
	}
	if p.Kind == "ksyscall" {
		reads = "        _h_strs = Array.new(7, BPF::UserStr.new(Array.new(0, 0), true))\n        _h_arrs = Array.new(7, " + argvTwinEmpty + ")\n"
	}
	fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_ret = 0\n        _h_args = Array.new(7, 0)\n%s        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n", kw, p.Name, reads)
	b.WriteString("          if false\n")
	if p.Kind == "fexit" || p.Kind == "kretprobe" || p.Kind == "uretprobe" {
		fmt.Fprintf(&b, "          elsif _h_kv[0] == \"ret\"\n            _h_ret = %s\n", widthCut("_h_kv[1].to_i", p.Ret))
	}
	for _, kp := range p.Params {
		if kp.Type == "ptr" {
			fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            _h_args[%d] = _h_kv[1].to_i\n", kp.N, kp.N)
			continue
		}
		if kp.Type == "user_str" {
			fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            if _h_kv[1] == \"@null\"\n              _h_strs[%d] = BPF::UserStr.new(Array.new(0, 0), true)\n            elsif _h_kv[1] == \"@empty\"\n              _h_strs[%d] = BPF::UserStr.new(Array.new(0, 0), false)\n            else\n              _h_strs[%d] = BPF::UserStr.new(_h_kv[1].bytes, false)\n            end\n", kp.N, kp.N, kp.N, kp.N)
			continue
		}
		if kp.Type == "user_str_array" {
			fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n%s", kp.N, argvTwinParse(fmt.Sprintf("_h_arrs[%d]", kp.N)))
			continue
		}
		fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            _h_args[%d] = %s\n", kp.N, kp.N, widthCut("_h_kv[1].to_i", kp.Type))
	}
	if p.Kind == "kprobe" {
		b.WriteString("          elsif _h_kv[0][0] == \"r\" || _h_kv[0][0] == \"s\"\n            _h_k = _h_kv[0][1, _h_kv[0].length - 1]\n            if !_h_reads.key?(_h_k)\n              _h_reads[_h_k] = [0, 0]\n            end\n            if _h_kv[0][0] == \"r\"\n              _h_reads[_h_k][0] = _h_kv[1].to_i\n            else\n              _h_reads[_h_k][1] = _h_kv[1].to_i\n            end\n")
	}
	b.WriteString("          else\n            raise \"undeclared context value #{_h_kv[0]}\"\n          end\n          _h_i += 1\n        end\n")
	switch p.Kind {
	case "fexit":
		fmt.Fprintf(&b, "        %s(BPF::FexitCtx.new(_h_ret))\n", p.Name)
	case "kprobe":
		fmt.Fprintf(&b, "        %s(BPF::KprobeCtx.new(_h_args, _h_reads))\n", p.Name)
	case "ksyscall":
		fmt.Fprintf(&b, "        %s(BPF::KsyscallCtx.new(_h_args, _h_strs, _h_arrs))\n", p.Name)
	case "uretprobe":
		fmt.Fprintf(&b, "        %s(BPF::UretprobeCtx.new(_h_ret))\n", p.Name)
	case "kretprobe":
		fmt.Fprintf(&b, "        %s(BPF::KretprobeCtx.new(_h_ret))\n", p.Name)
	default:
		fmt.Fprintf(&b, "        %s(BPF::FentryCtx.new)\n", p.Name)
	}
	b.WriteString("        puts \"ret=0\"\n")
	return b.String()
}

func hasRawTp(res *Result) bool { return hasKind(res, "raw_tp") }

func hasStrptr(res *Result) bool {
	for _, d := range res.KernelTypes {
		for _, f := range d.Fields {
			if f.Kind == "strptr" {
				return true
			}
		}
	}
	return false
}

const hSpawnC = `    static int h_spawn_fd = -1;
    long h_spawn(const char *path) {
      int p[2];
      if (pipe(p) != 0) return -1;
      pid_t c = fork();
      if (c < 0) { close(p[0]); close(p[1]); return -1; }
      if (c == 0) {
        char x;
        close(p[1]);
        if (read(p[0], &x, 1) != 1) _exit(126);
        char *argv[] = {(char *)path, 0};
        char *envp[] = {0};
        execve(path, argv, envp);
        _exit(127);
      }
      close(p[0]);
      h_spawn_fd = p[1];
      return (long)c;
    }
    long h_release(long c) {
      int st = 0;
      if (write(h_spawn_fd, "x", 1) != 1) return -1;
      close(h_spawn_fd);
      h_spawn_fd = -1;
      if (waitpid((pid_t)c, &st, 0) < 0) return -1;
      return (long)st;
    }
`

func hasKprobePtr(res *Result) bool {
	for _, p := range res.Programs {
		for _, kp := range p.Params {
			if p.Kind == "kprobe" && kp.Type == "ptr" {
				return true
			}
		}
	}
	return false
}

func hasKind(res *Result, kind string) bool {
	for _, p := range res.Programs {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

func widthCut(x, t string) string {
	rt := recordTypes[t]
	bits, signed := rt[0], rt[1] == 1
	if bits == 64 {
		return x
	}
	mask := fmt.Sprintf("0x%X", uint64(1)<<bits-1)
	if !signed {
		return fmt.Sprintf("(%s & %s)", x, mask)
	}
	return fmt.Sprintf("(((%s & %s) ^ 0x%X) - 0x%X)", x, mask, uint64(1)<<(bits-1), uint64(1)<<(bits-1))
}

func TwinHarness(text string, res *Result) (string, error) {
	k, err := keptSource(text, res)
	if err != nil {
		return "", err
	}
	if err := nfTwinCheck(res); err != nil {
		return "", err
	}
	run, runPkt := "%s(BPF::XdpMd.new(Array.new(64, 0)))", "%s(BPF::XdpMd.new(_h_hex(_h_f[2])))"
	if mutation("ifx-zero") {
		run, runPkt = "%s(BPF::XdpMd.new(Array.new(64, 0))._h_ifx(0))", "%s(BPF::XdpMd.new(_h_hex(_h_f[2]))._h_ifx(0))"
	}
	pre := recordTwinCode(res) + globalConfigLoop(res, false)
	if mutation("adjh-bound") || mutation("adjt-bound") {
		pre = "BPF::ADJH_BOUND[0] = 13\n" + pre
	}
	return k + "# spinelbpf twin harness\n" + harness(res, pre, "%s.poke(%s, %s)", run, runPkt, "%s.peek(%s)", false), nil
}

func KernelHarness(text string, res *Result) (string, error) {
	k, err := keptSource(text, res)
	if err != nil {
		return "", err
	}
	pre := "# spinelbpf kernel harness\nrequire \"spinelbpf\"\n" + globalConfigLoop(res, true) + tracingKernelSetup(res) + skHarnessSetup(res)
	return k + harness(res, pre, "_h_obj.map_put(%s, %s, %s)", "_h_obj.test_run_xdp(%q, 1)", "_h_obj.test_run_xdp_packet(%q, _h_hex(_h_f[2]))", "_h_obj.map_get(%s, %s)", true, tracingKernelCmds(res)), nil
}

func recordTwinCode(res *Result) string {
	var b strings.Builder
	b.WriteString("# spinelbpf twin records\n")
	b.WriteString("class HArr\n  def initialize(v, off, n)\n    @v = v\n    @off = off\n    @n = n\n  end\n\n  def [](i)\n    if i < 0 || i >= @n\n      raise IndexError, \"twin: index outside the array member\"\n    end\n    @v[@off + i]\n  end\n\n  def []=(i, x)\n    if i < 0 || i >= @n\n      raise IndexError, \"twin: index outside the array member\"\n    end\n    @v[@off + i] = x\n  end\nend\n")
	recs := usedRecords(res)
	for _, r := range recs {
		if r == lpmKey4 {
			continue
		}
		fmt.Fprintf(&b, "class HView%s\n  def initialize(v)\n    @v = v\n  end\n", r.Const)
		for i, f := range r.Fields {
			if f.Pad {
				continue
			}
			if f.Count > 0 {
				fmt.Fprintf(&b, "\n  def %s\n    HArr.new(@v, %d, %d)\n  end\n", f.Name, flatBase(r, i), f.Count)
				if f.Bits == 8 {
					fmt.Fprintf(&b, "\n  def %s=(a)\n    if a.length != %d\n      raise IndexError, \"twin: the copy is not %d bytes\"\n    end\n    i = 0\n    while i < %d\n      @v[%d + i] = a[i]\n      i += 1\n    end\n  end\n", f.Name, f.Count, f.Count, f.Count, flatBase(r, i))
				}
				continue
			}
			fmt.Fprintf(&b, "\n  def %s\n    @v[%d]\n  end\n\n  def %s=(x)\n    @v[%d] = x\n  end\n", f.Name, flatBase(r, i), f.Name, flatBase(r, i))
		}
		b.WriteString("end\n")
	}
	b.WriteString("def _h_flat(name, s)\n")
	for _, m := range res.Maps {
		if m.Record == nil || !m.Record.HasArray() {
			continue
		}
		var es []string
		for _, f := range m.Record.Fields {
			if f.Count == 0 {
				es = append(es, "s."+f.Name)
				continue
			}
			for k := 0; k < f.Count; k++ {
				es = append(es, fmt.Sprintf("s.%s[%d]", f.Name, k))
			}
		}
		fmt.Fprintf(&b, "  if name == %q\n    return [%s]\n  end\n", m.Name, strings.Join(es, ", "))
	}
	b.WriteString("  s.to_a\nend\n")
	b.WriteString("def _h_view(name, arr)\n")
	var first *MapDecl
	for _, m := range res.Maps {
		if m.Record == nil {
			continue
		}
		if first == nil {
			first = m
		}
		fmt.Fprintf(&b, "  if name == %q\n    return HView%s.new(arr)\n  end\n", m.Name, m.Record.Const)
	}
	if first != nil {
		fmt.Fprintf(&b, "  HView%s.new(arr)\nend\n", first.Record.Const)
	} else {
		b.WriteString("  arr\nend\n")
	}
	b.WriteString("def _h_radd(name, arr, m, d, e)\n")
	for _, m := range res.Maps {
		if m.Record == nil {
			continue
		}
		for fi, f := range m.Record.Fields {
			if f.Pad || (f.Bits != 32 && f.Bits != 64) {
				continue
			}
			fmt.Fprintf(&b, "  if name == %q && m == :%s\n", m.Name, f.Name)
			i, dv := fmt.Sprint(flatBase(m.Record, fi)), "d"
			if f.Count > 0 {
				i, dv = fmt.Sprintf("%d + d", flatBase(m.Record, fi)), "e"
			}
			switch {
			case f.Bits == 32 && !f.Signed:
				fmt.Fprintf(&b, "    arr[%s] = (arr[%s] + %s) & 0xFFFFFFFF\n", i, i, dv)
			case f.Bits == 32:
				fmt.Fprintf(&b, "    w = (arr[%s] + %s) & 0xFFFFFFFF\n    if w >= 2147483648\n      w -= 4294967296\n    end\n    arr[%s] = w\n", i, dv, i)
			default:
				fmt.Fprintf(&b, "    arr[%s] = arr[%s] + %s\n", i, i, dv)
			}
			b.WriteString("  end\n")
		}
	}
	b.WriteString("  0\nend\n")
	return b.String()
}

func recordPokeFuncs(res *Result, kernel bool) string {
	var b strings.Builder
	for _, m := range res.Maps {
		if m.Record == nil {
			continue
		}
		if kernel {
			fmt.Fprintf(&b, "def _h_rpoke_%s(obj, k, member, value)\n  v = obj.map_get_record(%s, k)\n", m.Name, m.Const)
		} else {
			fmt.Fprintf(&b, "def _h_rpoke_%s(k, member, value)\n  v = %s.slot(k)\n", m.Name, m.Const)
		}
		for _, x := range flatSlots(m.Record) {
			if !x.pad {
				fmt.Fprintf(&b, "  if member == %q\n    v[%d] = value\n  end\n", x.name, x.idx)
			}
		}
		if kernel && m.Record.HasArray() {
			fmt.Fprintf(&b, "  obj.map_put_record_values(%s, k, v)\n", m.Const)
		} else if kernel {
			var as []string
			for i := range m.Record.Fields {
				as = append(as, fmt.Sprintf("v[%d]", i))
			}
			fmt.Fprintf(&b, "  obj.map_put_record(%s, k, %s.new(%s))\n", m.Const, m.Record.Const, strings.Join(as, ", "))
		}
		b.WriteString("  0\nend\n")
	}
	return b.String()
}

func recordReset(m *MapDecl, kernel bool) string {
	if !kernel {
		return fmt.Sprintf("      %s.reset\n", m.Const)
	}
	if m.Record.HasArray() {
		return fmt.Sprintf("      _h_k = 0\n      while _h_k < %d\n        _h_obj.map_put_record_values(%s, _h_k, Array.new(%d, 0))\n        _h_k += 1\n      end\n", m.MaxEntries, m.Const, len(flatSlots(m.Record)))
	}
	zeros := strings.TrimSuffix(strings.Repeat("0, ", len(m.Record.Fields)), ", ")
	return fmt.Sprintf("      _h_k = 0\n      while _h_k < %d\n        _h_obj.map_put_record(%s, _h_k, %s.new(%s))\n        _h_k += 1\n      end\n", m.MaxEntries, m.Const, m.Record.Const, zeros)
}

func recordDump(m *MapDecl, kernel bool) string {
	var b strings.Builder
	get := fmt.Sprintf("%s.slot(_h_k)", m.Const)
	if kernel {
		get = fmt.Sprintf("_h_obj.map_get_record(%s, _h_k)", m.Const)
	}
	fmt.Fprintf(&b, "      _h_k = 0\n      while _h_k < %d\n        begin\n          _h_v = %s\n", m.MaxEntries, get)
	for _, x := range flatSlots(m.Record) {
		if !x.pad {
			fmt.Fprintf(&b, "          puts \"%s[#{_h_k}].%s=#{_h_v[%d]}\"\n", m.Name, x.name, x.idx)
		}
	}
	b.WriteString("        rescue => _h_e2\n")
	for _, x := range flatSlots(m.Record) {
		if !x.pad {
			fmt.Fprintf(&b, "          puts \"%s[#{_h_k}].%s=err=#{_h_e2.class}\"\n", m.Name, x.name)
		}
	}
	b.WriteString("        end\n        _h_k += 1\n      end\n")
	return b.String()
}

func ringSetup(res *Result, kernel bool) string {
	var b strings.Builder
	for _, r := range res.Rings {
		if kernel {
			fmt.Fprintf(&b, "_h_rd_%s = _h_obj.ringbuf(%s)\n", r.Name, r.Const)
			continue
		}
		limit := r.Size - 1
		if mutation("ring-model") {
			limit = r.Size
		}
		fmt.Fprintf(&b, "%s._h_set(%d, %d)\n", r.Const, r.Record.Size, limit)
	}
	return b.String()
}

func ringDrain(r *RingDecl, kernel, show bool) string {
	var b strings.Builder
	line := func(ind, ev string) {
		if !show {
			return
		}
		fi := 0
		for i, f := range r.Record.Fields {
			switch {
			case f.Pad:
			case f.Count > 0 && kernel:
				fmt.Fprintf(&b, "%sputs \"%s##{_h_n}.%s=#{_h_hexs(%s, %d, %d)}\"\n", ind, r.Name, f.Name, ev, fi, f.Count)
			case f.Count > 0:
				fmt.Fprintf(&b, "%sputs \"%s##{_h_n}.%s=#{_h_hexs(%s[%d], 0, %d)}\"\n", ind, r.Name, f.Name, ev, i, f.Count)
			case kernel:
				fmt.Fprintf(&b, "%sputs \"%s##{_h_n}.%s=#{%s[%d]}\"\n", ind, r.Name, f.Name, ev, fi)
			default:
				fmt.Fprintf(&b, "%sputs \"%s##{_h_n}.%s=#{%s[%d]}\"\n", ind, r.Name, f.Name, ev, i)
			}
			if f.Count > 0 {
				fi += f.Count
			} else {
				fi++
			}
		}
	}
	if kernel {
		fmt.Fprintf(&b, "      _h_n = 0\n      _h_ev_%s = _h_rd_%s.read_record(0)\n      while _h_ev_%s.length > 0\n", r.Name, r.Name, r.Name)
		line("        ", "_h_ev_"+r.Name)
		fmt.Fprintf(&b, "        _h_n += 1\n        _h_ev_%s = _h_rd_%s.read_record(0)\n      end\n", r.Name, r.Name)
	} else {
		fmt.Fprintf(&b, "      _h_evs_%s = %s.drain\n      _h_n = 0\n      while _h_n < _h_evs_%s.length\n", r.Name, r.Const, r.Name)
		line("        ", "_h_evs_"+r.Name+"[_h_n]")
		b.WriteString("        _h_n += 1\n      end\n")
	}
	if show {
		fmt.Fprintf(&b, "      puts \"%s drained=#{_h_n}\"\n", r.Name)
	}
	return b.String()
}

func hashSetup(res *Result, kernel bool) string {
	var b strings.Builder
	for _, m := range res.Maps {
		if m.IsHash() && !kernel && mutation("hash-cap") {
			fmt.Fprintf(&b, "%s._h_cap(%d)\n", m.Const, m.MaxEntries+1)
		}
	}
	return b.String()
}

func hashKeyLoop(m *MapDecl, kernel bool, body string) string {
	var b strings.Builder
	switch {
	case !kernel:
		fmt.Fprintf(&b, "      _h_ks = %s._h_keys\n      _h_i = 0\n      while _h_i < _h_ks.length\n        _h_kstr = _h_ks[_h_i]\n", m.Const)
	case m.KeyRecord == nil:
		fmt.Fprintf(&b, "      _h_ki = _h_obj."+pcpuName(m, "hash_keys")+"(%s)\n      _h_i = 0\n      while _h_i < _h_ki.length\n        _h_kobj = _h_ki[_h_i]\n        _h_kstr = _h_kobj.to_s\n", m.Const)
	default:
		var as []string
		for i := range m.KeyRecord.Fields {
			as = append(as, fmt.Sprintf("_h_ka[%d]", i))
		}
		fmt.Fprintf(&b, "      _h_kr = _h_obj."+pcpuName(m, "hash_keys_rk")+"(%s)\n      _h_i = 0\n      while _h_i < _h_kr.length\n        _h_ka = _h_kr[_h_i]\n        _h_kstr = _h_ka.join(\",\")\n        _h_kobj%s = %s.new(%s)\n", m.Const, m.Name, m.KeyRecord.Const, strings.Join(as, ", "))
	}
	b.WriteString(body)
	b.WriteString("        _h_i += 1\n      end\n")
	return b.String()
}

func hashReset(m *MapDecl, kernel bool) string {
	if !kernel {
		return fmt.Sprintf("      %s.reset\n", m.Const)
	}
	del := fmt.Sprintf("        _h_obj.%s(%s, _h_kobj)\n", pcpuName(m, "hash_delete"), m.Const)
	if m.KeyRecord != nil {
		del = fmt.Sprintf("        _h_obj.%s(%s, _h_kobj%s)\n", pcpuName(m, "hash_delete_rk"), m.Const, m.Name)
	}
	return hashKeyLoop(m, true, del)
}

func hashDump(m *MapDecl, kernel bool) string {
	if m.Kind == "lru_hash" {
		if !kernel {
			return fmt.Sprintf("      puts \"%s count=#{%s._h_keys.length}\"\n", m.Name, m.Const)
		}
		f := "hash_keys"
		if m.KeyRecord != nil {
			f = "hash_keys_rk"
		}
		return fmt.Sprintf("      puts \"%s count=#{_h_obj.%s(%s).length}\"\n", m.Name, f, m.Const)
	}
	val := fmt.Sprintf("%s._h_val(_h_kstr)", m.Const)
	nz := ""
	if m.PerCPU() {
		nz = fmt.Sprintf("\\n%s{#{_h_kstr}} nz=#{_h_n}", m.Name)
	}
	if kernel && m.PerCPU() {
		kobj, sfx := "_h_kobj", ""
		if m.KeyRecord != nil {
			kobj, sfx = "_h_kobj"+m.Name, "_rk"
		}
		if m.Record != nil {
			val = fmt.Sprintf("_h_obj.percpu_hash_get_record%s(%s, %s)", sfx, m.Const, kobj)
		} else {
			val = fmt.Sprintf("SpinelBPF.wraps(_h_obj.percpu_hash_get%s(%s, %s))", sfx, m.Const, kobj)
		}
	} else if kernel {
		kobj, sfx := "_h_kobj", ""
		if m.KeyRecord != nil {
			kobj, sfx = "_h_kobj"+m.Name, "_rk"
		}
		if m.Record != nil {
			val = fmt.Sprintf("_h_obj.hash_get_record%s(%s, %s)", sfx, m.Const, kobj)
		} else {
			val = fmt.Sprintf("[_h_obj.hash_get%s(%s, %s)]", sfx, m.Const, kobj)
		}
	}
	var line []string
	if m.Record == nil {
		line = append(line, fmt.Sprintf("%s{#{_h_kstr}}=#{_h_v[0]}", m.Name))
	} else {
		for i, f := range m.Record.Fields {
			if !f.Pad {
				line = append(line, fmt.Sprintf("%s{#{_h_kstr}}.%s=#{_h_v[%d]}", m.Name, f.Name, i))
			}
		}
	}
	body := fmt.Sprintf("        _h_v = %s\n        _h_es.push(\"#{_h_kstr}\\x01%s\")\n", val, strings.Join(line, "\\n"))
	if m.PerCPU() {
		conv := "        _h_n = _h_nz1(_h_v)\n"
		if kernel {
			conv = "        _h_n = _h_nzr(_h_v)\n        _h_v = _h_colsum(_h_v)\n"
		}
		body = fmt.Sprintf("        _h_v = %s\n%s        _h_es.push(\"#{_h_kstr}\\x01%s%s\")\n", val, conv, strings.Join(line, "\\n"), nz)
	}
	var b strings.Builder
	b.WriteString("      _h_es = [\"\"]\n      _h_es.pop\n")
	b.WriteString(hashKeyLoop(m, kernel, body))
	b.WriteString("      _h_es = _h_es.sort\n      _h_j = 0\n      while _h_j < _h_es.length\n        _h_e = _h_es[_h_j]\n        puts _h_e[_h_e.index(\"\\x01\") + 1, _h_e.length]\n        _h_j += 1\n      end\n")
	return b.String()
}

func pcpuName(m *MapDecl, name string) string {
	if m.PerCPU() {
		return "percpu_" + name
	}
	return name
}

func pcpuSetup(res *Result, kernel bool) string {
	has := false
	for _, m := range res.Maps {
		has = has || m.PerCPU()
	}
	if !has {
		return ""
	}
	var b strings.Builder
	b.WriteString("def _h_nz1(v)\n  i = 0\n  while i < v.length\n    if v[i] != 0\n      return 1\n    end\n    i += 1\n  end\n  0\nend\n")
	b.WriteString("def _h_nzr(rows)\n  n = 0\n  j = 0\n  while j < rows.length\n    n += _h_nz1(rows[j])\n    j += 1\n  end\n  n\nend\n")
	b.WriteString("def _h_colsum(rows)\n  out = Array.new(rows[0].length, 0)\n  j = 0\n  while j < rows.length\n    i = 0\n    while i < out.length\n      out[i] += rows[j][i]\n      i += 1\n    end\n    j += 1\n  end\n  out\nend\n")
	if kernel {
		b.WriteString("_h_ncpu = SpinelBPF.possible_cpus\n")
		for _, m := range res.Maps {
			if m.PerCPU() && m.IsArray() && m.Record != nil {
				zeros := strings.TrimSuffix(strings.Repeat("0, ", len(m.Record.Fields)), ", ")
				fmt.Fprintf(&b, "_h_z%s = []\n_h_i = 0\nwhile _h_i < _h_ncpu\n  _h_z%s.push(%s.new(%s))\n  _h_i += 1\nend\n", m.Name, m.Name, m.Record.Const, zeros)
			}
		}
	}
	return b.String()
}

func pcpuArrayReset(m *MapDecl) string {
	put := fmt.Sprintf("_h_obj.percpu_put(%s, _h_k, Array.new(_h_ncpu, 0))", m.Const)
	if m.Record != nil {
		put = fmt.Sprintf("_h_obj.percpu_put_record(%s, _h_k, _h_z%s)", m.Const, m.Name)
	}
	return fmt.Sprintf("      _h_k = 0\n      while _h_k < %d\n        %s\n        _h_k += 1\n      end\n", m.MaxEntries, put)
}

func pcpuArrayDump(m *MapDecl, kernel bool) string {
	var rows string
	switch {
	case kernel && m.Record != nil:
		rows = fmt.Sprintf("_h_obj.percpu_get_record(%s, _h_k)", m.Const)
	case kernel:
		rows = fmt.Sprintf("SpinelBPF.wraps(_h_obj.percpu_get(%s, _h_k))", m.Const)
	case m.Record != nil:
		rows = fmt.Sprintf("[%s.slot(_h_k)]", m.Const)
	default:
		rows = fmt.Sprintf("[[%s.peek(_h_k)]]", m.Const)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "      _h_k = 0\n      while _h_k < %d\n        _h_rows = %s\n        _h_v = _h_colsum(_h_rows)\n", m.MaxEntries, rows)
	if m.Record == nil {
		fmt.Fprintf(&b, "        puts \"%s[#{_h_k}]=#{_h_v[0]}\"\n", m.Name)
	} else {
		for i, f := range m.Record.Fields {
			if !f.Pad {
				fmt.Fprintf(&b, "        puts \"%s[#{_h_k}].%s=#{_h_v[%d]}\"\n", m.Name, f.Name, i)
			}
		}
	}
	fmt.Fprintf(&b, "        puts \"%s[#{_h_k}] nz=#{_h_nzr(_h_rows)}\"\n        _h_k += 1\n      end\n", m.Name)
	return b.String()
}

func noTracing(res *Result, what string) error {
	if err := noTpBtf(res); err != nil {
		return err
	}
	if err := noUprobe(res); err != nil {
		return err
	}
	if err := noSchedCls(res, what); err != nil {
		return err
	}
	for _, p := range res.Programs {
		if p.Kind != "xdp" {
			return fmt.Errorf("the %s for a %s program is not written (it needs the C loader's tracing attach and test run) — program %s", what, p.Kind, p.Name)
		}
	}
	return nil
}

func noSchedCls(res *Result, what string) error {
	for _, p := range res.Programs {
		if p.Kind == "sched_cls" {
			return fmt.Errorf("the %s has no sched_cls form (the twin and kernel harnesses do) — program %s", what, p.Name)
		}
	}
	return nil
}

func TwinHarnessThreads(text string, res *Result) (string, error) {
	if err := noTpBtf(res); err != nil {
		return "", err
	}
	if err := noUprobe(res); err != nil {
		return "", err
	}
	if err := noSchedCls(res, "twin harness, thread variant"); err != nil {
		return "", err
	}
	k, err := keptSource(text, res)
	if err != nil {
		return "", err
	}
	var x strings.Builder
	x.WriteString("    elsif _h_cmd == \"prun\"\n      _h_runs = _h_f[2].to_i\n      _h_i = 3\n      while _h_i < _h_f.length\n        _h_data = _h_hex(_h_f[_h_i])\n        _h_j = 0\n        while _h_j < _h_runs\n")
	for i, p := range res.Programs {
		kw := "if"
		if i > 0 {
			kw = "elsif"
		}
		fmt.Fprintf(&x, "          %s _h_f[1] == %q\n            %s(BPF::XdpMd.new(_h_data))\n", kw, p.Name, p.Name)
	}
	x.WriteString("          end\n          _h_j += 1\n        end\n        _h_i += 1\n      end\n      puts \"ok\"\n")
	x.WriteString(ppokeCode(res, false))
	return k + "# spinelbpf twin harness, thread variant (serial)\n" + harness(res, recordTwinCode(res)+globalConfigLoop(res, false), "%s.poke(%s, %s)", "%s(BPF::XdpMd.new(Array.new(64, 0)))", "%s(BPF::XdpMd.new(_h_hex(_h_f[2])))", "%s.peek(%s)", false, x.String()), nil
}

func KernelHarnessThreads(text string, res *Result) (string, error) {
	if err := noTracing(res, "kernel harness"); err != nil {
		return "", err
	}
	k, err := keptSource(text, res)
	if err != nil {
		return "", err
	}
	x := `    elsif _h_cmd == "prun"
      _h_runs = _h_f[2].to_i
      _h_ts = []
      _h_i = 3
      while _h_i < _h_f.length
        _h_ts << Thread.new(_h_obj, _h_f[1], _h_hex(_h_f[_h_i]), _h_runs) do |o, pg, data, n|
          s = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
          j = 0
          while j < n
            o.test_run_xdp_packet(pg, data)
            j += 1
          end
          [s, Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)]
        end
        _h_i += 1
      end
      _h_sp = []
      _h_i = 0
      while _h_i < _h_ts.length
        _h_sp << _h_ts[_h_i].value
        _h_i += 1
      end
      _h_ov = 0
      _h_i = 0
      while _h_i < _h_sp.length
        _h_j = _h_i + 1
        while _h_j < _h_sp.length
          if _h_sp[_h_i][0] < _h_sp[_h_j][1] && _h_sp[_h_j][0] < _h_sp[_h_i][1]
            _h_ov += 1
          end
          _h_j += 1
        end
        _h_i += 1
      end
      puts "overlaps=#{_h_ov}"
      puts "ok"
`
	pre := "# spinelbpf kernel harness, thread variant (parallel)\nrequire \"spinelbpf\"\n" + globalConfigLoop(res, true)
	return k + harness(res, pre, "_h_obj.map_put(%s, %s, %s)", "_h_obj.test_run_xdp(%q, 1)", "_h_obj.test_run_xdp_packet(%q, _h_hex(_h_f[2]))", "_h_obj.map_get(%s, %s)", true, x+ppokeCode(res, true)), nil
}

func ppokeCode(res *Result, kernel bool) string {
	var b strings.Builder
	b.WriteString("    elsif _h_cmd == \"ppoke\"\n      _h_tn = _h_f[2].to_i\n      _h_kn = _h_f[3].to_i\n")
	first := true
	for _, m := range res.Maps {
		if m.Record != nil || m.IsHash() || m.PerCPU() || m.IsLpm() {
			continue
		}
		kw := "elsif"
		if first {
			kw = "if"
			first = false
		}
		if kernel {
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_ts = []\n        _h_t = 0\n        while _h_t < _h_tn\n          _h_ts << Thread.new(_h_obj, _h_t, _h_kn) do |o, tt, kk|\n            j = 0\n            while j < kk\n              o.map_put(%s, tt * kk + j, tt * 1000 + j)\n              j += 1\n            end\n            0\n          end\n          _h_t += 1\n        end\n        _h_i = 0\n        while _h_i < _h_ts.length\n          _h_ts[_h_i].join\n          _h_i += 1\n        end\n", kw, m.Name, m.Const)
		} else {
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_t = 0\n        while _h_t < _h_tn\n          _h_j = 0\n          while _h_j < _h_kn\n            %s.poke(_h_t * _h_kn + _h_j, _h_t * 1000 + _h_j)\n            _h_j += 1\n          end\n          _h_t += 1\n        end\n", kw, m.Name, m.Const)
		}
	}
	if !first {
		b.WriteString("      end\n")
	}
	b.WriteString("      puts \"ok\"\n")
	return b.String()
}

func tracingKernelSetup(res *Result) string {
	var b strings.Builder
	any := false
	for _, p := range res.Programs {
		if !attachesKernelFunc(p.Kind) {
			continue
		}
		any = true
		if p.Kind == "fmod_ret" {
			continue
		}
		if p.Kind == "tp_btf" {
			fmt.Fprintf(&b, "_h_link_%s = _h_obj.attach_tp_btf(%q)\n", p.Name, p.Name)
			continue
		}
		if p.Kind == "uprobe" || p.Kind == "uretprobe" {
			fmt.Fprintf(&b, "_h_link_%s = _h_obj.attach_%s(%q, HUprobe.h_pid)\n", p.Name, p.Kind, p.Name)
			continue
		}
		fmt.Fprintf(&b, "_h_link_%s = _h_obj.attach_%s(%q)\n", p.Name, p.Kind, p.Name)
	}
	if !any {
		return ""
	}
	piC, piF := "", ""
	if hasTpBtf(res) {
		piC, piF = hPiC+hCommC, "  ffi_func :h_pi, [:long], :long\n  ffi_func :h_setcomm, [:str], :long\n  ffi_func :h_commb, [:long], :long\n"
	} else if hasComm(res) {
		piC, piF = hCommC, "  ffi_func :h_setcomm, [:str], :long\n  ffi_func :h_commb, [:long], :long\n"
	}
	if hasStrptr(res) {
		piC, piF = piC+hSpawnC, piF+"  ffi_func :h_spawn, [:str], :long\n  ffi_func :h_release, [:long], :long\n"
	}
	if hasArgv(res) {
		piC, piF = piC+hArgvSpawnC, piF+"  ffi_func :h_argv_spawn, [:str], :long\n  ffi_func :h_argv_release, [:long], :long\n"
	}
	if hasKprobePtr(res) {
		piC, piF = piC+"    static const char h_fname_buf[] = \"/nonexistent-e116\";\n    long h_fname(void) { return (long)h_fname_buf; }\n    long h_openat2(long mode, long resolve) { struct { unsigned long long flags, mode, resolve; } how = {0, (unsigned long long)mode, (unsigned long long)resolve}; return (long)syscall(SYS_openat2, -100 /* AT_FDCWD */, h_fname_buf, &how, sizeof how); }\n", piF+"  ffi_func :h_openat2, [:long, :long], :long\n  ffi_func :h_fname, [], :long\n"
	}
	if hasKind(res, "ksyscall") {
		piC, piF = piC+"    long h_prctl(long o, long a2, long a3, long a4, long a5) { return (long)syscall(SYS_prctl, o, a2, a3, a4, a5); }\n", piF+"  ffi_func :h_prctl, [:long, :long, :long, :long, :long], :long\n"
	}
	if hasKind(res, "tracepoint") {
		piC, piF = piC+"    long h_write(long fd, long count) { return (long)syscall(SYS_write, (int)fd, (void *)0, (size_t)count); }\n", piF+"  ffi_func :h_write, [:long, :long], :long\n"
	}
	if hasKind(res, "tracepoint") || hasKind(res, "ksyscall") {
		piC, piF = piC+"    long h_openat(const char *p) { long r = (long)syscall(SYS_openat, -100, p, 0); if (r >= 0) close((int)r); return r; }\n    long h_openat_null(void) { return (long)syscall(SYS_openat, -100, (const char *)0, 0); }\n", piF+"  ffi_func :h_openat, [:str], :long\n  ffi_func :h_openat_null, [], :long\n"
	}
	if hasTpArray(res) {
		piC, piF = piC+hTcpConnectC, piF+"  ffi_func :h_tcpconnect, [:long], :long\n"
	}
	if hasKpath(res) {
		piC, piF = piC+hTcpSendC, piF+"  ffi_func :h_tcpsend, [], :long\n  ffi_func :h_tcpsend_cport, [], :long\n"
	}
	if hasKaddr(res) {
		piC, piF = piC+hODirectC, piF+"  ffi_func :h_odirect, [:str, :long], :long\n  ffi_func :h_od_sector, [], :long\n"
	}
	if hasRawTp(res) {
		piC, piF = piC+"    long h_getppid(void) { return (long)syscall(SYS_getppid); }\n", piF+"  ffi_func :h_getppid, [], :long\n"
	}
	return uprobeKernelSetup(res) + "module HTrace\n  ffi_source <<~C\n    #include <poll.h>\n    #include <unistd.h>\n    #include <sys/syscall.h>\n    #include <sys/wait.h>\n    long h_poll(long n) { return (long)poll(NULL, (nfds_t)n, 0); }\n    long h_tgid(void) { return (long)getpid(); }\n    long h_tid(void) { return (long)syscall(SYS_gettid); }\n    long h_fork(void) { pid_t p = fork(); if (p == 0) _exit(0); if (p < 0) return -1; int st; waitpid(p, &st, 0); return (long)p; }\n" + piC + "  C\n  ffi_func :h_poll, [:long], :long\n  ffi_func :h_tgid, [], :long\n  ffi_func :h_tid, [], :long\n  ffi_func :h_fork, [], :long\n" + piF + "end\n" + b.String()
}

const hCommC = `    #include <sys/prctl.h>
    #include <string.h>
    static char h_comm_buf[16];
    long h_setcomm(const char *s) { if (prctl(PR_SET_NAME, s, 0, 0, 0) != 0) return -1; memset(h_comm_buf, 0, 16); return prctl(PR_GET_NAME, h_comm_buf, 0, 0, 0) == 0 ? 0 : -1; }
    long h_commb(long i) { return (long)(unsigned char)h_comm_buf[i & 15]; }
`

const hPiC = `    #include <pthread.h>
    #include <semaphore.h>
    #include <sched.h>
    #include <errno.h>
    #include <time.h>
    struct h_pi_round { pthread_mutex_t m; sem_t locked, unlock; int err; pid_t waiter_tid; };
    static void *h_pi_owner(void *arg) {
      struct h_pi_round *r = arg;
      if ((r->err = pthread_mutex_lock(&r->m)) != 0) { sem_post(&r->locked); return NULL; }
      sem_post(&r->locked);
      sem_wait(&r->unlock);
      pthread_mutex_unlock(&r->m);
      return NULL;
    }
    static void *h_pi_waiter(void *arg) {
      struct h_pi_round *r = arg;
      r->waiter_tid = (pid_t)syscall(SYS_gettid);
      struct sched_param sp = {.sched_priority = 10};
      int e = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
      if (e != 0) { r->err = e; return NULL; }
      if ((e = pthread_mutex_lock(&r->m)) != 0) { r->err = e; return NULL; }
      pthread_mutex_unlock(&r->m);
      return NULL;
    }
    long h_pi(long rounds) {
      long last = 0;
      for (long i = 0; i < rounds; i++) {
        struct h_pi_round r = {0};
        pthread_mutexattr_t a;
        pthread_mutexattr_init(&a);
        pthread_mutexattr_setprotocol(&a, PTHREAD_PRIO_INHERIT);
        pthread_mutex_init(&r.m, &a);
        pthread_mutexattr_destroy(&a);
        sem_init(&r.locked, 0, 0);
        sem_init(&r.unlock, 0, 0);
        pthread_t o, w;
        if (pthread_create(&o, NULL, h_pi_owner, &r) != 0) return -1;
        sem_wait(&r.locked);
        if (r.err != 0) { pthread_join(o, NULL); return -1; }
        if (pthread_create(&w, NULL, h_pi_waiter, &r) != 0) return -1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
        sem_post(&r.unlock);
        pthread_join(o, NULL);
        pthread_join(w, NULL);
        pthread_mutex_destroy(&r.m);
        sem_destroy(&r.locked);
        sem_destroy(&r.unlock);
        if (r.err != 0) return r.err == EPERM ? -2 : -1;
        last = r.waiter_tid;
      }
      return last;
    }
`

func tracingKernelCmds(res *Result) string {
	var b strings.Builder
	b.WriteString("    elsif _h_cmd == \"self\"\n      puts \"tgid=#{HTrace.h_tgid}\"\n")
	if hasTpBtf(res) {
		b.WriteString("    elsif _h_cmd == \"fork\"\n      puts \"child=#{HTrace.h_fork}\"\n")
		b.WriteString("    elsif _h_cmd == \"pi\"\n      puts \"waiter=#{HTrace.h_pi(_h_f[1].to_i)}\"\n")
	}
	if hasTpBtf(res) || hasComm(res) {
		b.WriteString("    elsif _h_cmd == \"comm\"\n      if HTrace.h_setcomm(_h_f[1]) != 0\n        raise \"prctl PR_SET_NAME failed\"\n      end\n      _h_c = \"\"\n      _h_j = 0\n      while _h_j < 16\n        _h_c += _h_hexs([HTrace.h_commb(_h_j)], 0, 1)\n        _h_j += 1\n      end\n      puts \"comm=#{_h_c}\"\n")
	}
	if hasStrptr(res) {
		b.WriteString("    elsif _h_cmd == \"exec\"\n      _h_c = HTrace.h_spawn(_h_f[3])\n      if _h_c <= 0\n        raise \"fork failed\"\n      end\n")
		first := true
		for _, m := range res.Maps {
			if m.Record != nil || m.IsHash() || m.PerCPU() {
				continue
			}
			kw := "elsif"
			if first {
				kw, first = "if", false
			}
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_obj.map_put(%s, _h_f[2].to_i, _h_c)\n", kw, m.Name, m.Const)
		}
		if !first {
			b.WriteString("      end\n")
		}
		b.WriteString("      _h_st = HTrace.h_release(_h_c)\n      puts \"child=#{_h_c} status=#{_h_st}\"\n")
	}
	if hasArgv(res) {
		b.WriteString("    elsif _h_cmd == \"execargv\"\n      _h_c = HTrace.h_argv_spawn(_h_f[3])\n      if _h_c <= 0\n        raise \"fork failed\"\n      end\n")
		first := true
		for _, m := range res.Maps {
			if m.Record != nil || m.IsHash() || m.PerCPU() {
				continue
			}
			kw := "elsif"
			if first {
				kw, first = "if", false
			}
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_obj.map_put(%s, _h_f[2].to_i, _h_c)\n", kw, m.Name, m.Const)
		}
		if !first {
			b.WriteString("      end\n")
		}
		b.WriteString("      _h_st = HTrace.h_argv_release(_h_c)\n      puts \"child=#{_h_c} status=#{_h_st}\"\n")
	}
	if hasKprobePtr(res) {
		b.WriteString("    elsif _h_cmd == \"openat2\"\n      _h_j = 0\n      while _h_j < _h_f[3].to_i\n        HTrace.h_openat2(_h_f[1].to_i, _h_f[2].to_i)\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n      puts \"fname=#{HTrace.h_fname}\"\n")
	}
	if hasKind(res, "ksyscall") {
		b.WriteString("    elsif _h_cmd == \"prctl\"\n      _h_j = 0\n      while _h_j < _h_f[6].to_i\n        HTrace.h_prctl(_h_f[1].to_i, _h_f[2].to_i, _h_f[3].to_i, _h_f[4].to_i, _h_f[5].to_i)\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasKind(res, "tracepoint") {
		b.WriteString("    elsif _h_cmd == \"write\"\n      _h_j = 0\n      while _h_j < _h_f[3].to_i\n        HTrace.h_write(_h_f[1].to_i, _h_f[2].to_i)\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasKind(res, "tracepoint") || hasKind(res, "ksyscall") {
		b.WriteString("    elsif _h_cmd == \"openat\"\n      _h_j = 0\n      while _h_j < _h_f[2].to_i\n        if _h_f[1] == \"@null\"\n          HTrace.h_openat_null\n        elsif _h_f[1] == \"@empty\"\n          HTrace.h_openat(\"\")\n        else\n          HTrace.h_openat(_h_f[1])\n        end\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasKaddr(res) {
		b.WriteString("    elsif _h_cmd == \"odirect\"\n      puts \"reads=#{HTrace.h_odirect(_h_f[1], _h_f[2].to_i)}\"\n      puts \"want_sector=#{HTrace.h_od_sector}\"\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasKpath(res) {
		b.WriteString("    elsif _h_cmd == \"tcpsend\"\n      _h_j = 0\n      while _h_j < _h_f[1].to_i\n        puts \"port=#{HTrace.h_tcpsend}\"\n        puts \"cport=#{HTrace.h_tcpsend_cport}\"\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasTpArray(res) {
		b.WriteString("    elsif _h_cmd == \"tcpconnect\"\n      _h_j = 0\n      while _h_j < _h_f[2].to_i\n        puts \"port=#{HTrace.h_tcpconnect(_h_f[1].to_i)}\"\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasRawTp(res) {
		b.WriteString("    elsif _h_cmd == \"getppid\"\n      _h_j = 0\n      while _h_j < _h_f[1].to_i\n        HTrace.h_getppid\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasUprobe(res) {
		b.WriteString("    elsif _h_cmd == \"child\"\n      puts \"child=#{(HUprobe.h_pid << 32) | HUprobe.h_pid}\"\n")
	}
	b.WriteString("    elsif _h_cmd == \"pokeself\"\n")
	first := true
	for _, m := range res.Maps {
		if m.Record != nil || m.IsHash() || m.PerCPU() || m.IsLpm() {
			continue
		}
		kw := "elsif"
		if first {
			kw, first = "if", false
		}
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_obj.map_put(%s, _h_f[2].to_i, HTrace.h_tgid)\n", kw, m.Name, m.Const)
	}
	if !first {
		b.WriteString("      end\n")
	}
	b.WriteString("      puts \"ok\"\n")
	for _, p := range res.Programs {
		if attachesKernelFunc(p.Kind) {
			return b.String()
		}
	}
	return ""
}

func tracingKernelRun(kw string, p *Program) string {
	var b strings.Builder
	fmt.Fprintf(&b, "      %s _h_f[1] == %q\n", kw, p.Name)
	if p.Kind == "tp_btf" {
		b.WriteString("        raise \"a tp_btf program has no test run (the kernel returns EFAULT) — trigger it with the fork command\"\n")
		return b.String()
	}
	if p.Kind == "ksyscall" {
		b.WriteString("        raise \"a ksyscall program has no test run — trigger it with the prctl command\"\n")
		return b.String()
	}
	if p.Kind == "tracepoint" {
		b.WriteString("        raise \"a tracepoint program has no test run — trigger it with the write command\"\n")
		return b.String()
	}
	if p.Kind == "raw_tp" {
		b.WriteString("        _h_args = Array.new(12, 0)\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          _h_n = -1\n          _h_j = 0\n          while _h_j < 12\n            if _h_kv[0] == \"a#{_h_j}\"\n              _h_n = _h_j\n            end\n            _h_j += 1\n          end\n          if _h_n < 0\n            raise \"a raw_tp run sets a0..a11 only\"\n          end\n          _h_args[_h_n] = _h_kv[1].to_i\n          _h_i += 1\n        end\n")
		fmt.Fprintf(&b, "        _h_r = _h_obj.test_run_raw_tp(%q, _h_args)\n        puts \"ret=#{_h_r} tid=#{HTrace.h_tid}\"\n", p.Name)
		return b.String()
	}
	if p.Kind == "kprobe" || p.Kind == "kretprobe" {
		b.WriteString("        _h_n = 0\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if _h_kv[0] == \"a2\"\n            _h_n = _h_kv[1].to_i\n          else\n            raise \"the kernel harness triggers the kprobe through poll(2) — only a2 (nfds) is set\"\n          end\n          _h_i += 1\n        end\n        HTrace.h_poll(_h_n)\n        puts \"ret=0 tid=#{HTrace.h_tid}\"\n")
		return b.String()
	}
	if p.Kind == "fmod_ret" {
		fmt.Fprintf(&b, "        _h_lk = _h_obj.attach_fmod_ret(%q)\n        _h_td = _h_obj.test_run_tracing(%q, 1)\n        _h_lk.detach\n        puts \"ret=0 tid=#{_h_td}\"\n", p.Name, p.Name)
		return b.String()
	}
	fmt.Fprintf(&b, "        puts \"ret=0 tid=#{_h_obj.test_run_tracing(%q, 1)}\"\n", p.Name)
	return b.String()
}

func globalConfigLoop(res *Result, kernel bool) string {
	if kernel && hasUprobe(res) {
		if len(res.Globals) > 0 {
			return "raise \"the kernel harness does not combine globals and uprobe targets\"\n"
		}
		var b strings.Builder
		b.WriteString("_h_tg = SpinelBPF::UprobeTargets.new\n")
		for _, p := range res.Programs {
			if p.Kind == "uprobe" || p.Kind == "uretprobe" {
				if p.SysTarget != "" {
					fmt.Fprintf(&b, "_h_tg.add(%q, %q)\n", p.Name, p.SysTarget)
					continue
				}
				fmt.Fprintf(&b, "_h_tg.add(%q, ARGV[0])\n", p.Name)
			}
		}
		b.WriteString("_h_obj = SpinelBPF.load_embedded_targets(SpinelBPF::ConfigSet.new, _h_tg)\n")
		return b.String()
	}
	if len(res.Globals) == 0 {
		if kernel {
			return "_h_obj = SpinelBPF.load_embedded\n"
		}
		return ""
	}
	var b strings.Builder
	if kernel {
		b.WriteString("_h_cfg = SpinelBPF::ConfigSet.new\n")
	}
	b.WriteString("_h_go = true\nwhile _h_go && (_h_line = $stdin.gets)\n  _h_f = _h_line.split(\" \")\n  if _h_f[0] == \"load\"\n    _h_go = false\n  elsif _h_f[0] == \"config\"\n")
	for i, g := range res.Globals {
		kw := "if"
		if i > 0 {
			kw = "elsif"
		}
		switch {
		case !kernel:
			fmt.Fprintf(&b, "    %s _h_f[1] == %q\n      BPF.set_global(%q, _h_f[2].to_i)\n", kw, g.Name, g.Name)
		case g.Counter():
			fmt.Fprintf(&b, "    %s _h_f[1] == %q\n      raise \"%s is a Counter (.bss) — it has no load-time value\"\n", kw, g.Name, g.Name)
		case g.Optional:
			fmt.Fprintf(&b, "    %s _h_f[1] == %q\n      _h_cfg.set_optional(%s, _h_f[2].to_i)\n", kw, g.Name, g.Const)
		default:
			fmt.Fprintf(&b, "    %s _h_f[1] == %q\n      _h_cfg.set(%s, _h_f[2].to_i)\n", kw, g.Name, g.Const)
		}
	}
	b.WriteString("    end\n  end\nend\n")
	if kernel {
		b.WriteString("begin\n  _h_obj = SpinelBPF.load_embedded_config(_h_cfg)\nrescue SpinelBPF::Error => _h_le\n  puts \"load err=#{_h_le.class} msg=#{_h_le.message}\"\n  exit 0\nend\n")
	}
	return b.String()
}

func globalDump(res *Result, kernel bool) string {
	var b strings.Builder
	for _, g := range res.Globals {
		get := g.Const + ".value"
		if kernel {
			m := "config_get"
			if g.Optional {
				m = "optional_get"
			} else if g.Counter() {
				m = "counter_get"
			}
			get = "_h_obj." + m + "(" + g.Const + ")"
		}
		fmt.Fprintf(&b, "      begin\n        puts \"%s=#{%s}\"\n      rescue => _h_ge\n        puts \"%s=err=#{_h_ge.class}\"\n      end\n", g.Name, get, g.Name)
	}
	return b.String()
}

type flatSlot struct {
	name string
	idx  int
	pad  bool
}

func flatSlots(r *RecordDecl) []flatSlot {
	var out []flatSlot
	for _, f := range r.Fields {
		ns, _ := f.Flat()
		for _, n := range ns {
			out = append(out, flatSlot{n, len(out), f.Pad})
		}
	}
	return out
}

func flatBase(r *RecordDecl, i int) int {
	n := 0
	for j := 0; j < i; j++ {
		if r.Fields[j].Count > 0 {
			n += r.Fields[j].Count
		} else {
			n++
		}
	}
	return n
}

func noUprobe(res *Result) error {
	for _, p := range res.Programs {
		if p.Kind == "uprobe" || p.Kind == "uretprobe" {
			return fmt.Errorf("the twin and kernel harnesses for a uprobe program are not written here (they need the target's child process and the load's uprobe targets) — program %s", p.Name)
		}
	}
	return nil
}

func parenDelta(line string) int {
	d, inStr := 0, byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inStr != 0:
			if c == '\\' {
				i++
			} else if c == inStr {
				inStr = 0
			}
		case c == '"' || c == '\'':
			inStr = c
		case c == '#':
			return d
		case c == '(':
			d++
		case c == ')':
			d--
		}
	}
	return d
}
