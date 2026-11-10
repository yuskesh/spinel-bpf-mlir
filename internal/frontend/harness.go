package frontend

import (
	"fmt"
	"strings"
)

// The differential harness. It builds two programs that speak the same command protocol, one for the twin (the native Ruby model of
// the eBPF program) and one for the kernel; a single process reads many command lines.
// The protocol (one command per stdin line; each output line is flushed):
//
//	reset                      set every slot of every map to 0
//	poke <Map> <key> <value>   put a value in a map slot (the twin uses the twin library's poke, the kernel map_put)
//	run <prog>                 run the root once and print `ret=<v>` (the twin passes a BPF::XdpMd of a 64-byte zero packet, the kernel
//	                           does one test run with 64 zero bytes)
//	run <prog> <hex>           run with the data given in hex (`-` for empty — the twin uses BPF::XdpMd.new(bytes) / BPF::SkBuff.new(bytes),
//	                           the kernel test_run_xdp_packet / test_run_tc_packet)
//	dump                       print every slot of every map as `<Map>[<k>]=<v>` (the twin uses peek, the kernel map_get)
//	echo <label>               print `## <label>` (marks a row of the test table)
//	drain <Ring>               print every ring buffer event as `<Ring>#<i>.<member>=<v>`, then `<Ring> drained=<n>` (the twin reads its
//	                           event list, the kernel calls read_record(0) until the ring is empty)
//
// An error (a Spinel RangeError or a loader exception) becomes one `err=<class>` line and the loop goes on.
// Both programs are used only in test builds — they never reach the user's executable (the default output of spinelbpf build does
// not change).

// keptSource returns the user's source with the lines of the root defs, the map declarations, `require "bpf"` and `BPF.xdp` kept
// as they are and every other line blanked (so lines and columns do not move).
func keptSource(text string, res *Result) (string, error) {
	if len(res.Programs) == 0 {
		return "", fmt.Errorf("no program")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keep := make([]bool, len(lines))
	mark := func(from, to int) {
		if from == to && from >= 1 { // a one-line declaration mark also keeps the continuation lines until the parentheses close (multi-line Struct.new / BPF.record / RingBuf.new)
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
	for _, d := range res.StructOps { // a BPF.struct_ops declaration, all its lines (its keyword options continue without parentheses)
		mark(d.Pos.Line, d.EndLine)
	}
	for _, f := range res.Funcs { // subprogram defs (the twin calls them natively as they are)
		mark(f.Pos.Line, f.EndLine)
	}
	for _, m := range res.Maps {
		mark(m.Pos.Line, m.Pos.Line)
		for _, r := range []*RecordDecl{m.Record, m.KeyRecord} { // also the record key of a hash map
			if r != nil {
				mark(r.StructPos.Line, r.StructPos.Line)
				mark(r.Pos.Line, r.Pos.Line)
			}
		}
	}
	for _, l := range ringLines(res) {
		mark(l, l)
	}
	for _, d := range res.KernelTypes { // a kernel struct's Struct, its declaration and its sample handles
		mark(d.StructPos.Line, d.StructPos.Line)
		mark(d.Pos.Line, d.Pos.Line)
		for _, h := range d.HandlePoss {
			mark(h.Line, h.Line)
		}
	}
	for _, g := range res.Globals { // the lines declaring globals
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

// harness writes the command loop. put / run / get are templates of the Ruby expression for each command (%s takes the map
// constant, the key and the value).
func harness(res *Result, prelude, put, run, runPkt, get string, kernel bool, extra ...string) string {
	var b strings.Builder
	b.WriteString(prelude)
	b.WriteString(hexFunc)
	b.WriteString(recordPokeFuncs(res, kernel))
	b.WriteString(ringSetup(res, kernel))
	b.WriteString(hashSetup(res, kernel))
	b.WriteString(pcpuSetup(res, kernel))
	b.WriteString(lpmSetup(res, kernel)) // LPM trie maps
	b.WriteString("while (_h_line = $stdin.gets)\n  _h_f = _h_line.split(\" \")\n  _h_cmd = _h_f[0]\n  begin\n")
	b.WriteString("    if _h_cmd == \"reset\"\n")
	for _, m := range res.Maps {
		if m.IsDevmap() && kernel { // a devmap is empty after load — the kernel rejects a put of ifindex 0 (only the twin resets it)
			continue
		}
		if m.Kind == "sockmap" && kernel { // a sockmap slot holds only a socket fd (sput) — only the twin resets it
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
		if m.Kind == "sockmap" { // sockmaps take sput, not poke
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        raise \"poke is not for sockmaps (sput)\"\n", kw, m.Name)
			continue
		}
		if m.PerCPU() && (m.IsHash() || m.Record != nil) {
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        raise \"poke is for per-CPU integer arrays\"\n", kw, m.Name)
			continue
		}
		if m.PerCPU() && kernel { // a per-CPU integer array — put the value in slot 0 (the kernel harness is pinned to CPU 0)
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_pv = Array.new(_h_ncpu, 0)\n        _h_pv[0] = _h_f[3].to_i\n        _h_obj.percpu_put(%s, _h_f[2].to_i, _h_pv)\n", kw, m.Name, m.Const)
			continue
		}
		if m.IsHash() { // a hash map (integer keys and values only — the twin uses update, the kernel hash_put)
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
		b.WriteString("      puts \"ok\"\n    elsif _h_cmd == \"task\"\n      puts \"ok\"\n    elsif _h_cmd == \"run\"\n") // in the kernel the task is the real one (only the twin sets it)
	} else {
		b.WriteString("      puts \"ok\"\n    elsif _h_cmd == \"task\"\n      BPF::TASK[0] = _h_f[1].to_i\n      puts \"ok\"\n")
		if hasComm(res) { // the twin's current comm (same rules as PR_SET_NAME — BPF.set_comm), printed like the kernel's comm=<16 bytes in hex>
			b.WriteString("    elsif _h_cmd == \"comm\"\n      BPF.set_comm(_h_f[1])\n      puts \"comm=#{_h_hexs(BPF::TASK_COMM, 0, 16)}\"\n")
		}
		b.WriteString("    elsif _h_cmd == \"run\"\n")
	}
	for i, p := range res.Programs {
		kw := "if"
		if i > 0 {
			kw = "elsif"
		}
		if p.Kind == "sched_cls" { // the twin gets SkBuff bytes, the kernel a tc (skb) test run — no data means a 64-byte zero frame (as for xdp)
			runPktTC, runTC := "%s(BPF::SkBuff.new(_h_hex(_h_f[2])))", "%s(BPF::SkBuff.new(Array.new(64, 0)))"
			if kernel {
				runPktTC, runTC = "_h_obj.test_run_tc_packet(%q, _h_hex(_h_f[2]))", "_h_obj.test_run_tc_packet(%q, Array.new(64, 0))"
			}
			fmt.Fprintf(&b, "      %s _h_f[1] == %q && _h_f.length > 2\n        puts \"ret=#{%s}\"\n", kw, p.Name, fmt.Sprintf(runPktTC, p.Name))
			fmt.Fprintf(&b, "      elsif _h_f[1] == %q\n        puts \"ret=#{%s}\"\n", p.Name, fmt.Sprintf(runTC, p.Name))
			continue
		}
		if p.Kind == "flow_dissector" { // `run <prog> <hex>` — the verdict and the 20 key values (in SpinelBPF::FLOW_KEYS order); the twin clamps FlowCtx's keys as the kernel does
			fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_d = Array.new(64, 0)\n        if _h_f.length > 2\n          _h_d = _h_hex(_h_f[2])\n        end\n", kw, p.Name)
			if kernel {
				fmt.Fprintf(&b, "        _h_k = _h_obj.test_run_flow_dissector(%q, _h_d)\n        puts \"ret=#{_h_k[0]} keys=#{_h_k[1, 20].join(\",\")}\"\n", p.Name)
			} else {
				clamp := 1
				if mutation("flow-noclamp") { // mutation: drop the twin's clamp of thoff
					clamp = 0
				}
				fmt.Fprintf(&b, "        _h_c = BPF::FlowCtx.new(_h_d)\n        _h_r = %s(_h_c)\n        puts \"ret=#{_h_r} keys=#{_h_c._h_keys(%d).join(\",\")}\"\n", p.Name, clamp)
			}
			continue
		}
		if p.Kind == "sk_lookup" { // see sklookupharness.go
			b.WriteString(skRun(kw, p, kernel))
			continue
		}
		if p.Kind == "netfilter" { // `run <prog> <hex> <hook> <pf>` — the twin uses the twins of the declared structs, the kernel a netfilter test run
			if kernel {
				fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        puts \"ret=#{_h_obj.test_run_netfilter(%q, _h_hex(_h_f[2]), _h_f[4].to_i, _h_f[3].to_i)}\"\n", kw, p.Name, p.Name)
			} else {
				b.WriteString(nfTwinRun(kw, p, res.KernelTypes))
			}
			continue
		}
		if p.Kind == "cgroup_skb" { // the twin starts at byte 14 of the frame (the test run strips the Ethernet header — window offset 0 is L3), the kernel does an skb test run
			hdr := 14
			if mutation("cg-win-l2") { // mutation: the twin's window and len come from the bytes with the Ethernet header kept
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
		if p.Kind == "socket_filter" { // the twin's len is the frame's byte count − 14 (the test run strips the Ethernet header), the kernel does an skb test run — no data means a 64-byte zero frame
			hdr := 14
			if mutation("sf-len-l2") { // mutation: the twin's len is n with the Ethernet header kept
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
		if usesKernelTypes(p) && !kernel && p.Kind != "struct_ops" { // the twin takes the struct members and integer arguments the test gives (also fentry programs with args)
			b.WriteString(tpBtfTwinRun(kw, p, res.KernelTypes))
			continue
		}
		if p.Kind == "uprobe" || (kernel && p.Kind == "uretprobe") { // cfix commands (`sum A B C`, `greet N TEXT`, `null N`) — the twin uses UprobeCtx, the kernel sends them to the child process (also for uretprobe in the kernel — the child's answer goes to rv=)
			if kernel {
				fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        if HUprobe.h_send(_h_f[2, _h_f.length - 2].join(\" \")) < 0\n          raise \"the uprobe target's child process did not answer\"\n        end\n", kw, p.Name)
				if p.Kind == "uretprobe" || hasPtrParam(p) { // also programs with a :ptr argument (the pointer in the child's answer goes to the twin's `at`)
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
			} else if p.Kind == "struct_ops" && len(p.TArgs) > 0 {
				b.WriteString(soKptrTwinRun(kw, p, res.KernelTypes))
			} else {
				b.WriteString(tracingTwinRun(kw, p))
			}
			continue
		}
		fmt.Fprintf(&b, "      %s _h_f[1] == %q && _h_f.length > 2\n        puts \"ret=#{%s}\"\n", kw, p.Name, fmt.Sprintf(runPkt, p.Name))
		fmt.Fprintf(&b, "      elsif _h_f[1] == %q\n        puts \"ret=#{%s}\"\n", p.Name, fmt.Sprintf(run, p.Name))
	}
	b.WriteString("      end\n    elsif _h_cmd == \"echo\"\n      puts \"## #{_h_f[1]}\"\n    elsif _h_cmd == \"dump\"\n")
	b.WriteString(globalDump(res, kernel)) // globals
	for _, m := range res.Maps {
		if m.IsDevmap() { // the kernel answers ENOENT to a read of an empty devmap key — keep it out of dump (the redirect's return value shows it)
			continue
		}
		if m.Kind == "sockmap" { // a socket slot cannot be read as a value (the assign status and the cookie show it)
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
		// catch errors per slot (a ValueRange on one slot must not lose the remaining slots)
		fmt.Fprintf(&b, "      _h_k = 0\n      while _h_k < %d\n        begin\n          puts \"%s[#{_h_k}]=#{%s}\"\n        rescue => _h_e2\n          puts \"%s[#{_h_k}]=err=#{_h_e2.class}\"\n        end\n        _h_k += 1\n      end\n", m.MaxEntries, m.Name, fmt.Sprintf(get, m.Const, "_h_k"), m.Name)
	}
	for _, r := range res.Rings {
		fmt.Fprintf(&b, "    elsif _h_cmd == \"drain\" && _h_f[1] == %q\n", r.Name)
		b.WriteString(ringDrain(r, kernel, true))
	}
	b.WriteString(lpmCmds(res, kernel)) // LPM trie commands
	b.WriteString(skCmds(res, kernel))  // sockmap commands (sput)
	for _, x := range extra {
		b.WriteString(x)
	}
	b.WriteString("    end\n  rescue => _h_e\n    puts \"err=#{_h_e.class}\"\n  end\n  $stdout.flush\nend\n")
	return b.String()
}

// hexFunc turns the data of the harness's `run <prog> <hex>` into an Array of Integers (a harness function — not user API).
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

// tracingTwinRun writes the twin's `run <prog> [ret=<v>] [a<n>=<v> …]` for a tracing program: it builds a synthetic context, calls
// the root once and prints `ret=0` (verdict done).
// Values are cut to the width of the declared type (a model of the kernel reading the bits of a register or of the return-value
// slot at that width — u masks, i sign-extends, 64 bits stay as they are).
func tracingTwinRun(kw string, p *Program) string {
	var b strings.Builder
	if p.Kind == "fmod_ret" { // `run <prog> a<i>=<v>` — the declared integer arguments (cut to width, unset indexes are 0); the return value goes to ret= (FMOD_CALL is 0)
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_args = Array.new(12, 0)\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if false\n", kw, p.Name)
		for _, a := range p.TArgs {
			fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            _h_args[%d] = %s\n", a.Idx, a.Idx, widthCut("_h_kv[1].to_i", a.Type))
		}
		b.WriteString("          else\n            raise \"undeclared fmod_ret argument #{_h_kv[0]}\"\n          end\n          _h_i += 1\n        end\n")
		fmt.Fprintf(&b, "        puts \"ret=#{%s(BPF::FmodRetCtx.new(_h_args))}\"\n", p.Name)
		return b.String()
	}
	if p.Kind == "struct_ops" { // `run <prog> a<i>=<v>`: the member's integer arguments (cut to the table's width; unset are 0); ret= is an integer member's return, 0 for a void one
		m := soMemberOf(p)
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_args = Array.new(%d, 0)\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if false\n", kw, p.Name, len(m.Args))
		for i, ar := range m.Args {
			if ar.Kind == "int" || ar.Kind == "enum" {
				fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            _h_args[%d] = %s\n", i, i, widthCut("_h_kv[1].to_i", ar.Type))
			}
		}
		fmt.Fprintf(&b, "          else\n            raise \"not an integer argument of %s.%s: #{_h_kv[0]}\"\n          end\n          _h_i += 1\n        end\n", p.SOType, p.SOMember)
		if p.Ret == "void" {
			fmt.Fprintf(&b, "        %s(BPF::StructOpsCtx.new(_h_args))\n        puts \"ret=0\"\n", p.Name)
		} else {
			fmt.Fprintf(&b, "        puts \"ret=#{%s(BPF::StructOpsCtx.new(_h_args))}\"\n", p.Name)
		}
		if p.Scx {
			b.WriteString(scxLogLines)
		}
		return b.String()
	}
	if p.Kind == "tracepoint" { // declared field name = value (cut to the declared type's width — unset fields are 0)
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_tpf = {", kw, p.Name)
		for i, f := range p.TFields {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q => 0", f.Name)
		}
		// a :user_str field is a twin UserStr (`f=<path>` — a path without spaces, `f=@null`, `f=@empty` — unset fields are NULL)
		b.WriteString("}\n        _h_tps = {\"\" => BPF::UserStr.new(Array.new(0, 0), true)}\n        _h_tpa = {\"\" => " + argvTwinEmpty + "}\n        _h_tpb = {\"\" => Array.new(0, 0)}\n")
		for _, f := range p.TFields {
			if f.Type == "user_str" {
				fmt.Fprintf(&b, "        _h_tps[%q] = BPF::UserStr.new(Array.new(0, 0), true)\n", f.Name)
			}
			if f.Type == "user_str_array" { // an argv-style string array
				fmt.Fprintf(&b, "        _h_tpa[%q] = %s\n", f.Name, argvTwinEmpty)
			}
			if f.N > 0 { // a fixed-size byte array (`f=b0,b1,…` — unset fields and unset bytes are 0)
				fmt.Fprintf(&b, "        _h_tpb[%q] = Array.new(%d, 0)\n", f.Name, f.N)
			}
		}
		b.WriteString("        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if false\n")
		for _, f := range p.TFields {
			if f.N > 0 { // a fixed-size byte array
				fmt.Fprintf(&b, "          elsif _h_kv[0] == %q\n            _h_bs = _h_kv[1].split(\",\")\n            _h_j = 0\n            while _h_j < _h_bs.length && _h_j < %d\n              _h_tpb[%q][_h_j] = _h_bs[_h_j].to_i & 255\n              _h_j += 1\n            end\n", f.Name, f.N, f.Name)
				continue
			}
			if f.Type == "user_str_array" { // an argv-style string array
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
	if p.Kind == "raw_tp" { // 12 args[i] (unset indexes are 0) — there is no declared type (u64)
		fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_args = Array.new(12, 0)\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n", kw, p.Name)
		b.WriteString("          _h_n = -1\n          _h_j = 0\n          while _h_j < 12\n            if _h_kv[0] == \"a#{_h_j}\"\n              _h_n = _h_j\n            end\n            _h_j += 1\n          end\n          if _h_n < 0\n            raise \"undeclared context value #{_h_kv[0]}\"\n          end\n          _h_args[_h_n] = _h_kv[1].to_i\n          _h_i += 1\n        end\n")
		fmt.Fprintf(&b, "        %s(BPF::RawTpCtx.new(_h_args))\n", p.Name)
		b.WriteString("        puts \"ret=0\"\n")
		return b.String()
	}
	reads := ""
	if p.Kind == "kprobe" { // the table of reads ("<n>_<off>" → [value, status])
		reads = "        _h_reads = {\"\" => [0, 0]}\n"
	}
	if p.Kind == "ksyscall" { // twin UserStrs for the :user_str arguments (a<n>=<path>|@null|@empty — unset arguments are NULL)
		reads = "        _h_strs = Array.new(7, BPF::UserStr.new(Array.new(0, 0), true))\n        _h_arrs = Array.new(7, " + argvTwinEmpty + ")\n" // argv arguments
	}
	fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_ret = 0\n        _h_args = Array.new(7, 0)\n%s        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n", kw, p.Name, reads)
	b.WriteString("          if false\n")
	if p.Kind == "fexit" || p.Kind == "kretprobe" || p.Kind == "uretprobe" {
		fmt.Fprintf(&b, "          elsif _h_kv[0] == \"ret\"\n            _h_ret = %s\n", widthCut("_h_kv[1].to_i", p.Ret))
	}
	for _, kp := range p.Params {
		if kp.Type == "ptr" { // the raw value of a pointer (an i64 not cut to width — an address the test gives); reads through it come from r<n>_<off>= / s<n>_<off>=
			fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            _h_args[%d] = _h_kv[1].to_i\n", kp.N, kp.N)
			continue
		}
		if kp.Type == "user_str" { // a user string argument
			fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            if _h_kv[1] == \"@null\"\n              _h_strs[%d] = BPF::UserStr.new(Array.new(0, 0), true)\n            elsif _h_kv[1] == \"@empty\"\n              _h_strs[%d] = BPF::UserStr.new(Array.new(0, 0), false)\n            else\n              _h_strs[%d] = BPF::UserStr.new(_h_kv[1].bytes, false)\n            end\n", kp.N, kp.N, kp.N, kp.N)
			continue
		}
		if kp.Type == "user_str_array" { // an argv-style string array argument
			fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n%s", kp.N, argvTwinParse(fmt.Sprintf("_h_arrs[%d]", kp.N)))
			continue
		}
		fmt.Fprintf(&b, "          elsif _h_kv[0] == \"a%d\"\n            _h_args[%d] = %s\n", kp.N, kp.N, widthCut("_h_kv[1].to_i", kp.Type))
	}
	if p.Kind == "kprobe" { // a read's value (r<n>_<off>=) and status (s<n>_<off>=)
		b.WriteString("          elsif _h_kv[0][0] == \"r\" || _h_kv[0][0] == \"s\"\n            _h_k = _h_kv[0][1, _h_kv[0].length - 1]\n            if !_h_reads.key?(_h_k)\n              _h_reads[_h_k] = [0, 0]\n            end\n            if _h_kv[0][0] == \"r\"\n              _h_reads[_h_k][0] = _h_kv[1].to_i\n            else\n              _h_reads[_h_k][1] = _h_kv[1].to_i\n            end\n")
	}
	b.WriteString("          else\n            raise \"undeclared context value #{_h_kv[0]}\"\n          end\n          _h_i += 1\n        end\n")
	switch p.Kind {
	case "fexit":
		fmt.Fprintf(&b, "        %s(BPF::FexitCtx.new(_h_ret))\n", p.Name)
	case "kprobe":
		fmt.Fprintf(&b, "        %s(BPF::KprobeCtx.new(_h_args, _h_reads))\n", p.Name)
	case "ksyscall": // the syscall's arguments (a<n>= as for kprobe)
		fmt.Fprintf(&b, "        %s(BPF::KsyscallCtx.new(_h_args, _h_strs, _h_arrs))\n", p.Name)
	case "uretprobe": // the probed function's return value
		fmt.Fprintf(&b, "        %s(BPF::UretprobeCtx.new(_h_ret))\n", p.Name)
	case "kretprobe": // the probed function's return value
		fmt.Fprintf(&b, "        %s(BPF::KretprobeCtx.new(_h_ret))\n", p.Name)
	default:
		fmt.Fprintf(&b, "        %s(BPF::FentryCtx.new)\n", p.Name)
	}
	b.WriteString("        puts \"ret=0\"\n")
	return b.String()
}

// hasRawTp reports whether res has a raw_tp program.
func hasRawTp(res *Result) bool { return hasKind(res, "raw_tp") }

// hasStrptr reports whether res has a kernel_type with a :strptr member.
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

// hSpawnC is the C behind the harness's `exec`: h_spawn forks a child (the child waits for one byte on a pipe, then calls
// execve(path) — on failure _exit(127)), and h_release writes that byte, calls waitpid and returns the child's exit status.
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

// hasKprobePtr reports whether res has a kprobe program with a :ptr argument.
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

// hasKind reports whether res has a program of the given kind.
func hasKind(res *Result, kind string) bool {
	for _, p := range res.Programs {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

// widthCut returns a Ruby expression that cuts the Ruby expression x to the width of type t (a name from :u8 … :i64).
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

// TwinHarness returns the harness program for the native twin (built with `spinel -I ruby/lib/native` — it also runs on CRuby).
func TwinHarness(text string, res *Result) (string, error) {
	k, err := keptSource(text, res)
	if err != nil {
		return "", err
	}
	if err := nfTwinCheck(res); err != nil { // netfilter programs
		return "", err
	}
	run, runPkt := "%s(BPF::XdpMd.new(Array.new(64, 0)))", "%s(BPF::XdpMd.new(_h_hex(_h_f[2])))"
	if mutation("ifx-zero") { // mutation: the twin's ingress_ifindex is 0
		run, runPkt = "%s(BPF::XdpMd.new(Array.new(64, 0))._h_ifx(0))", "%s(BPF::XdpMd.new(_h_hex(_h_f[2]))._h_ifx(0))"
	}
	pre := recordTwinCode(res) + globalConfigLoop(res, false)
	if mutation("adjh-bound") || mutation("adjt-bound") { // mutation: the twin's bound on the shrinking side of adjust_head / adjust_tail is 13 bytes
		pre = "BPF::ADJH_BOUND[0] = 13\n" + pre
	}
	return k + "# spinelbpf twin harness\n" + harness(res, pre, "%s.poke(%s, %s)", run, runPkt, "%s.peek(%s)", false), nil
}

// KernelHarness returns the kernel harness program (the eBPF side of the user's source plus a user-space harness — built with
// spinelbpf build -o and run as root).
func KernelHarness(text string, res *Result) (string, error) {
	k, err := keptSource(text, res)
	if err != nil {
		return "", err
	}
	pre := "# spinelbpf kernel harness\nrequire \"spinelbpf\"\n" + globalConfigLoop(res, true) + tracingKernelSetup(res) + skHarnessSetup(res)
	return k + harness(res, pre, "_h_obj.map_put(%s, %s, %s)", "_h_obj.test_run_xdp(%q, 1)", "_h_obj.test_run_xdp_packet(%q, _h_hex(_h_f[2]))", "_h_obj.map_get(%s, %s)", true, tracingKernelCmds(res)), nil
}

// recordTwinCode returns the twin's record view classes and helpers. A slot is an Array of member values, a view has a getter and
// a setter per member, and _h_radd wraps at the member's width (u masks, i wraps as signed — 64 bits do not wrap: an overflow is a
// Spinel RangeError, and the test tables have no overflowing rows).
// Programs without a record map also get the stubs (the native library's RecordRef refers to them).
func recordTwinCode(res *Result) string {
	var b strings.Builder
	b.WriteString("# spinelbpf twin records\n")
	// A slot is a flat Array (an array member takes one entry per element — the same order as the library's map_get_record).
	// The view of an array member is an HArr (an index outside the range is an error).
	b.WriteString("class HArr\n  def initialize(v, off, n)\n    @v = v\n    @off = off\n    @n = n\n  end\n\n  def [](i)\n    if i < 0 || i >= @n\n      raise IndexError, \"twin: index outside the array member\"\n    end\n    @v[@off + i]\n  end\n\n  def []=(i, x)\n    if i < 0 || i >= @n\n      raise IndexError, \"twin: index outside the array member\"\n    end\n    @v[@off + i] = x\n  end\nend\n")
	recs := usedRecords(res)
	for _, r := range recs {
		if r == lpmKey4 {
			continue // the library's LPM key record (the twin has no Struct for it — a lookup takes 4 bytes)
		}
		fmt.Fprintf(&b, "class HView%s\n  def initialize(v)\n    @v = v\n  end\n", r.Const)
		for i, f := range r.Fields {
			if f.Pad {
				continue
			}
			if f.Count > 0 {
				fmt.Fprintf(&b, "\n  def %s\n    HArr.new(@v, %d, %d)\n  end\n", f.Name, flatBase(r, i), f.Count)
				if f.Bits == 8 { // the destination of `r.load.m = t.copy(:f)` (a fixed N bytes — a different length is an error)
					fmt.Fprintf(&b, "\n  def %s=(a)\n    if a.length != %d\n      raise IndexError, \"twin: the copy is not %d bytes\"\n    end\n    i = 0\n    while i < %d\n      @v[%d + i] = a[i]\n      i += 1\n    end\n  end\n", f.Name, f.Count, f.Count, f.Count, flatBase(r, i))
				}
				continue
			}
			fmt.Fprintf(&b, "\n  def %s\n    @v[%d]\n  end\n\n  def %s=(x)\n    @v[%d] = x\n  end\n", f.Name, flatBase(r, i), f.Name, flatBase(r, i))
		}
		b.WriteString("end\n")
	}
	// _h_flat turns a sample Struct into a flat Array (element by element only for records with array members — the others stay to_a)
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
	// _h_radd's d and e are RecordRef#atomic_add's second and third arguments — (index d, delta e) for an array member, delta d otherwise
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

// recordPokeFuncs returns the harness's `poke M k member value` (the twin edits the slot's Array, the kernel does map_get → change →
// map_put — S.new takes explicit arguments).
// An array member is poked element by element under the name `m[i]` (for a record with array members the kernel writes back with
// map_put_record_values).
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
	if m.Record.HasArray() { // a record with array members is written flat, element by element
		return fmt.Sprintf("      _h_k = 0\n      while _h_k < %d\n        _h_obj.map_put_record_values(%s, _h_k, Array.new(%d, 0))\n        _h_k += 1\n      end\n", m.MaxEntries, m.Const, len(flatSlots(m.Record)))
	}
	zeros := strings.TrimSuffix(strings.Repeat("0, ", len(m.Record.Fields)), ", ")
	return fmt.Sprintf("      _h_k = 0\n      while _h_k < %d\n        _h_obj.map_put_record(%s, _h_k, %s.new(%s))\n        _h_k += 1\n      end\n", m.MaxEntries, m.Const, m.Record.Const, zeros)
}

// recordDump prints `M[k].member=v` for each named member (a kernel get error becomes err= on each member's line — the line count
// does not change). An array member is printed element by element as `M[k].m[i]=v`.
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

// ringSetup prepares the harness's ring buffers: the twin gets the record size and the limit of its capacity model (size − 1 — the
// kernel's mask), the kernel opens a reader.
// The mutation control ring-model (test builds only) sets the limit to size (misreading the kernel's condition — thinking a 4096-byte
// ring holds 128 records of 32 bytes).
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

// ringDrain reads every event of a ring buffer (with show false it discards them without printing — for reset).
func ringDrain(r *RingDecl, kernel, show bool) string {
	var b strings.Builder
	line := func(ind, ev string) {
		if !show {
			return
		}
		fi := 0 // the flat index into the kernel's read_record (an array member takes one index per element)
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

// hashSetup sets up the mutation control on the twin's hash capacity (hash-cap — read the capacity as max_entries + 1; test builds only).
func hashSetup(res *Result, kernel bool) string {
	var b strings.Builder
	for _, m := range res.Maps {
		if m.IsHash() && !kernel && mutation("hash-cap") {
			fmt.Fprintf(&b, "%s._h_cap(%d)\n", m.Const, m.MaxEntries+1)
		}
	}
	return b.String()
}

// hashKeyLoop returns code that loops over the keys of a hash map one by one (the loop body is body — `_h_kstr` holds the key as a
// string, `_h_kobj` the key to pass to the kernel API).
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

// hashReset empties a hash map (the twin resets it, the kernel deletes every key).
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

// hashDump prints a hash map's entries in the order of their key strings as `M{k}=v` / `M{k}.member=v` (the kernel enumerates in
// hash order — sort before comparing).
// An LRU map prints only the count (`M count=<n>` — the kernel's LRU does not fix which key it evicts).
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
	if m.PerCPU() { // the kernel's per-CPU rows become a sum per member and a count of non-zero slots; the twin has one slot
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

// pcpuName returns the name of the kernel harness's hash API (a per-CPU hash uses percpu_hash_*).
func pcpuName(m *MapDecl, name string) string {
	if m.PerCPU() {
		return "percpu_" + name
	}
	return name
}

// pcpuSetup returns the harness helpers for per-CPU maps: the count of non-zero slots and the sum per member. The kernel side also
// gets the number of possible CPUs and an Array of zero record Structs.
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

// pcpuArrayReset sets every CPU of every key of a kernel per-CPU array to 0.
func pcpuArrayReset(m *MapDecl) string {
	put := fmt.Sprintf("_h_obj.percpu_put(%s, _h_k, Array.new(_h_ncpu, 0))", m.Const)
	if m.Record != nil {
		put = fmt.Sprintf("_h_obj.percpu_put_record(%s, _h_k, _h_z%s)", m.Const, m.Name)
	}
	return fmt.Sprintf("      _h_k = 0\n      while _h_k < %d\n        %s\n        _h_k += 1\n      end\n", m.MaxEntries, put)
}

// pcpuArrayDump prints, for each key of a per-CPU array, the sum over CPUs (`M[k]=<sum>` / `M[k].m=<sum>`) and the count of non-zero
// slots (`M[k] nz=<n>`). The twin has one slot (peek for integers, the slot for records), the kernel the per-CPU rows of percpu_get.
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

// noTracing returns an error for a Result that has a tracing program (the kernel-side tracing harness was to follow once the C
// loader supported tracing). It never silently builds the xdp form instead.
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

// The thread variant of the harness: `prun <prog> <runs> <hex_1> … <hex_T>` and `ppoke <Map> <T> <K>`. The kernel side runs truly in
// parallel on T Threads (the object and the values are passed as `Thread.new` arguments — a Spinel block cannot capture a non-integer
// local variable); the twin runs the same steps serially (the twin's maps are Ruby Arrays — concurrent writes without
// synchronisation could corrupt them). A harness that uses the Thread constant gets the threaded runtime, so it is kept out of the
// default harness.

// noSchedCls returns an error for a Result that has a sched_cls program (TwinHarness and KernelHarness have a sched_cls form; the
// thread variant and NativeTwin do not — never silently build the xdp form (XdpMd, test_run_xdp) instead).
func noSchedCls(res *Result, what string) error {
	for _, p := range res.Programs {
		if p.Kind == "sched_cls" {
			return fmt.Errorf("the %s has no sched_cls form (the twin and kernel harnesses do) — program %s", what, p.Name)
		}
	}
	return nil
}

// TwinHarnessThreads returns the twin side of the thread variant (serial — it does not use Thread).
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

// KernelHarnessThreads returns the kernel side of the thread variant (T Threads in parallel — it prints, as `overlaps=<n>`, how many
// of the Threads' start-to-end intervals overlap).
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
	pre := "# spinelbpf kernel harness, thread variant (parallel)\nrequire \"spinelbpf\"\n" + globalConfigLoop(res, true) // a program with globals reads the config lines and loads
	return k + harness(res, pre, "_h_obj.map_put(%s, %s, %s)", "_h_obj.test_run_xdp(%q, 1)", "_h_obj.test_run_xdp_packet(%q, _h_hex(_h_f[2]))", "_h_obj.map_get(%s, %s)", true, x+ppokeCode(res, true)), nil
}

// ppokeCode returns `ppoke <Map> <T> <K>` — it puts the value t*1000 + j at key t*K + j (integer array maps only).
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

// tracingKernelSetup sets up the kernel harness for tracing: after load it attaches every tracing root, and adds `self` (the harness's
// tgid) and `pokeself <Map> <key>` (puts that tgid in the map — the Filter). For fentry / fexit, `run` is the C loader (bml)'s tracing
// test run (on another thread — it prints the tid); for kprobe, `run <prog> a2=<v>` makes the harness thread call `poll(NULL, v, 0)`
// (do_sys_poll's nfds — register 2). To compare with the twin, feed the kernel's tid to the twin's `task` (a two-stage comparison:
// run the kernel side first, then the twin with those tids).
func tracingKernelSetup(res *Result) string {
	var b strings.Builder
	any := false
	for _, p := range res.Programs {
		if !attachesKernelFunc(p.Kind) { // xdp, sched_cls and socket_filter are not attached (test runs only)
			continue
		}
		any = true
		if p.Kind == "fmod_ret" { // attach → test run → detach for each run command (two fmod_ret programs never stack on one function)
			continue
		}
		if p.Kind == "tp_btf" { // tp_btf has its own attach call
			fmt.Fprintf(&b, "_h_link_%s = _h_obj.attach_tp_btf(%q)\n", p.Name, p.Name)
			continue
		}
		if p.Kind == "uprobe" || p.Kind == "uretprobe" { // attached to the child process's pid (uretprobe too)
			fmt.Fprintf(&b, "_h_link_%s = _h_obj.attach_%s(%q, HUprobe.h_pid)\n", p.Name, p.Kind, p.Name)
			continue
		}
		fmt.Fprintf(&b, "_h_link_%s = _h_obj.attach_%s(%q)\n", p.Name, p.Kind, p.Name)
	}
	if !any {
		return ""
	}
	piC, piF := "", ""
	if hasTpBtf(res) { // priority-inheritance boost / deboost (sched_pi_setprio's pi_task present / absent — the shape of mojo-bpf-mlir's helper)
		piC, piF = hPiC+hCommC, "  ffi_func :h_pi, [:long], :long\n  ffi_func :h_setcomm, [:str], :long\n  ffi_func :h_commb, [:long], :long\n"
	} else if hasComm(res) { // an output_comm program — only the comm command (pi is a tool for the tp_btf tests)
		piC, piF = hCommC, "  ffi_func :h_setcomm, [:str], :long\n  ffi_func :h_commb, [:long], :long\n"
	}
	if hasStrptr(res) { // fork a child that waits on a pipe (h_spawn — returns the child's pid); after the pid is in the Filter, release it to execve(path) and wait (h_release)
		piC, piF = piC+hSpawnC, piF+"  ffi_func :h_spawn, [:str], :long\n  ffi_func :h_release, [:long], :long\n"
	}
	if hasArgv(res) { // fork a child that waits on a pipe (h_argv_spawn — argv is `,`-separated, @e is an empty element, @null is no elements), then release it to execve and wait (h_argv_release)
		piC, piF = piC+hArgvSpawnC, piF+"  ffi_func :h_argv_spawn, [:str], :long\n  ffi_func :h_argv_release, [:long], :long\n"
	}
	if hasKprobePtr(res) { // call openat2(2) directly — how (struct open_how: flags 0, mode, resolve) is copied to the kernel stack; a mode without O_CREAT gives EINVAL
		piC, piF = piC+"    static const char h_fname_buf[] = \"/nonexistent-e116\";\n    long h_fname(void) { return (long)h_fname_buf; }\n    long h_openat2(long mode, long resolve) { struct { unsigned long long flags, mode, resolve; } how = {0, (unsigned long long)mode, (unsigned long long)resolve}; return (long)syscall(SYS_openat2, -100 /* AT_FDCWD */, h_fname_buf, &how, sizeof how); }\n", piF+"  ffi_func :h_openat2, [:long, :long], :long\n  ffi_func :h_fname, [], :long\n" // the filename is a static array — h_fname gives its address
	}
	if hasKind(res, "ksyscall") { // call prctl(2) directly (an unknown option gives EINVAL — no state changes)
		piC, piF = piC+"    long h_prctl(long o, long a2, long a3, long a4, long a5) { return (long)syscall(SYS_prctl, o, a2, a3, a4, a5); }\n", piF+"  ffi_func :h_prctl, [:long, :long, :long, :long, :long], :long\n"
	}
	if hasKind(res, "tracepoint") { // call write(2) directly on an fd that is not open (EBADF — sys_enter_write fires at syscall entry anyway)
		piC, piF = piC+"    long h_write(long fd, long count) { return (long)syscall(SYS_write, (int)fd, (void *)0, (size_t)count); }\n", piF+"  ffi_func :h_write, [:long, :long], :long\n"
	}
	if hasKind(res, "tracepoint") || hasKind(res, "ksyscall") {
		// call openat(2) directly (for ksyscall too) with AT_FDCWD and O_RDONLY — a path that does not exist is fine, the return value
		// is dropped. h_openat_null passes NULL as the filename (EFAULT).
		piC, piF = piC+"    long h_openat(const char *p) { long r = (long)syscall(SYS_openat, -100, p, 0); if (r >= 0) close((int)r); return r; }\n    long h_openat_null(void) { return (long)syscall(SYS_openat, -100, (const char *)0, 0); }\n", piF+"  ffi_func :h_openat, [:str], :long\n  ffi_func :h_openat_null, [], :long\n"
	}
	if hasTpArray(res) { // a connect over loopback to the harness's own listener
		piC, piF = piC+hTcpConnectC, piF+"  ffi_func :h_tcpconnect, [:long], :long\n"
	}
	if hasKpath(res) { // a connect and send from 127.0.0.1 to 127.0.0.2
		piC, piF = piC+hTcpSendC, piF+"  ffi_func :h_tcpsend, [], :long\n  ffi_func :h_tcpsend_cport, [], :long\n"
	}
	if hasKaddr(res) { // an O_DIRECT read of the harness's own file and the sector FIEMAP expects
		piC, piF = piC+hODirectC, piF+"  ffi_func :h_odirect, [:str, :long], :long\n  ffi_func :h_od_sector, [], :long\n"
	}
	if hasRawTp(res) { // the getppid(2) syscall directly (bypassing any libc cache — sys_enter's number 110)
		piC, piF = piC+"    long h_getppid(void) { return (long)syscall(SYS_getppid); }\n", piF+"  ffi_func :h_getppid, [], :long\n"
	}
	return uprobeKernelSetup(res) + "module HTrace\n  ffi_source <<~C\n    #include <poll.h>\n    #include <unistd.h>\n    #include <sys/syscall.h>\n    #include <sys/wait.h>\n    long h_poll(long n) { return (long)poll(NULL, (nfds_t)n, 0); }\n    long h_tgid(void) { return (long)getpid(); }\n    long h_tid(void) { return (long)syscall(SYS_gettid); }\n    long h_fork(void) { pid_t p = fork(); if (p == 0) _exit(0); if (p < 0) return -1; int st; waitpid(p, &st, 0); return (long)p; }\n" + piC + "  C\n  ffi_func :h_poll, [:long], :long\n  ffi_func :h_tgid, [], :long\n  ffi_func :h_tid, [], :long\n  ffi_func :h_fork, [], :long\n" + piF + "end\n" + b.String()
}

// hCommC is the C behind the harness's `comm <name>`: it sets the harness thread's comm with prctl(PR_SET_NAME) (a forked child
// copies its parent's comm) and returns the 16 bytes of PR_GET_NAME one byte at a time.
const hCommC = `    #include <sys/prctl.h>
    #include <string.h>
    static char h_comm_buf[16];
    long h_setcomm(const char *s) { if (prctl(PR_SET_NAME, s, 0, 0, 0) != 0) return -1; memset(h_comm_buf, 0, 16); return prctl(PR_GET_NAME, h_comm_buf, 0, 0, 0) == 0 ? 0 : -1; }
    long h_commb(long i) { return (long)(unsigned char)h_comm_buf[i & 15]; }
`

// hPiC is the C behind the harness's `pi <R>`: a SCHED_OTHER owner thread holds a PTHREAD_PRIO_INHERIT mutex and a SCHED_FIFO
// (priority 10) waiter thread waits for the lock → the kernel boosts the owner (sched_pi_setprio(owner, waiter)) and deboosts it on
// unlock (sched_pi_setprio(owner, NULL)). It does this R times and returns the tid of the last waiter (negative is an error — -2
// means no permission for SCHED_FIFO (needs root)). The same shape as mojo-bpf-mlir's testhelper_pi_rounds.
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
	if hasTpBtf(res) { // the fork trigger — prints the child's pid (the child exits at once — single-threaded, so pid = tgid)
		b.WriteString("    elsif _h_cmd == \"fork\"\n      puts \"child=#{HTrace.h_fork}\"\n")
		b.WriteString("    elsif _h_cmd == \"pi\"\n      puts \"waiter=#{HTrace.h_pi(_h_f[1].to_i)}\"\n") // the priority-inheritance trigger
	}
	if hasTpBtf(res) || hasComm(res) { // the comm command (output_comm programs too)
		b.WriteString("    elsif _h_cmd == \"comm\"\n      if HTrace.h_setcomm(_h_f[1]) != 0\n        raise \"prctl PR_SET_NAME failed\"\n      end\n      _h_c = \"\"\n      _h_j = 0\n      while _h_j < 16\n        _h_c += _h_hexs([HTrace.h_commb(_h_j)], 0, 1)\n        _h_j += 1\n      end\n      puts \"comm=#{_h_c}\"\n")
	}
	if hasStrptr(res) { // the real exec trigger — `exec <Map> <key> <path>` (the child's pid goes to Map[key], then the child calls execve(path) itself, with no shell in between)
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
	if hasArgv(res) { // the real trigger for execve's argv — `execargv <Map> <key> <w1,w2,…|@null>` (@e is an empty element — the child's pid goes to Map[key], then the child calls execve("/nonexistent-e151", argv))
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
	if hasKprobePtr(res) { // the real trigger for do_sys_openat2 — `openat2 <mode> <resolve> <n>` (n times on the harness thread; prints the tid)
		b.WriteString("    elsif _h_cmd == \"openat2\"\n      _h_j = 0\n      while _h_j < _h_f[3].to_i\n        HTrace.h_openat2(_h_f[1].to_i, _h_f[2].to_i)\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n      puts \"fname=#{HTrace.h_fname}\"\n") // the filename's user-space address
	}
	if hasKind(res, "ksyscall") { // the real prctl trigger — `prctl <option> <a2> <a3> <a4> <a5> <n>` (n times on the harness thread; prints the tid)
		b.WriteString("    elsif _h_cmd == \"prctl\"\n      _h_j = 0\n      while _h_j < _h_f[6].to_i\n        HTrace.h_prctl(_h_f[1].to_i, _h_f[2].to_i, _h_f[3].to_i, _h_f[4].to_i, _h_f[5].to_i)\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasKind(res, "tracepoint") { // the real sys_enter_write trigger — `write <fd> <count> <n>` (n times on the harness thread; prints the tid)
		b.WriteString("    elsif _h_cmd == \"write\"\n      _h_j = 0\n      while _h_j < _h_f[3].to_i\n        HTrace.h_write(_h_f[1].to_i, _h_f[2].to_i)\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasKind(res, "tracepoint") || hasKind(res, "ksyscall") {
		// the real openat trigger (for ksyscall too) — `openat <path|@empty|@null> <n>` (n times on the harness thread; prints the tid)
		b.WriteString("    elsif _h_cmd == \"openat\"\n      _h_j = 0\n      while _h_j < _h_f[2].to_i\n        if _h_f[1] == \"@null\"\n          HTrace.h_openat_null\n        elsif _h_f[1] == \"@empty\"\n          HTrace.h_openat(\"\")\n        else\n          HTrace.h_openat(_h_f[1])\n        end\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasKaddr(res) { // the real blk_mq_start_request trigger — `odirect <dir> <n>` (prints the number of successful reads, the expected sector and the tid)
		b.WriteString("    elsif _h_cmd == \"odirect\"\n      puts \"reads=#{HTrace.h_odirect(_h_f[1], _h_f[2].to_i)}\"\n      puts \"want_sector=#{HTrace.h_od_sector}\"\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasKpath(res) { // the real tcp_sendmsg trigger — `tcpsend <n>` (n times on the harness thread; prints each round's listen port and client port, and the tid)
		b.WriteString("    elsif _h_cmd == \"tcpsend\"\n      _h_j = 0\n      while _h_j < _h_f[1].to_i\n        puts \"port=#{HTrace.h_tcpsend}\"\n        puts \"cport=#{HTrace.h_tcpsend_cport}\"\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasTpArray(res) { // the real sock/inet_sock_set_state trigger — `tcpconnect <4|6> <n>` (n times on the harness thread; prints each round's listen port, and the tid)
		b.WriteString("    elsif _h_cmd == \"tcpconnect\"\n      _h_j = 0\n      while _h_j < _h_f[2].to_i\n        puts \"port=#{HTrace.h_tcpconnect(_h_f[1].to_i)}\"\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasRawTp(res) { // the real sys_enter trigger — the harness thread calls getppid(2) N times (prints the tid)
		b.WriteString("    elsif _h_cmd == \"getppid\"\n      _h_j = 0\n      while _h_j < _h_f[1].to_i\n        HTrace.h_getppid\n        _h_j += 1\n      end\n      puts \"tid=#{HTrace.h_tid}\"\n")
	}
	if hasUprobe(res) { // the child process's pid_tgid (single-threaded — tid = pid) goes to the twin's task (the two-stage comparison)
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
	if p.Kind == "tp_btf" { // the kernel's tracing test run runs only fentry / fexit / fmod_ret (and fsession on 7.1.8); for tp_btf it returns EFAULT without running the program (on 7.1.8, 6.12.111 and 6.6.157) — use the real `fork` trigger
		b.WriteString("        raise \"a tp_btf program has no test run (the kernel returns EFAULT) — trigger it with the fork command\"\n")
		return b.String()
	}
	if p.Kind == "ksyscall" { // a kprobe program has no test run
		b.WriteString("        raise \"a ksyscall program has no test run — trigger it with the prctl command\"\n")
		return b.String()
	}
	if p.Kind == "tracepoint" { // a tracepoint program has no test run (the kernel's BPF_PROG_TYPE_TRACEPOINT)
		b.WriteString("        raise \"a tracepoint program has no test run — trigger it with the write command\"\n")
		return b.String()
	}
	if p.Kind == "raw_tp" { // a test run (in the calling thread's context — the tid is the harness thread's), 12 args (unset indexes are 0)
		b.WriteString("        _h_args = Array.new(12, 0)\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          _h_n = -1\n          _h_j = 0\n          while _h_j < 12\n            if _h_kv[0] == \"a#{_h_j}\"\n              _h_n = _h_j\n            end\n            _h_j += 1\n          end\n          if _h_n < 0\n            raise \"a raw_tp run sets a0..a11 only\"\n          end\n          _h_args[_h_n] = _h_kv[1].to_i\n          _h_i += 1\n        end\n")
		fmt.Fprintf(&b, "        _h_r = _h_obj.test_run_raw_tp(%q, _h_args)\n        puts \"ret=#{_h_r} tid=#{HTrace.h_tid}\"\n", p.Name)
		return b.String()
	}
	if p.Kind == "kprobe" || p.Kind == "kretprobe" { // kretprobe also probes do_sys_poll's return (for n > 0, ufds is NULL, so −EFAULT)
		b.WriteString("        _h_n = 0\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if _h_kv[0] == \"a2\"\n            _h_n = _h_kv[1].to_i\n          else\n            raise \"the kernel harness triggers the kprobe through poll(2) — only a2 (nfds) is set\"\n          end\n          _h_i += 1\n        end\n        HTrace.h_poll(_h_n)\n        puts \"ret=0 tid=#{HTrace.h_tid}\"\n")
		return b.String()
	}
	if p.Kind == "fmod_ret" { // attach → test run (the kernel calls bpf_modify_return_test) → detach. The C loader's (bml's) tracing test run returns the test thread's tid, not the kernel's retval — the return value is observed by an fexit program
		fmt.Fprintf(&b, "        _h_lk = _h_obj.attach_fmod_ret(%q)\n        _h_td = _h_obj.test_run_tracing(%q, 1)\n        _h_lk.detach\n        puts \"ret=0 tid=#{_h_td}\"\n", p.Name, p.Name)
		return b.String()
	}
	fmt.Fprintf(&b, "        puts \"ret=0 tid=#{_h_obj.test_run_tracing(%q, 1)}\"\n", p.Name)
	return b.String()
}

// globalConfigLoop writes the harness's handling of globals: a program with globals first reads the `config <Name> <v>` lines on
// stdin up to the `load` line; the kernel side then calls `load_embedded_config` (on failure it prints `load err=<class> msg=<text>`
// and stops — the ConfigNotSet test), the twin only sets the values. A program without globals is unchanged.
func globalConfigLoop(res *Result, kernel bool) string {
	if kernel && hasUprobe(res) { // every uprobe program targets ARGV[0] (a declared absolute path targets that path); the harness has no form combining globals and uprobes — stop
		if len(res.Globals) > 0 {
			return "raise \"the kernel harness does not combine globals and uprobe targets\"\n"
		}
		var b strings.Builder
		b.WriteString("_h_tg = SpinelBPF::UprobeTargets.new\n")
		for _, p := range res.Programs {
			if p.Kind == "uprobe" || p.Kind == "uretprobe" {
				if p.SysTarget != "" { // a system library target — probe the library that the child process (ARGV[0]) calls
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
	k := 0
	for _, g := range res.Globals {
		if g.Class == "ExitInfo" { // the .data exit record is not set or dumped by the harness
			continue
		}
		kw := "if"
		k++
		if k > 1 {
			kw = "elsif"
		}
		switch {
		case !kernel:
			fmt.Fprintf(&b, "    %s _h_f[1] == %q\n      BPF.set_global(%q, _h_f[2].to_i)\n", kw, g.Name, g.Name)
		case g.Counter() || g.Class == "Global":
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

// globalDump returns dump's lines for the globals (`<Name>=<v>` — the twin reads value, the kernel config_get / optional_get /
// counter_get).
func globalDump(res *Result, kernel bool) string {
	var b strings.Builder
	for _, g := range res.Globals {
		if g.Class == "ExitInfo" {
			continue
		}
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

// flatSlot is one entry of a record's flat layout (an array member has one entry per element, `m[i]` — the same as the library's
// map_get_record and the embedded table).
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

// flatBase returns the first index of member i in the flat layout.
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

// noUprobe returns an error for a Result that has a uprobe program (the uprobe forms of the twin and kernel harnesses — the target's
// child process and the target passed to load — are built separately). It never silently builds another form instead.
func noUprobe(res *Result) error {
	for _, p := range res.Programs {
		if p.Kind == "uprobe" || p.Kind == "uretprobe" {
			return fmt.Errorf("the twin and kernel harnesses for a uprobe program are not written here (they need the target's child process and the load's uprobe targets) — program %s", p.Name)
		}
	}
	return nil
}

// parenDelta returns the number of `(` minus the number of `)` in a line (not counting those inside string literals or comments —
// keptSource uses it to find the end of a multi-line declaration).
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

// scxLogLines print the sched_ext ops a call made (the twin's models log them), then clear the log.
const scxLogLines = "        _h_li = 0\n        while _h_li < BPF::Scx::LOG.length\n          puts \"scx=#{BPF::Scx::LOG[_h_li]}\"\n          _h_li += 1\n        end\n        BPF::Scx::LOG.clear\n"

// soKptrNames are the quoted `<pre>.<m>` names a run may set: the integer members, and those of an embedded struct
// (`a0.scx.dsq_vtime`), as twinKPtr reads them.
func soKptrNames(pre string, d *KernelTypeDecl, byConst map[string]*KernelTypeDecl) []string {
	var ok []string
	for _, f := range d.Fields {
		switch f.Kind {
		case "int":
			ok = append(ok, fmt.Sprintf("%q", pre+"."+f.Name))
		case "struct":
			if e := byConst[f.Ptr]; e != nil {
				ok = append(ok, soKptrNames(pre+"."+f.Name, e, byConst)...)
			}
		}
	}
	return ok
}

// soKptrTwinRun writes the twin's `run <prog> [a<i>=<v> …] [a<s>.<m>=<v> …] [a<s>=null]` for a struct_ops program that reads its
// socket argument s: integer arguments are cut to the member table's width, the tcp_sock is the kernel type's Struct
// built from the given members (0 when not given), `a<s>=null` makes it NULL. It prints `ret=<v>` (0 for a void member) and then,
// for a present socket, `f.<m>=<v>` for each integer member of the Struct after the call (the stores the callback made).
func soKptrTwinRun(kw string, p *Program, kts []*KernelTypeDecl) string {
	byConst := map[string]*KernelTypeDecl{}
	for _, d := range kts {
		byConst[d.Const] = d
	}
	m := soMemberOf(p)
	var ok []string
	for i, ar := range m.Args {
		if ar.Kind == "int" || ar.Kind == "enum" {
			ok = append(ok, fmt.Sprintf("%q", fmt.Sprintf("a%d", i)))
		}
	}
	for _, a := range p.TArgs {
		ok = append(ok, fmt.Sprintf("%q", fmt.Sprintf("a%d", a.Idx)))
		ok = append(ok, soKptrNames(fmt.Sprintf("a%d", a.Idx), a.KT, byConst)...)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_n = Array.new(0, \"\")\n        _h_v = Array.new(0, 0)\n        _h_s = Array.new(0, \"\")\n        _h_ok = [%s]\n        _h_i = 2\n        while _h_i < _h_f.length\n          _h_kv = _h_f[_h_i].split(\"=\")\n          if !_h_ok.include?(_h_kv[0])\n            raise \"not an argument of %s.%s: #{_h_kv[0]}\"\n          end\n          _h_n.push(_h_kv[0])\n          _h_v.push(_h_kv[1].to_i)\n          _h_i += 1\n        end\n        _h_args = Array.new(%d, 0)\n", kw, p.Name, strings.Join(ok, ", "), p.SOType, p.SOMember, len(m.Args))
	for i, ar := range m.Args {
		if ar.Kind == "int" || ar.Kind == "enum" {
			fmt.Fprintf(&b, "        _h_args[%d] = %s\n", i, widthCut(fmt.Sprintf("_h_fv(_h_n, _h_v, %q)", fmt.Sprintf("a%d", i)), ar.Type))
		}
	}
	var kps, idx []string
	for _, a := range p.TArgs {
		v := fmt.Sprintf("_h_kp%d", a.Idx)
		twinKPtr(&b, v, a.KT, fmt.Sprintf("a%d", a.Idx), "        ", byConst)
		kps = append(kps, v)
		idx = append(idx, fmt.Sprint(a.Idx))
	}
	fmt.Fprintf(&b, "        _h_ks = [%s]\n", strings.Join(kps, ", "))
	for k, a := range p.TArgs {
		fmt.Fprintf(&b, "        if _h_n.include?(\"a%d\")\n          _h_ks[%d] = nil\n        end\n", a.Idx, k)
	}
	call := fmt.Sprintf("%s(BPF::StructOpsCtx.new(_h_args, _h_ks, [%s]))", p.Name, strings.Join(idx, ", "))
	if p.Ret == "void" {
		fmt.Fprintf(&b, "        %s\n        puts \"ret=0\"\n", call)
	} else {
		fmt.Fprintf(&b, "        puts \"ret=#{%s}\"\n", call)
	}
	if p.Scx {
		b.WriteString(scxLogLines)
	}
	for k, a := range p.TArgs {
		fmt.Fprintf(&b, "        if _h_ks[%d]\n", k)
		for _, f := range a.KT.Fields {
			if f.Kind == "int" {
				fmt.Fprintf(&b, "          puts \"f.%s=#{_h_kp%d.load.%s}\"\n", f.Name, a.Idx, f.Name)
			}
		}
		b.WriteString("        end\n")
	}
	return b.String()
}
