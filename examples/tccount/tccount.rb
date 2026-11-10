require "bpf"





Counts = BPF::ArrayMap.new("Counts", :u64, 15)

def tcc_xdp(ctx)
kind = 4
eth = ctx.check(0, 14)
if eth
  if eth.be16(12) == 0x0800
    ip = ctx.check(14, 21)
    if ip
      if ip.u8(0) == 0x45
        proto = ip.u8(9)
        if proto == 17
          kind = 0
        elsif proto == 1
          t = ip.u8(20)
          if t == 8
            kind = 1
          elsif t == 0
            kind = 2
          elsif t == 3
            kind = 3
          end
        end
      end
    end
  end
end
  Counts.atomic_add(kind, 1)
  BPF::XDP_PASS
end

def tcc_in(skb)
kind = 4
eth = skb.check(0, 14)
if eth
  if eth.be16(12) == 0x0800
    ip = skb.check(14, 21)
    if ip
      if ip.u8(0) == 0x45
        proto = ip.u8(9)
        if proto == 17
          kind = 0
        elsif proto == 1
          t = ip.u8(20)
          if t == 8
            kind = 1
          elsif t == 0
            kind = 2
          elsif t == 3
            kind = 3
          end
        end
      end
    end
  end
end
  Counts.atomic_add(5 + kind, 1)
  BPF::TC_PASS
end

def tcc_out(skb)
kind = 4
eth = skb.check(0, 14)
if eth
  if eth.be16(12) == 0x0800
    ip = skb.check(14, 21)
    if ip
      if ip.u8(0) == 0x45
        proto = ip.u8(9)
        if proto == 17
          kind = 0
        elsif proto == 1
          t = ip.u8(20)
          if t == 8
            kind = 1
          elsif t == 0
            kind = 2
          elsif t == 3
            kind = 3
          end
        end
      end
    end
  end
end
  Counts.atomic_add(10 + kind, 1)
  BPF::TC_PASS
end
BPF.xdp :tcc_xdp
BPF.tcx :tcc_in, :ingress
BPF.tcx :tcc_out, :egress




require "spinelbpf"

USAGE = "usage: tccount --iface IF [--duration-ms MS] | --selftest"
HOOKS = ["xdp", "tc_ingress", "tc_egress"]
KINDS = ["udp", "echo_request", "echo_reply", "unreachable", "other"]
iface = ""
duration_ms = 0
selftest = false
i = 0
while i < ARGV.length
  a = ARGV[i]
  if a == "--iface" && i + 1 < ARGV.length
    iface = ARGV[i + 1]
    i += 2
  elsif a == "--duration-ms" && i + 1 < ARGV.length
    duration_ms = ARGV[i + 1].to_i
    i += 2
  elsif a == "--selftest"
    selftest = true
    i += 1
  else
    raise "#{USAGE} (unknown argument #{a})"
  end
end
if iface == "" && !selftest
  raise USAGE
end


def frame(et, proto, icmp_type)
  f = Array.new(64, 0)
  f[12] = et >> 8
  f[13] = et & 0xFF
  if et == 0x0800
    f[14] = 0x45
    f[23] = proto
    f[34] = icmp_type
  end
  f
end

def show(obj)
  h = 0
  while h < 3
    line = "count #{HOOKS[h]}"
    k = 0
    while k < 5
      line = line + " #{KINDS[k]}=#{obj.map_get(Counts, h * 5 + k)}"
      k += 1
    end
    puts line
    h += 1
  end
end

obj = SpinelBPF.load_embedded
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
if selftest
  frames = [frame(0x0800, 17, 0), frame(0x0800, 1, 8), frame(0x0800, 1, 0), frame(0x0800, 1, 3), frame(0x0806, 0, 0)]
  ok = true
  frames.each do |f|
    x = obj.test_run_xdp_packet("tcc_xdp", f)
    a = obj.test_run_tc_packet("tcc_in", f)
    b = obj.test_run_tc_packet("tcc_out", f)
    if x != BPF::XDP_PASS || a != BPF::TC_PASS || b != BPF::TC_PASS
      puts "selftest: verdicts xdp=#{x} tc_in=#{a} tc_out=#{b}, want #{BPF::XDP_PASS} / #{BPF::TC_PASS} / #{BPF::TC_PASS}"
      ok = false
    end
  end
  show(obj)
  s = 0
  while s < 15
    if obj.map_get(Counts, s) != 1
      puts "selftest: slot #{s} (#{HOOKS[s / 5]} #{KINDS[s % 5]}) is #{obj.map_get(Counts, s)}, want 1"
      ok = false
    end
    s += 1
  end
  obj.close
  if !ok
    puts "selftest FAILED"
    exit 1
  end
  puts "selftest ok"
else
  lx = obj.attach_xdp("tcc_xdp", iface)
  li = obj.attach_tcx("tcc_in", iface)
  lo = obj.attach_tcx("tcc_out", iface)
  puts "attached tcc_xdp tcc_in=#{li.tcx_direction} tcc_out=#{lo.tcx_direction} to #{iface}"
  $stdout.flush
  sleep(duration_ms / 1000.0)
  lo.detach
  li.detach
  lx.detach
  show(obj)
  obj.close
end
