require "bpf"




FlowKey = Struct.new(:proto, :_pad0, :port, :addr)
BPF.record(FlowKey, proto: :u8, _pad0: :u8, port: :u16, addr: :u32)

Frames = BPF::LruHashMap.new("Frames", FlowKey.new(0, 0, 0, 0), :u64, 1024)
Bytes = BPF::LruHashMap.new("Bytes", FlowKey.new(0, 0, 0, 0), :u64, 1024)
Errs = BPF::ArrayMap.new("Errs", :u64, 1)

def flowcount(ctx)
  eth = ctx.check(0, 14)
  if eth
    if eth.be16(12) == 0x0800
      proto = 0
      addr = 0
      len = 0
      ihl = 0
      ip = ctx.check(14, 20)
      if ip
        ihl = ip.u8(0) & 0x0F
        proto = ip.u8(9)
        len = ip.be16(2)
        addr = ip.be32(16)
      end
      port = 0
      if ihl == 5 && (proto == 17 || proto == 6)
        l4 = ctx.check(34, 4)
        if l4
          port = l4.be16(2)
        end
      end
      s1 = Frames.add_or_init(FlowKey.new(proto, 0, port, addr), 1)
      s2 = Bytes.add_or_init(FlowKey.new(proto, 0, port, addr), len)
      if s1 != 0 || s2 != 0
        Errs.atomic_add(0, 1)
      end
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :flowcount




require "spinelbpf"

USAGE = "usage: flowcount --iface IF [--duration-ms MS] | --selftest"
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


def frame(et, ihl, total, proto, dst, port)
  f = Array.new(64, 0)
  f[12] = et >> 8
  f[13] = et & 0xFF
  if et == 0x0800
    f[14] = 0x40 | ihl
    f[16] = total >> 8
    f[17] = total & 0xFF
    f[23] = proto
    f[30] = (dst >> 24) & 0xFF
    f[31] = (dst >> 16) & 0xFF
    f[32] = (dst >> 8) & 0xFF
    f[33] = dst & 0xFF
    o = 14 + ihl * 4
    f[o + 2] = port >> 8
    f[o + 3] = port & 0xFF
  end
  f
end

def show(obj)
  ks = obj.hash_keys_rk(Frames)
  lines = []
  i = 0
  while i < ks.length
    k = FlowKey.new(ks[i][0], ks[i][1], ks[i][2], ks[i][3])
    lines.push("flow proto=#{k.proto} port=#{k.port} addr=#{k.addr} frames=#{obj.hash_get_rk(Frames, k)} bytes=#{obj.hash_get_rk(Bytes, k)}")
    i += 1
  end
  lines.sort.each { |l| puts l }
  puts "flows=#{ks.length} errs=#{obj.map_get(Errs, 0)}"
end

obj = SpinelBPF.load_embedded
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
if selftest
  dst = 167772162
  obj.test_run_xdp_packet("flowcount", frame(0x0800, 5, 29, 17, dst, 9999))
  obj.test_run_xdp_packet("flowcount", frame(0x0800, 5, 40, 17, dst, 9999))
  obj.test_run_xdp_packet("flowcount", frame(0x0800, 5, 52, 6, dst, 443))
  obj.test_run_xdp_packet("flowcount", frame(0x0800, 5, 84, 1, dst, 0))
  obj.test_run_xdp_packet("flowcount", frame(0x86DD, 5, 0, 0, 0, 0))
  obj.test_run_xdp_packet("flowcount", frame(0x0800, 6, 33, 17, dst, 53))
  show(obj)
  ok = true
  [[17, 9999, 2, 69], [6, 443, 1, 52], [1, 0, 1, 84], [17, 0, 1, 33]].each do |c|
    k = FlowKey.new(c[0], 0, c[1], dst)
    f = obj.hash_get_rk(Frames, k)
    b = obj.hash_get_rk(Bytes, k)
    if f != c[2] || b != c[3]
      puts "selftest: flow proto=#{c[0]} port=#{c[1]} got frames=#{f} bytes=#{b}, want #{c[2]} / #{c[3]}"
      ok = false
    end
  end
  if obj.hash_keys_rk(Frames).length != 4 || obj.map_get(Errs, 0) != 0
    puts "selftest: want 4 flows and no errors"
    ok = false
  end
  obj.close
  if !ok
    puts "selftest FAILED"
    exit 1
  end
  puts "selftest ok"
else
  link = obj.attach_xdp("flowcount", iface)
  puts "attached flowcount to #{iface}"
  $stdout.flush
  sleep(duration_ms / 1000.0)
  link.detach
  show(obj)
  obj.close
end
