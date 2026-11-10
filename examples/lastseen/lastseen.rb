require "bpf"



LastSeen = Struct.new(:ethertype, :proto, :_pad0, :len, :ns)
BPF.record(LastSeen, ethertype: :u16, proto: :u8, _pad0: :u8, len: :u32, ns: :u64)
Count = Struct.new(:frames)
BPF.record(Count, frames: :u64)

Last = BPF::RecordMap.new("Last", LastSeen.new(0, 0, 0, 0, 0), 5)
Stats = BPF::RecordMap.new("Stats", Count.new(0), 5)

def last_seen(ctx)
  eth = ctx.check(0, 14)
  if eth
    et = eth.be16(12)
    kind = 3
    if et == 0x0800
      kind = 0
    elsif et == 0x86DD
      kind = 1
    elsif et == 0x0806
      kind = 2
    end
    proto = 0
    len = 0
    if kind == 0
      ip = ctx.check(14, 20)
      if ip
        proto = ip.u8(9)
        len = ip.be16(2)
      end
    end
    Last.update(kind, LastSeen.new(et, proto, 0, len, BPF.ktime_ns))
    s = Stats.lookup(kind)
    if s
      s.atomic_add(:frames, 1)
    end
  else
    Last.update(4, LastSeen.new(0, 0, 0, 0, BPF.ktime_ns))
    t = Stats.lookup(4)
    if t
      t.atomic_add(:frames, 1)
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :last_seen




require "spinelbpf"

USAGE = "usage: lastseen --iface IF [--duration-ms MS] | --selftest"
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


def frame(et, total, proto)
  f = Array.new(64, 0)
  f[12] = et >> 8
  f[13] = et & 0xFF
  if et == 0x0800
    f[14] = 0x45
    f[16] = total >> 8
    f[17] = total & 0xFF
    f[23] = proto
  end
  f
end


def last(obj, k)
  v = obj.map_get_record(Last, k)
  LastSeen.new(v[0], v[1], v[2], v[3], v[4])
end

def frame_count(obj, k)
  obj.map_get_record(Stats, k)[0]
end

def show(obj)
  counts = []
  k = 0
  while k < 5
    counts.push(frame_count(obj, k))
    k += 1
  end
  l = last(obj, 0)
  puts "stats=#{counts.join(",")} ipv4_last_proto=#{l.proto} ipv4_last_len=#{l.len} ipv4_last_ns_nonzero=#{l.ns > 0}"
end

obj = SpinelBPF.load_embedded
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
if selftest
  ok = true
  prev = 0
  [[0x0800, 84, 17], [0x0800, 60, 1], [0x86DD, 0, 0], [0x0806, 0, 0], [0x88CC, 0, 0], [0x0800, 40, 6]].each do |c|
    obj.test_run_xdp_packet("last_seen", frame(c[0], c[1], c[2]))
    k = 3
    if c[0] == 0x0800
      k = 0
    elsif c[0] == 0x86DD
      k = 1
    elsif c[0] == 0x0806
      k = 2
    end
    l = last(obj, k)
    if l.ethertype != c[0] || l.proto != c[2] || l.len != c[1] || l.ns == 0
      puts "selftest: kind #{k} got #{l.inspect}, want ethertype=#{c[0]} proto=#{c[2]} len=#{c[1]} ns>0"
      ok = false
    end
    if k == 0
      if l.ns <= prev
        puts "selftest: IPv4 ns #{l.ns} is not after #{prev}"
        ok = false
      end
      prev = l.ns
    end
  end
  show(obj)
  want = [3, 1, 1, 1, 0]
  k = 0
  while k < 5
    if frame_count(obj, k) != want[k]
      puts "selftest: kind #{k} frames #{frame_count(obj, k)}, want #{want[k]}"
      ok = false
    end
    k += 1
  end
  obj.close
  if !ok
    puts "selftest FAILED"
    exit 1
  end
  puts "selftest ok"
else
  link = obj.attach_xdp("last_seen", iface)
  puts "attached last_seen to #{iface}"
  $stdout.flush
  sleep(duration_ms / 1000.0)
  show(obj)
  link.detach
  obj.close
end
