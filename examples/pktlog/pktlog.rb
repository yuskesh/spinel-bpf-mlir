require "bpf"

# The eBPF side — for each frame of 14 bytes or more, puts an event (EtherType; for IPv4 the protocol and total length; ns from a monotonic clock) on a ring buffer.
# When the ring is full and the reservation fails, counts Drops[0] (the result of output is never discarded — diagnostic SB025).
Pkt = Struct.new(:ethertype, :proto, :_pad0, :len, :ns)
BPF.record(Pkt, ethertype: :u16, proto: :u8, _pad0: :u8, len: :u32, ns: :u64)

Events = BPF::RingBuf.new("Events", Pkt.new(0, 0, 0, 0, 0), 4096)
Drops = BPF::ArrayMap.new("Drops", :u64, 1)

def pktlog(ctx)
  eth = ctx.check(0, 14)
  if eth
    et = eth.be16(12)
    proto = 0
    len = 0
    if et == 0x0800
      ip = ctx.check(14, 20)
      if ip
        proto = ip.u8(9)
        len = ip.be16(2)
      end
    end
    unless Events.output(Pkt.new(et, proto, 0, len, BPF.ktime_ns))
      Drops.atomic_add(0, 1)
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :pktlog

# The user-space side — plain Ruby (compiled by Spinel).
#   pktlog --iface IF [--duration-ms MS]   attach, read and print events for MS milliseconds, then print the count per kind and the drops
#   pktlog --selftest                     without attaching, run BPF_PROG_TEST_RUN on built frames (passed on 7.1.8, and on 6.12 and 6.6 in VMs)
require "spinelbpf"

USAGE = "usage: pktlog --iface IF [--duration-ms MS] | --selftest"
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

# frame builds a 64-byte frame with the EtherType and, for IPv4, the total length and protocol.
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

# event is read_record's Array of member values (in the order declared in BPF.record; an empty Array on timeout).
def event(r, ms)
  v = r.read_record(ms)
  if v.length == 0
    return nil
  end
  Pkt.new(v[0], v[1], v[2], v[3], v[4])
end

# kind is the event's kind (0 IPv4, 1 IPv6, 2 ARP, 3 other).
def kind(e)
  if e.ethertype == 0x0800
    return 0
  elsif e.ethertype == 0x86DD
    return 1
  elsif e.ethertype == 0x0806
    return 2
  end
  3
end

obj = SpinelBPF.load_embedded
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
r = obj.ringbuf(Events)
if selftest
  ok = true
  prev = 0
  [[0x0800, 29, 17], [0x0800, 84, 1], [0x86DD, 0, 0], [0x0806, 0, 0]].each do |c|
    obj.test_run_xdp_packet("pktlog", frame(c[0], c[1], c[2]))
    e = event(r, 100)
    if e.nil?
      puts "selftest: no event for ethertype #{c[0]}"
      ok = false
    elsif e.ethertype != c[0] || e.proto != c[2] || e.len != c[1] || e.ns <= prev
      puts "selftest: got #{e.inspect}, want ethertype=#{c[0]} proto=#{c[2]} len=#{c[1]} ns>#{prev}"
      ok = false
    else
      prev = e.ns
    end
  end
  # 200 runs without reading — a 4096-byte ring holds 170 reservations of 24 bytes (8 + 16; 170 × 24 = 4080 ≤ 4095), the rest are dropped
  n = 0
  while n < 200
    obj.test_run_xdp_packet("pktlog", frame(0x0800, 29, 17))
    n += 1
  end
  got = 0
  while !event(r, 0).nil?
    got += 1
  end
  drops = obj.map_get(Drops, 0)
  puts "fill: sent=200 events=#{got} drops=#{drops}"
  if got != 170 || drops != 30
    puts "selftest: want events=170 drops=30"
    ok = false
  end
  r.close
  obj.close
  if !ok
    puts "selftest FAILED"
    exit 1
  end
  puts "selftest ok"
else
  link = obj.attach_xdp("pktlog", iface)
  puts "attached pktlog to #{iface}"
  $stdout.flush
  t0 = Time.now
  counts = [0, 0, 0, 0] # IPv4, IPv6, ARP, other
  events = 0
  while (Time.now - t0) * 1000 < duration_ms
    e = event(r, 100)
    if !e.nil?
      events += 1
      counts[kind(e)] += 1
      puts "event ethertype=#{e.ethertype} proto=#{e.proto} len=#{e.len}"
      $stdout.flush
    end
  end
  link.detach
  e = event(r, 0)
  while !e.nil? # events left after detach
    events += 1
    counts[kind(e)] += 1
    e = event(r, 0)
  end
  puts "kinds=#{counts.join(",")} events=#{events} drops=#{obj.map_get(Drops, 0)}"
  r.close
  obj.close
end
