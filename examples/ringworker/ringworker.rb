require "bpf"



Ev = Struct.new(:kind, :ethertype)
BPF.record(Ev, kind: :u32, ethertype: :u32)

Events = BPF::RingBuf.new("Events", Ev.new(0, 0), 4096)
Counts = BPF::ArrayMap.new("Counts", :u64, 4)
Drops = BPF::ArrayMap.new("Drops", :u64, 1)
Ack = BPF::ArrayMap.new("Ack", :u64, 1)

def ringworker(ctx)
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
    Counts.atomic_add(kind, 1)
    unless Events.output(Ev.new(kind, et))
      Drops.atomic_add(0, 1)
    end
  end
  Ack.atomic_add(0, 0)
  BPF::XDP_PASS
end
BPF.xdp :ringworker










require "spinelbpf"

USAGE = "usage: ringworker --selftest N | --iface IF [--duration-ms MS]"
KINDS = ["ipv4", "ipv6", "arp", "other"]
iface = ""
duration_ms = 3000
selftest = 0
i = 0
while i < ARGV.length
  a = ARGV[i]
  if a == "--iface" && i + 1 < ARGV.length
    iface = ARGV[i + 1]
    i += 2
  elsif a == "--duration-ms" && i + 1 < ARGV.length
    duration_ms = ARGV[i + 1].to_i
    i += 2
  elsif a == "--selftest" && i + 1 < ARGV.length
    selftest = ARGV[i + 1].to_i
    i += 2
  else
    raise "#{USAGE} (unknown argument #{a})"
  end
end
if iface == "" && selftest <= 0
  raise USAGE
end


def frame(et)
  f = Array.new(64, 0)
  f[12] = et >> 8
  f[13] = et & 0xFF
  f
end


def read_kinds(r, want, wait_ms, per)
  got = 0
  more = true
  while more && (want == 0 || got < want)
    v = r.read_record(wait_ms)
    if v.length == 0
      more = false
    else
      per[v[0]] += 1
      got += 1
    end
  end
  got
end


def drain(r, per)
  begin
    while r.read_record(1500).length > 0
      per[4] += 1
    end
    r.close
  rescue SpinelBPF::State
    per[4] += 0
  end
  per
end




obj = SpinelBPF.load_embedded
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
link = nil
if selftest > 0
  t = Thread.new(obj, selftest) do |o, want|
    per = Array.new(5, 0)
    r = o.ringbuf(Events)
    o.map_put(Ack, 0, read_kinds(r, want, 2000, per) + 1)
    drain(r, per)
  end
  ets = [0x0800, 0x86DD, 0x0806, 0x88CC]
  n = 0
  while n < selftest
    obj.test_run_xdp_packet("ringworker", frame(ets[n % 4]))
    n += 1
  end
else
  link = obj.attach_xdp("ringworker", iface)
  puts "attached ringworker to #{iface}"
  t = Thread.new(obj, duration_ms) do |o, ms|
    per = Array.new(5, 0)
    r = o.ringbuf(Events)
    o.map_put(Ack, 0, read_kinds(r, 0, ms, per) + 1)
    drain(r, per)
  end
end

while obj.map_get(Ack, 0) == 0
  sleep 0.01
end
got = obj.map_get(Ack, 0) - 1
counts = []
k = 0
while k < 4
  counts << obj.map_get(Counts, k)
  k += 1
end
drops = obj.map_get(Drops, 0)
puts "kernel counts: #{KINDS[0]}=#{counts[0]} #{KINDS[1]}=#{counts[1]} #{KINDS[2]}=#{counts[2]} #{KINDS[3]}=#{counts[3]} drops=#{drops} (worker read #{got})"
if link
  link.detach
end

path = ""
begin
  obj.close
  path = "close went first (the worker's drain ended with State)"
rescue SpinelBPF::State => e
  path = "close refused while the worker drained (#{e.message}) — joined and closed again"
  t.join
  obj.close
end
per = t.value
puts "worker counts: #{KINDS[0]}=#{per[0]} #{KINDS[1]}=#{per[1]} #{KINDS[2]}=#{per[2]} #{KINDS[3]}=#{per[3]} late=#{per[4]}"
puts path
if selftest > 0
  q = selftest / 4
  ok = drops == 0 && per[4] == 0
  k = 0
  while k < 4
    want = q
    if k < selftest % 4
      want += 1
    end
    if counts[k] != want || per[k] != want
      ok = false
    end
    k += 1
  end
  if !ok
    puts "selftest FAILED"
    exit 1
  end
  puts "selftest ok"
end
