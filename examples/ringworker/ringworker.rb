require "bpf"

# The eBPF side — picks a kind from the frame's EtherType (0 IPv4, 1 IPv6, 2 ARP, 3 other), counts per kind, and puts an event (kind and EtherType) on a ring buffer.
# When the ring is full and the reservation fails, counts Drops[0] (the result of output is never discarded — diagnostic SB025).
Ev = Struct.new(:kind, :ethertype)
BPF.record(Ev, kind: :u32, ethertype: :u32)

Events = BPF::RingBuf.new("Events", Ev.new(0, 0), 4096)
Counts = BPF::ArrayMap.new("Counts", :u64, 4)
Drops = BPF::ArrayMap.new("Drops", :u64, 1)
Ack = BPF::ArrayMap.new("Ack", :u64, 1) # the worker's "done counting" mark (events read + 1) — a signal between two user-space Threads (the eBPF side only touches it, adding 0)

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

# The user-space side — a model of how to use Threads:
#   - only the main Thread loads
#   - only the Thread that opened a ring buffer reader (the worker) reads from it and closes it
#   - the object is passed as an argument, `Thread.new(obj, …) do |o, …|` (a Spinel block cannot capture a non-integer local variable)
#   - the library splits a long read_record into 100 ms slices (so GC in other Threads is not stalled)
#   - closing the object while another Thread is inside a call raises SpinelBPF::State — join the worker, then close again
#
#   ringworker --selftest N                 without attaching, send N frames with BPF_PROG_TEST_RUN and compare the worker's counts with the map's
#   ringworker --iface IF [--duration-ms MS] attach; the worker counts events for MS milliseconds and main prints the map's counts
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

# frame builds a 64-byte frame with the EtherType.
def frame(et)
  f = Array.new(64, 0)
  f[12] = et >> 8
  f[13] = et & 0xFF
  f
end

# read_kinds reads want events (0: until the timeout) from the reader this Thread owns, counts them per kind in per, and returns how many it read.
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

# drain counts late events in per[4], then closes the reader. A State error in the drain or the close (main closed the object first) is taken as the end.
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

# The worker Thread's body — the worker opens the reader, so it owns it. Counts are [ipv4, ipv6, arp, other, late]. Avoid Enumerable method names (count etc.):
# Spinel then splices its builtins into the source and the line numbers shift. Values reach the Thread as 2 arguments (an object and an Integer) — passing a Queue as a
# Thread argument broke Spinel's type inference (it was treated as a frozen Array), so the "done" mark is signalled through the map (Ack)
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
# wait on the map's Ack until the worker has finished counting (a map can be read and written from several Threads)
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
# the worker is still reading in drain — close should be refused with State; join and close again
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
