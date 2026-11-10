require "bpf"

# Example tlvwalk: an XDP program that walks up to 8 TLVs (type 1 byte, len 1 byte, value len bytes) after the Ethernet header (14 bytes).
# The body of a bounded loop (8.times — ebpf.loop, fully unrolled) checks a packet window and reads it. The walk stops at type 0 or outside the packet.
Types = BPF::ArrayMap.new("Types", :u64, 8) # TLV count per type & 7
Walks = BPF::ArrayMap.new("Walks", :u64, 2) # [0] total TLVs read, [1] packets cut off at 8 TLVs

def tlv(ctx)
  off = 14
  n = 0
  8.times do |i|
    t = 0
    l = 0
    w = ctx.check(off, 2)
    if w
      t = w.u8(0)
      l = w.u8(1) & 0x3F
    end
    break if t == 0
    Types.atomic_add(t & 7, 1)
    n += 1
    off += 2 + l
  end
  Walks.atomic_add(0, n)
  if n == 8
    Walks.atomic_add(1, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :tlv

# The user-space side — plain Ruby (compiled by Spinel).
#   tlvwalk --selftest   without attaching, run BPF_PROG_TEST_RUN on 4 built packets and check the counts
#   tlvwalk --dump       just load and print the maps
require "spinelbpf"

USAGE = "usage: tlvwalk --selftest | --dump"
if ARGV.length != 1 || (ARGV[0] != "--selftest" && ARGV[0] != "--dump")
  raise USAGE
end

# packet puts tlvs (a list of bytes) after a 14-byte all-zero Ethernet header and pads with zeros to length n.
def packet(tlvs, n)
  f = Array.new(14, 0) + tlvs
  while f.length < n
    f.push(0)
  end
  f
end

def show(obj)
  ts = []
  k = 0
  while k < 8
    ts.push(obj.map_get(Types, k))
    k += 1
  end
  puts "types=#{ts.join(",")} walked=#{obj.map_get(Walks, 0)} capped=#{obj.map_get(Walks, 1)}"
  ts
end

obj = SpinelBPF.load_embedded # load after checking the requirements against the kernel; no attach
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
if ARGV[0] == "--selftest"
  pkts = [
    packet([1, 2, 9, 9, 2, 0, 3, 1, 7, 0], 64),       # 3 TLVs and a terminating 0
    packet([4, 0, 4, 0, 4, 0, 4, 0, 4, 0, 4, 0, 4, 0, 4, 0, 4, 0, 4, 0], 64), # 10 TLVs — cut off at 8
    packet([5, 60, 1, 2, 3], 30),                      # 1 TLV — the next window (76) is outside the packet
    packet([], 14)                                     # Ethernet only — the first window is outside
  ]
  pkts.each do |p|
    ret = obj.test_run_xdp_packet("tlv", p)
    if ret != BPF::XDP_PASS
      raise "selftest: ret=#{ret}"
    end
  end
  ts = show(obj)
  want = [0, 1, 1, 1, 8, 1, 0, 0]
  ok = ts == want && obj.map_get(Walks, 0) == 12 && obj.map_get(Walks, 1) == 1
  obj.close
  if !ok
    puts "selftest FAILED (want types=#{want.join(",")} walked=12 capped=1)"
    exit 1
  end
  puts "selftest ok"
else
  show(obj)
  obj.close
end
