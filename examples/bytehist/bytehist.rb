require "bpf"

# Example bytehist: an XDP program that counts packets by the upper 4 bits of the first byte after the Ethernet header, in an array member of a per-CPU record.
# The variable index b in [0, 15] (w.u8(0) >> 4 — the frontend proves the range) is a read-modify-write of one element, accepted because the map is per-CPU (no CPU writes another CPU's slot, so no count is lost).
Hist = Struct.new(:counts)
BPF.record(Hist, counts: [:u32, 16])
Hists = BPF::PerCpuRecordMap.new("Hists", Hist.new(Array.new(16, 0)), 1)

def byte_hist(ctx)
  w = ctx.check(14, 1)
  if w
    b = w.u8(0) >> 4
    p = Hists.lookup(0)
    if p
      p.load.counts[b] = (p.load.counts[b] + 1) & 0xFFFF_FFFF
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :byte_hist

# The user-space side — plain Ruby (compiled by Spinel).
#   bytehist --selftest   without attaching, run BPF_PROG_TEST_RUN on built packets and check the sums over CPUs
#   bytehist --dump       just load and print the sums over CPUs
require "spinelbpf"

USAGE = "usage: bytehist --selftest | --dump"
if ARGV.length != 1 || (ARGV[0] != "--selftest" && ARGV[0] != "--dump")
  raise USAGE
end

# sums adds up the per-CPU values (each a flat Array, one entry per element of the array member).
def sums(obj)
  rows = obj.percpu_get_record(Hists, 0)
  s = Array.new(16, 0)
  j = 0
  while j < rows.length
    b = 0
    while b < 16
      s[b] += rows[j][b]
      b += 1
    end
    j += 1
  end
  s
end

# packet puts first (omitted when negative) after a 14-byte all-zero Ethernet header and pads with zeros to length n.
def packet(first, n)
  f = Array.new(14, 0)
  if first >= 0
    f.push(first)
  end
  while f.length < n
    f.push(0)
  end
  f
end

obj = SpinelBPF.load_embedded # load after checking the requirements against the kernel; no attach
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
if ARGV[0] == "--selftest"
  pkts = [packet(0x45, 64), packet(0x45, 64), packet(0x45, 64), packet(0x60, 64), packet(0x60, 64), packet(0xFF, 64), packet(-1, 14)]
  pkts.each do |pk|
    ret = obj.test_run_xdp_packet("byte_hist", pk)
    if ret != BPF::XDP_PASS
      raise "selftest: ret=#{ret}"
    end
  end
  s = sums(obj)
  puts "counts=#{s.join(",")}"
  want = [0, 0, 0, 0, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1]
  obj.close
  if s != want
    puts "selftest FAILED (want counts=#{want.join(",")})"
    exit 1
  end
  puts "selftest ok"
else
  puts "counts=#{sums(obj).join(",")}"
  obj.close
end
