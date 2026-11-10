require "bpf"

# The eBPF side — counts per Ethernet EtherType, per IPv4 protocol, and of UDP packets to dst port 9999.
# Every read goes through a checked window (`w = ctx.check(off, len)` followed by `if w`); a short frame is counted in the out-of-range branch.
Ether = BPF::ArrayMap.new("Ether", :u64, 8)   # 0 IPv4, 1 IPv6, 2 ARP, 3 VLAN, 4 other, 5 short frame, 6 IPv4 header too short, 7 IHL < 5
Proto = BPF::ArrayMap.new("Proto", :u64, 256) # one slot per IPv4 protocol
Udp = BPF::ArrayMap.new("Udp", :u64, 2)       # 0 count of dst port 9999, 1 last dst port

def count_ether(ctx)
  eth = ctx.check(0, 14)
  if eth
    et = eth.be16(12)
    if et == 0x0800
      Ether.atomic_add(0, 1)
      ip = ctx.check(14, 20)
      if ip
        ihl = ip.u8(0) & 0x0F
        if ihl < 5
          Ether.atomic_add(7, 1) # malformed header: the verifier would pass it, so the program's own branch skips reading it
        else
          proto = ip.u8(9)
          Proto.atomic_add(proto, 1)
          if proto == 17
            l4 = ctx.check(14 + ihl * 4, 4) # variable offset (a non-root loader needs CAP_PERFMON)
            if l4
              port = l4.be16(2)
              Udp.update(1, port)
              if port == 9999
                Udp.atomic_add(0, 1)
              end
            end
          end
        end
      else
        Ether.atomic_add(6, 1)
      end
    elsif et == 0x86DD
      Ether.atomic_add(1, 1)
    elsif et == 0x0806
      Ether.atomic_add(2, 1)
    elsif et == 0x8100
      Ether.atomic_add(3, 1)
    else
      Ether.atomic_add(4, 1)
    end
  else
    Ether.atomic_add(5, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :count_ether

# The user-space side — plain Ruby (compiled by Spinel).
#   ethertype --iface IF [--duration-ms MS]   attach, wait MS milliseconds, print the counts
#   ethertype --selftest                     without attaching, run BPF_PROG_TEST_RUN on built frames (passed on 7.1.8, and on 6.12 and 6.6 in VMs)
require "spinelbpf"

USAGE = "usage: ethertype --iface IF [--duration-ms MS] | --selftest"
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

# frame builds an all-zero frame of length n with the EtherType, the IPv4 header fields (vihl, protocol) and the L4 dst port (zero values are not written).
def frame(n, et, vihl, proto, port)
  f = Array.new(n, 0)
  f[12] = et >> 8
  f[13] = et & 0xFF
  if vihl > 0 && n > 23
    f[14] = vihl
    f[23] = proto
    l4 = 14 + (vihl & 0x0F) * 4
    if port > 0 && n >= l4 + 4
      f[l4 + 2] = port >> 8
      f[l4 + 3] = port & 0xFF
    end
  end
  f
end

def show(obj)
  e = []
  k = 0
  while k < 8
    e.push(obj.map_get(Ether, k))
    k += 1
  end
  puts "ether=#{e.join(",")} proto17=#{obj.map_get(Proto, 17)} proto6=#{obj.map_get(Proto, 6)} proto1=#{obj.map_get(Proto, 1)} udp9999=#{obj.map_get(Udp, 0)} last_port=#{obj.map_get(Udp, 1)}"
  e
end

obj = SpinelBPF.load_embedded # load after checking the requirements against the kernel
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
if selftest
  frames = [
    frame(64, 0x0800, 0x45, 17, 9999), # IPv4 UDP 9999
    frame(64, 0x0800, 0x45, 17, 53),   # IPv4 UDP 53
    frame(64, 0x0800, 0x46, 17, 9999), # IPv4 (IHL 6) UDP 9999
    frame(64, 0x0800, 0x45, 6, 80),    # IPv4 TCP
    frame(64, 0x0800, 0x45, 1, 0),     # IPv4 ICMP
    frame(64, 0x0800, 0x44, 17, 9999), # IPv4 IHL 4 (malformed header)
    frame(33, 0x0800, 0, 0, 0),        # IPv4 header too short (outside check(14, 20))
    frame(34, 0x0800, 0x45, 17, 9999), # IPv4 UDP — the L4 window (34..38) is outside the frame
    frame(64, 0x86DD, 0, 0, 0),
    frame(60, 0x0806, 0, 0, 0),
    frame(64, 0x8100, 0, 0, 0),
    frame(64, 0x88CC, 0, 0, 0)
  ]
  frames.each do |f|
    ret = obj.test_run_xdp_packet("count_ether", f)
    if ret != BPF::XDP_PASS
      raise "selftest: ret=#{ret}"
    end
  end
  e = show(obj)
  want = [8, 1, 1, 1, 1, 0, 1, 1]
  ok = e == want && obj.map_get(Proto, 17) == 4 && obj.map_get(Proto, 6) == 1 && obj.map_get(Proto, 1) == 1 &&
    obj.map_get(Udp, 0) == 2 && obj.map_get(Udp, 1) == 9999
  obj.close
  if !ok
    puts "selftest FAILED (want ether=#{want.join(",")} proto17=4 proto6=1 proto1=1 udp9999=2 last_port=9999)"
    exit 1
  end
  puts "selftest ok"
else
  link = obj.attach_xdp("count_ether", iface)
  puts "attached count_ether to #{iface}"
  $stdout.flush
  sleep(duration_ms / 1000.0)
  show(obj)
  link.detach
  obj.close
end
