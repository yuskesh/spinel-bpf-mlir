require "bpf"





Stats = Struct.new(:packets, :bytes)
BPF.record(Stats, packets: :u64, bytes: :u64)

PerKind = BPF::PerCpuRecordMap.new("PerKind", Stats.new(0, 0), 7)

def protostat(ctx)
  kind = 6
  len = 0
  eth = ctx.check(0, 14)
  if eth
    et = eth.be16(12)
    if et == 0x0800
      kind = 3
      ip = ctx.check(14, 20)
      if ip
        proto = ip.u8(9)
        len = ip.be16(2)
        if proto == 17
          kind = 0
        elsif proto == 6
          kind = 1
        elsif proto == 1
          kind = 2
        end
      end
    elsif et == 0x86DD
      kind = 4
      ip6 = ctx.check(14, 40)
      if ip6
        len = ip6.be16(4) + 40
      end
    elsif et == 0x0806
      kind = 5
    end
  end
  p = PerKind.lookup(kind)
  if p
    p.load.packets += 1
    p.load.bytes += len
  end
  BPF::XDP_PASS
end
BPF.xdp :protostat




require "spinelbpf"

USAGE = "usage: protostat --iface IF [--duration-ms MS] | --selftest"
KINDS = ["ipv4_udp", "ipv4_tcp", "ipv4_icmp", "ipv4_other", "ipv6", "arp", "other"]
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


def frame(n, et, total, proto)
  f = Array.new(n, 0)
  if n >= 14
    f[12] = et >> 8
    f[13] = et & 0xFF
  end
  if et == 0x0800
    f[14] = 0x45
    f[16] = total >> 8
    f[17] = total & 0xFF
    f[23] = proto
  elsif et == 0x86DD
    f[18] = total >> 8
    f[19] = total & 0xFF
  end
  f
end


def kind_sums(obj, k)
  rows = obj.percpu_get_record(PerKind, k)
  packets = 0
  bytes = 0
  nz = 0
  j = 0
  while j < rows.length
    packets += rows[j][0]
    bytes += rows[j][1]
    if rows[j][0] != 0 || rows[j][1] != 0
      nz += 1
    end
    j += 1
  end
  [packets, bytes, nz]
end

def show(obj)
  k = 0
  while k < 7
    s = kind_sums(obj, k)
    puts "kind #{KINDS[k]} packets=#{s[0]} bytes=#{s[1]} slots=#{s[2]}"
    k += 1
  end
end

obj = SpinelBPF.load_embedded
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
puts "possible_cpus=#{SpinelBPF.possible_cpus}"
if selftest
  cases = [[64, 0x0800, 29, 17], [64, 0x0800, 40, 17], [64, 0x0800, 52, 6], [64, 0x0800, 84, 1], [64, 0x0800, 20, 47], [80, 0x86DD, 16, 0], [64, 0x0806, 0, 0], [64, 0x88CC, 0, 0], [14, 0x9000, 0, 0]]
  cases.each do |c|
    obj.test_run_xdp_packet("protostat", frame(c[0], c[1], c[2], c[3]))
  end
  show(obj)
  want = [[2, 69], [1, 52], [1, 84], [1, 20], [1, 56], [1, 0], [2, 0]]
  ok = true
  k = 0
  while k < 7
    s = kind_sums(obj, k)
    if s[0] != want[k][0] || s[1] != want[k][1] || s[2] > want[k][0]
      puts "selftest: kind #{KINDS[k]} got packets=#{s[0]} bytes=#{s[1]} slots=#{s[2]}, want #{want[k][0]} / #{want[k][1]} (slots <= packets)"
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
  link = obj.attach_xdp("protostat", iface)
  puts "attached protostat to #{iface}"
  $stdout.flush
  sleep(duration_ms / 1000.0)
  link.detach
  show(obj)
  obj.close
end
