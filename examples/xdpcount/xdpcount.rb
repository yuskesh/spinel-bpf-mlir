require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def count_pkts(ctx)
  Counts.atomic_add(0, 1)
  p = Counts.lookup(0)
  if p
    Counts.update(1, p.load)
  end
  BPF::XDP_PASS
end
BPF.xdp :count_pkts




require "spinelbpf"

USAGE = "usage: xdpcount --iface IF [--duration-ms MS] | --selftest N"
iface = ""
duration_ms = 0
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

obj = SpinelBPF.load_embedded
unmet = obj.unmet
puts "unmet (not blocking — undetermined requirements, loaded anyway): #{unmet.length} (requirements policy #{SpinelBPF.policy_version})"
unmet.each { |u| puts "  unmet: #{u}" }
if selftest > 0
  ret = obj.test_run_xdp("count_pkts", selftest)
  c0 = obj.map_get(Counts, 0)
  c1 = obj.map_get(Counts, 1)
  obj.close
  puts "selftest: ret=#{ret} counts[0]=#{c0} counts[1]=#{c1}"
  if ret != BPF::XDP_PASS || c0 != selftest || c1 != selftest
    puts "selftest FAILED (want ret=#{BPF::XDP_PASS} counts[0]=counts[1]=#{selftest})"
    exit 1
  end
  puts "selftest ok"
else
  link = obj.attach_xdp("count_pkts", iface)
  puts "attached count_pkts to #{iface}"
  $stdout.flush
  sleep(duration_ms / 1000.0)
  puts "counts[0]=#{obj.map_get(Counts, 0)} counts[1]=#{obj.map_get(Counts, 1)}"
  link.detach
  obj.close
end
