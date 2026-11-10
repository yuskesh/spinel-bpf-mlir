require "bpf"





Filter = BPF::OptionalConfig.new("Filter", :u32)
Polls = BPF::HashMap.new("Polls", :u32, :u64, 1024)
Nfds = BPF::HashMap.new("Nfds", :u32, :u64, 1024)
Tests = BPF::ArrayMap.new("Tests", :u64, 1)

def on_poll(ctx)
  tgid = BPF.pid_tgid >> 32
  want = Filter.value
  if want == 0 || want == tgid
    _ = Polls.add_or_init(tgid, 1)
    _ = Nfds.add_or_init(tgid, ctx.arg(2))
  end
end
BPF.kprobe :on_poll, "do_sys_poll", params: {2 => :u32}

def on_test(ctx)
  tgid = BPF.pid_tgid >> 32
  if Filter.value == tgid
    Tests.atomic_add(0, 1)
  end
end
BPF.fentry :on_test, "bpf_fentry_test1"




require "spinelbpf"

module Sys
  ffi_source <<~C
    #include <poll.h>
    #include <unistd.h>
    long sys_poll_empty(long n) { return (long)poll(NULL, (nfds_t)n, 0); }
    long sys_getpid(void) { return (long)getpid(); }
  C
  ffi_func :sys_poll_empty, [:long], :long
  ffi_func :sys_getpid, [], :long
end

USAGE = "usage: pollwatch --selftest | [--duration-ms MS]"
duration_ms = 3000
selftest = false
i = 0
while i < ARGV.length
  a = ARGV[i]
  if a == "--selftest"
    selftest = true
    i += 1
  elsif a == "--duration-ms" && i + 1 < ARGV.length
    duration_ms = ARGV[i + 1].to_i
    i += 2
  else
    raise "#{USAGE} (unknown argument #{a})"
  end
end

me = Sys.sys_getpid
cfg = SpinelBPF::ConfigSet.new
if selftest
  cfg.set_optional(Filter, me)
end
obj = SpinelBPF.load_embedded_config(cfg)
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version}) filter=#{obj.optional_get(Filter)}"
lp = obj.attach_kprobe("on_poll")
lt = obj.attach_fentry("on_test")
if selftest
  n = 0
  while n < 4
    Sys.sys_poll_empty(3)
    n += 1
  end
  Sys.sys_poll_empty(5)
  Sys.sys_poll_empty(5)
  tid = obj.test_run_tracing("on_test", 10)
  lp.detach
  lt.detach
  polls = obj.hash_get(Polls, me)
  nfds = obj.hash_get(Nfds, me)
  tests = obj.map_get(Tests, 0)
  puts "tgid=#{me} polls=#{polls} nfds=#{nfds} tests=#{tests} (test run thread #{tid != me ? "differs" : "same"})"
  obj.close
  if polls != 6 || nfds != 22 || tests != 10
    puts "selftest FAILED (want polls=6 nfds=22 tests=10)"
    exit 1
  end
  puts "selftest ok"
else
  sleep(duration_ms / 1000.0)
  lp.detach
  lt.detach
  ks = obj.hash_keys(Polls)
  rows = []
  ks.each { |k| rows << [obj.hash_get(Polls, k), k] }
  rows.sort! { |x, y| y[0] <=> x[0] }
  puts "poll(2) calls in #{duration_ms} ms (#{ks.length} processes):"
  j = 0
  while j < rows.length && j < 5
    puts "  tgid #{rows[j][1]}: #{rows[j][0]} calls, nfds #{obj.hash_get(Nfds, rows[j][1])}"
    j += 1
  end
  obj.close
end
