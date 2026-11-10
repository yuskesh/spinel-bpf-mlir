require "bpf"




Greeting = Struct.new(:pid_tgid, :count, :_pad0, :status, :name)
BPF.record(Greeting, pid_tgid: :u64, count: :u32, _pad0: :u32, status: :i64, name: [:u8, 32])
Greetings = BPF::RingBuf.new("Greetings", Greeting.new(0, 0, 0, 0, Array.new(32, 0)), 65536)
Stats = BPF::ArrayMap.new("Stats", :u64, 2)

def on_greet(ctx)
  r = Greetings.output_str(Greeting.new(BPF.pid_tgid, ctx.arg(2), 0, 0, Array.new(32, 0)), :name, ctx.str_arg(1), :status)
  if r
    Stats.atomic_add(0, 1)
  else
    Stats.atomic_add(1, 1)
  end
end
BPF.uprobe :on_greet, "target/greeter", "greet", params: {1 => :user_str, 2 => :u32}






require "spinelbpf"


module GW
  ffi_source <<~C
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/types.h>
    static int gw_in = -1;
    static FILE *gw_rf = NULL;
    static long gw_child = 0;
    long gw_start(const char *path) {
      int a[2], b[2];
      if (pipe(a) != 0 || pipe(b) != 0) return -1;
      pid_t p = fork();
      if (p < 0) return -1;
      if (p == 0) {
        dup2(a[0], 0); dup2(b[1], 1); close(a[1]); close(b[0]);
        execl(path, path, (char *)0);
        _exit(127);
      }
      close(a[0]); close(b[1]);
      gw_in = a[1];
      gw_rf = fdopen(b[0], "r");
      gw_child = (long)p;
      char line[256];
      if (gw_rf == NULL || fgets(line, sizeof line, gw_rf) == NULL || strncmp(line, "ready ", 6) != 0) return -1;
      return gw_child;
    }
    long gw_send(const char *s) {
      size_t n = strlen(s);
      char nl = 10;
      if (write(gw_in, s, n) != (ssize_t)n || write(gw_in, &nl, 1) != 1) return -1;
      char line[1100];
      if (fgets(line, sizeof line, gw_rf) == NULL) return -1;
      return (long)strlen(line);
    }
  C
  ffi_func :gw_start, [:str], :long
  ffi_func :gw_send, [:str], :long
end

USAGE = "usage: greetwatch --target PATH --pid PID [--duration-ms MS] | --selftest --target PATH"
target = ""
pid = -1
duration_ms = 0
selftest = false
i = 0
while i < ARGV.length
  a = ARGV[i]
  if a == "--target" && i + 1 < ARGV.length
    target = ARGV[i + 1]
    i += 2
  elsif a == "--pid" && i + 1 < ARGV.length
    pid = ARGV[i + 1].to_i
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
if target == "" || (!selftest && pid < 0)
  raise USAGE
end


def text(v)
  if v[3] < 0
    return "(read failed)"
  end
  if v[4] == 0
    return "(empty)"
  end
  s = ""
  i = 4
  while i < 36 && v[i] != 0
    s += v[i].chr
    i += 1
  end
  s
end

def show(v)
  puts "greeting pid=#{v[0] >> 32} count=#{v[1]} status=#{v[3]} name=#{text(v)}"
end

tg = SpinelBPF::UprobeTargets.new
tg.add("on_greet", target)
obj = SpinelBPF.load_embedded_targets(SpinelBPF::ConfigSet.new, tg)
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
rd = obj.ringbuf(Greetings)
if selftest
  child = GW.gw_start(target)
  if child < 0
    raise "greetwatch: could not start #{target}"
  end
  link = obj.attach_uprobe("on_greet", child)
  names = ["hello", "", "a" * 40, "(null)"]
  names.each do |n|
    if GW.gw_send(n) < 0
      raise "greetwatch: the target did not answer"
    end
  end
  ok = true
  k = 0
  while k < 4
    v = rd.read_record(1000)
    if v.length == 0
      puts "selftest: event #{k} did not arrive"
      ok = false
      break
    end
    show(v)
    want = ["hello", "(empty)", "a" * 31, "(read failed)"][k]
    if text(v) != want || v[1] != k + 1 || (v[0] >> 32) != child
      puts "selftest: event #{k} got name=#{text(v)} count=#{v[1]} pid=#{v[0] >> 32}, want name=#{want} count=#{k + 1} pid=#{child}"
      ok = false
    end
    if k == 3
      j = 4
      while j < 36
        if v[j] != 0
          ok = false
        end
        j += 1
      end
    end
    k += 1
  end
  if obj.map_get(Stats, 1) != 0
    puts "selftest: #{obj.map_get(Stats, 1)} reservations failed"
    ok = false
  end
  link.detach
  rd.close
  obj.close
  if !ok
    puts "selftest FAILED"
    exit 1
  end
  puts "selftest ok"
else
  link = obj.attach_uprobe("on_greet", pid)
  puts "attached on_greet to pid #{pid}"
  $stdout.flush
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) / 1_000_000 + duration_ms
  while Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) / 1_000_000 < deadline
    v = rd.read_record(100)
    if v.length > 0
      show(v)
      $stdout.flush
    end
  end
  link.detach
  puts "events=#{obj.map_get(Stats, 0)} ring_full=#{obj.map_get(Stats, 1)}"
  rd.close
  obj.close
end
