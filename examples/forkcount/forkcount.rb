require "bpf"



Task = Struct.new(:pid, :tgid)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32)
TaskT = BPF::KernelType.new(Task.new(0, 0))
Cfg = BPF::ArrayMap.new("Cfg", :u32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 3)

def on_fork(ctx)
  parent = ctx.kptr(0, TaskT)
  child = ctx.kptr(1, TaskT)
  c = Cfg.lookup(0)
  if c
    if parent.load.tgid == c.load
      Out.atomic_add(0, 1)
      Out.update(1, child.load.pid & 0xFFFFFFFF)
      Out.update(2, child.load.tgid & 0xFFFFFFFF)
    end
  end
end
BPF.tp_btf :on_fork, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}




require "spinelbpf"


module FC
  ffi_source <<~C
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    long fc_pid(void) { return (long)getpid(); }
    long fc_fork(void) { pid_t p = fork(); if (p == 0) _exit(0); if (p < 0) return -1; int st; waitpid(p, &st, 0); return (long)p; }
  C
  ffi_func :fc_pid, [], :long
  ffi_func :fc_fork, [], :long
end

USAGE = "usage: forkcount --selftest [N] | --pid PID [--duration-ms MS]"
selftest = false
n = 5
pid = -1
duration_ms = 0
i = 0
while i < ARGV.length
  a = ARGV[i]
  if a == "--selftest"
    selftest = true
    if i + 1 < ARGV.length && ARGV[i + 1].to_i > 0
      n = ARGV[i + 1].to_i
      i += 1
    end
    i += 1
  elsif a == "--pid" && i + 1 < ARGV.length
    pid = ARGV[i + 1].to_i
    i += 2
  elsif a == "--duration-ms" && i + 1 < ARGV.length
    duration_ms = ARGV[i + 1].to_i
    i += 2
  else
    raise "#{USAGE} (unknown argument #{a})"
  end
end
if !selftest && pid < 0
  raise USAGE
end

obj = SpinelBPF.load_embedded
puts "unmet (not blocking): #{obj.unmet.length} (requirements policy #{SpinelBPF.policy_version})"
link = obj.attach_tp_btf("on_fork")
if selftest
  obj.map_put(Cfg, 0, FC.fc_pid)
  last = 0
  k = 0
  while k < n
    last = FC.fc_fork
    k += 1
  end
  got = obj.map_get(Out, 0)
  lp = obj.map_get(Out, 1)
  lt = obj.map_get(Out, 2)
  link.detach
  obj.close
  puts "forks=#{got} last_pid=#{lp} last_tgid=#{lt}"
  if got != n || lp != last || lt != last
    puts "selftest FAILED: want forks=#{n} last_pid=#{last} last_tgid=#{last}"
    exit 1
  end
  puts "selftest ok"
else
  obj.map_put(Cfg, 0, pid)
  puts "attached on_fork (sched_process_fork) — counting the forks of pid #{pid}"
  $stdout.flush
  sleep(duration_ms / 1000.0)
  link.detach
  puts "forks=#{obj.map_get(Out, 0)} last_pid=#{obj.map_get(Out, 1)} last_tgid=#{obj.map_get(Out, 2)}"
  obj.close
end
