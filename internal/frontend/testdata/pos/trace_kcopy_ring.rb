require "bpf"



Task = Struct.new(:pid, :tgid, :comm)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, comm: [:u8, 16])
TaskT = BPF::KernelType.new(Task.new(0, 0, Array.new(16, 0)))
Ev = Struct.new(:comm, :pid)
BPF.record(Ev, comm: [:u8, 16], pid: :u32)

Cfg = BPF::ArrayMap.new("Cfg", :u32, 1)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(16, 0), 0), 4096)

def on_fork(ctx)
  parent = ctx.kptr(0, TaskT)
  child = ctx.kptr(1, TaskT)
  c = Cfg.lookup(0)
  if c
    if parent.load.tgid == c.load
      _ = Events.output(Ev.new(child.copy(:comm), child.load.pid & 0xFFFF_FFFF))
    end
  end
end
BPF.tp_btf :on_fork, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}
