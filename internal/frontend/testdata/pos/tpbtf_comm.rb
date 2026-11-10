require "bpf"



Task = Struct.new(:pid, :tgid, :real_parent, :comm)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, real_parent: [:kptr, Task], comm: [:u8, 16])
TaskT = BPF::KernelType.new(Task.new(0, 0, 0, Array.new(16, 0)))
Ev = Struct.new(:comm, :pid)
BPF.record(Ev, comm: [:u8, 16], pid: :u32)

Cfg = BPF::ArrayMap.new("Cfg", :u32, 1)
Recs = BPF::RecordMap.new("Recs", Ev.new(Array.new(16, 0), 0), 2)

def on_fork(ctx)
  parent = ctx.kptr(0, TaskT)
  child = ctx.kptr(1, TaskT)
  c = Cfg.lookup(0)
  if c
    if parent.load.tgid == c.load
      r = Recs.lookup(0)
      if r
        r.load.comm = child.copy(:comm)
        r.load.pid = child.load.pid & 0xFFFFFFFF
      end
      rp = child.ptr(:real_parent, TaskT)
      if rp
        q = Recs.lookup(1)
        if q
          q.load.comm = rp.copy(:comm)
        end
      end
    end
  end
end
BPF.tp_btf :on_fork, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}
