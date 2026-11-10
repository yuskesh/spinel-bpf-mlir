require "bpf"

Task = Struct.new(:pid, :tgid, :comm)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, comm: [:u8, 16])
TaskT = BPF::KernelType.new(Task.new(0, 0, Array.new(16, 0)))
Ev = Struct.new(:comm, :pid)
BPF.record(Ev, comm: [:u8, 16], pid: :u32)
Recs = BPF::RecordMap.new("Recs", Ev.new(Array.new(16, 0), 0), 1)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def on_x(ctx)
  t = ctx.kptr(1, TaskT)
  r = Recs.lookup(0)
  if r
    r.load.pid = t.copy(:comm)
  end
end
BPF.tp_btf :on_x, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}
# want: SB033 15:5
