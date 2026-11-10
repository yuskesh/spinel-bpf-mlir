require "bpf"

Task = Struct.new(:pid, :tgid, :comm)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, comm: [:u8, 16])
TaskT = BPF::KernelType.new(Task.new(0, 0, Array.new(16, 0)))
Ev = Struct.new(:comm, :pid)
BPF.record(Ev, comm: [:u8, 16], pid: :u32)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(16, 0), 0), 4096)
Recs = BPF::RecordMap.new("Recs", Ev.new(Array.new(16, 0), 0), 2)

def on_fork(ctx)
  child = ctx.kptr(1, TaskT)
  e = Ev.new(child.copy(:comm), 0)
end
BPF.tp_btf :on_fork, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}
# want: SB024 13:7
