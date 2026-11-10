require "bpf"

Task = Struct.new(:pid, :tgid, :real_parent, :comm)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, real_parent: [:kptr, Task], comm: [:u8, 16])
TaskT = BPF::KernelType.new(Task.new(0, 0, 0, Array.new(16, 0)))
Out = BPF::ArrayMap.new("Out", :u64, 4)

def on_fork(ctx)
  t = ctx.kptr(1, TaskT)
  4.times do |i|
    Out.update(i, t.load.pid & 0xFF)
  end
end
BPF.tp_btf :on_fork, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}
# want: SB030 11:19
