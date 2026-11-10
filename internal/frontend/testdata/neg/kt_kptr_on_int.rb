require "bpf"

Task = Struct.new(:pid, :tgid, :real_parent, :comm)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, real_parent: [:kptr, Task], comm: [:u8, 16])
TaskT = BPF::KernelType.new(Task.new(0, 0, 0, Array.new(16, 0)))
Out = BPF::ArrayMap.new("Out", :u64, 4)

def on_sw(ctx)
  t = ctx.kptr(3, TaskT)
  Out.update(0, t.load.pid & 0xFF)
end
BPF.tp_btf :on_sw, "sched_switch", args: {2 => TaskT, 3 => :u32}
# want: SB033 9:7
