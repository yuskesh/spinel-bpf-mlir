require "bpf"

Task = Struct.new(:pid, :tgid, :comm)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, comm: [:u8, 16])
TaskT = BPF::KernelType.new(Task.new(0, 0, Array.new(16, 0)))

Out = BPF::ArrayMap.new("Out", :u64, 4)

def on_x(ctx)
  t = ctx.kptr(0, TaskT)
  Out.update(0, t.load.pid & 0xFFFFFFFF)
end
BPF.fentry :on_x, "wake_up_new_task", args: {0 => [:or_null, TaskT]}
# want: SB033 10:7
