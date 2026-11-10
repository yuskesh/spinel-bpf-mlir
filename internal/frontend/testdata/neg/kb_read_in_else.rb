require "bpf"

Mm = Struct.new(:total_vm)
BPF.kernel_type(Mm, "mm_struct", total_vm: :u64)
MmT = BPF::KernelType.new(Mm.new(0))
Task = Struct.new(:pid, :tgid, :real_parent)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, real_parent: [:kptr, Task])
TaskT = BPF::KernelType.new(Task.new(0, 0, 0))
Out = BPF::ArrayMap.new("Out", :u64, 4)

def on_x(ctx)
  q = ctx.kptr_or_null(1, TaskT)
  if q
    Out.update(0, 1)
  else
    Out.update(1, q.load.pid & 0xFFFFFFFF)
  end
end
BPF.tp_btf :on_x, "sched_pi_setprio", args: {0 => TaskT, 1 => [:or_null, TaskT]}
# want: SB005 16:19
