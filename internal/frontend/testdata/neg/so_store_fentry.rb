require "bpf"

# t.set_field(:pid, 1) on a checked pointer in a fentry program
Task = Struct.new(:pid, :tgid)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32)
TaskT = BPF::KernelType.new(Task.new(0, 0))

def on_wake(ctx)
  t = ctx.kptr_or_null(0, TaskT)
  if t
    t.set_field(:pid, 1)
  end
end
BPF.fentry :on_wake, "wake_up_new_task", args: {0 => [:or_null, TaskT]}
# want: SB033 11:5
