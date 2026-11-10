require "bpf"

# `return 1` as the last statement in a tp_btf program (it was once dropped silently) — the return-free pair
Task = Struct.new(:pid, :tgid)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32)
TaskT = BPF::KernelType.new(Task.new(0, 0))
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  Out.atomic_add(0, 1)
end
BPF.tp_btf :on_x, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}
