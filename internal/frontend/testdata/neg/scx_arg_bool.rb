require "bpf"

# ctx.arg(1) on stopping (a bool)
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
def n_stopping(ctx)
  x = ctx.arg(1)
  Stats.atomic_add(0, x)
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", stopping: :n_stopping
# want: SB033 11:7
