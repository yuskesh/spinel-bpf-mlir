require "bpf"

# a, b = 1, 2 in a sched_ext_ops callback
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
def n_enable(ctx)
  a, b = 1, 2
  Stats.atomic_add(0, a + b)
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", enable: :n_enable
# want: SB001 11:3
