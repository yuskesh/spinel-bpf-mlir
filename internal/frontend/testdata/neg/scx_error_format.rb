require "bpf"

# BPF::Scx.error(f) with f a local
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
def n_init(ctx)
  f = 1
  BPF::Scx.error(f)
  0
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", init: :n_init
# want: SB002 12:3
