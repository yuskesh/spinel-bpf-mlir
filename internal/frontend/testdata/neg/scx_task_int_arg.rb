require "bpf"

# ctx.kptr_or_null(1, TaskT) on select_cpu (argument 1 is s32)
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
def n_select(ctx)
  p = ctx.kptr_or_null(1, TaskT)
  if p
    Stats.atomic_add(0, 1)
  end
  0
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", select_cpu: :n_select
# want: SB033 11:24
