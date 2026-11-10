require "bpf"

# BPF::Scx.dsq_insert(p, …) after the if p … end
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
def n_enqueue(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    Stats.atomic_add(0, 1)
  end
  BPF::Scx.dsq_insert(p, 0, BPF::Scx::SLICE_DFL, 0)
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", enqueue: :n_enqueue
# want: SB005 15:23
