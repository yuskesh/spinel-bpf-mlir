require "bpf"

# moved = BPF::Scx.dsq_move_to_local(0) and `if moved` (the Bool used)
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
def n_dispatch(ctx)
  moved = BPF::Scx.dsq_move_to_local(0)
  if moved
    Stats.atomic_add(0, 1)
  end
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbpos", dispatch: :n_dispatch
