require "bpf"

SchedExtEntity = Struct.new(:dsq_vtime, :slice, :weight)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64, slice: :u64, weight: :u32)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0, 0, 0)))

def n_stopping(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    d = p.load.scx.weight
    BPF::Scx.task_set_dsq_vtime(p, BPF.u64_div(p.load.scx.dsq_vtime, d))
  end
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", stopping: :n_stopping
# want: SB014 13:70
