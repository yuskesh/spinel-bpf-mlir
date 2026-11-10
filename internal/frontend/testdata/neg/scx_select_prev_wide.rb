require "bpf"

# select_cpu_dfl(p, ctx.arg(2), ctx.arg(2)) (a Wide value at the i32 operand)
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
def n_select(ctx)
  cpu = ctx.arg(1)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    c, idle = BPF::Scx.select_cpu_dfl(p, ctx.arg(2), ctx.arg(2))
    cpu = c
  end
  cpu
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", select_cpu: :n_select
# want: SB014 14:42
