require "bpf"

# wake = ctx.arg(2) in a select_cpu callback; accepted (rule A, a u64 local)
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
def n_select(ctx)
  wake = ctx.arg(2)
  cpu = ctx.arg(1)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    c, idle = BPF::Scx.select_cpu_dfl(p, ctx.arg(1), wake)
    cpu = c
  end
  cpu
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", select_cpu: :n_select
