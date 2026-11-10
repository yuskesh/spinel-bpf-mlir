require "bpf"

# `G.set(x & 0xFF)` on a :u8 Global
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
G = BPF::Global.new("G", :u8)

def n_select(ctx)
  x = ctx.arg(1)
  G.set(x & 0xFF)
  x
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbpos", select_cpu: :n_select
