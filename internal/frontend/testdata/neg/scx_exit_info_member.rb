require "bpf"

# BPF::Scx.exit_info(ctx, Uei) in enable
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
Uei = BPF::ExitInfo.new("Uei")

def n_enable(ctx)
  BPF::Scx.exit_info(ctx, Uei)
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", enable: :n_enable
# want: SB002 13:3
