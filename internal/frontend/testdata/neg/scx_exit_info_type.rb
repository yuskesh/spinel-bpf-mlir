require "bpf"

# a user BPF.kernel_type(…, "scx_exit_info", …) with exit_info used
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
ExitS = Struct.new(:kind)
BPF.kernel_type(ExitS, "scx_exit_info", kind: :i32)
Uei = BPF::ExitInfo.new("Uei")

def n_exit(ctx)
  BPF::Scx.exit_info(ctx, Uei)
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", exit: :n_exit
# want: SB033 11:24
