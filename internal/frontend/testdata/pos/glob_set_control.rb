require "bpf"

# `if G.value < 5` around `G.set(5)` (a control dependence — S4)
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
G = BPF::Global.new("G", :u32)

def n_enable(ctx)
  if G.value < 5
    G.set(5)
  end
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbpos", enable: :n_enable
