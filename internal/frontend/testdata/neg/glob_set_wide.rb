require "bpf"

# G.set(VtimeNow.value) on a :u32 Global
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
G = BPF::Global.new("G", :u32)
VtimeNow = BPF::Global.new("VtimeNow", :u64)

def n_enable(ctx)
  G.set(VtimeNow.value)
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", enable: :n_enable
# want: SB014 14:9
