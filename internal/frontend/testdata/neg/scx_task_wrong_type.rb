require "bpf"

# ctx.kptr_or_null(0, T) with T named tcp_sock
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))
Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
TcpSock = Struct.new(:snd_cwnd)
BPF.kernel_type(TcpSock, "tcp_sock", snd_cwnd: :u32)
TcpT = BPF::KernelType.new(TcpSock.new(0))

def n_enable(ctx)
  p = ctx.kptr_or_null(0, TcpT)
  if p
    Stats.atomic_add(0, 1)
  end
end

BPF.struct_ops :Ops, "sched_ext_ops", name: "rbneg", enable: :n_enable
# want: SB033 15:27
