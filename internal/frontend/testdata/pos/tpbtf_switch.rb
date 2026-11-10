require "bpf"



Task = Struct.new(:pid)
BPF.kernel_type(Task, "task_struct", pid: :i32)
TaskT = BPF::KernelType.new(Task.new(0))

Seen = BPF::ArrayMap.new("Seen", :u64, 3)

def on_switch(ctx)
  nxt = ctx.kptr(2, TaskT)
  Seen.atomic_add(0, ctx.arg(0))
  Seen.update(1, ctx.arg(3) & 0xFFFFFFFF)
  Seen.update(2, nxt.load.pid & 0xFFFFFFFF)
end
BPF.tp_btf :on_switch, "sched_switch", args: {0 => :u8, 2 => TaskT, 3 => :u32}
