require "bpf"



Task = Struct.new(:pid, :tgid, :start_time, :migration_disabled, :rcu_tasks_holdout)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, start_time: :u64, migration_disabled: :u16, rcu_tasks_holdout: :u8)
TaskT = BPF::KernelType.new(Task.new(0, 0, 0, 0, 0))

Cfg = BPF::ArrayMap.new("Cfg", :u32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 5)

def on_fork(ctx)
  parent = ctx.kptr(0, TaskT)
  child = ctx.kptr(1, TaskT)
  c = Cfg.lookup(0)
  if c
    if parent.load.tgid == c.load
      Out.update(0, child.load.pid & 0xFFFFFFFF)
      Out.update(1, child.load.tgid & 0xFFFFFFFF)
      Out.update(2, child.load.start_time)
      Out.update(3, child.load.migration_disabled & 0xFFFF)
      Out.update(4, child.load.rcu_tasks_holdout & 0xFF)
    end
  end
end
BPF.tp_btf :on_fork, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}
