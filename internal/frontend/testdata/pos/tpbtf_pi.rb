require "bpf"



Task = Struct.new(:pid, :tgid)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32)
TaskT = BPF::KernelType.new(Task.new(0, 0))

Cfg = BPF::ArrayMap.new("Cfg", :u32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 3)

def on_pi(ctx)
  tsk = ctx.kptr(0, TaskT)
  mine = 0
  c = Cfg.lookup(0)
  if c
    if tsk.load.tgid == c.load
      mine = 1
    end
  end
  pi = ctx.kptr_or_null(1, TaskT)
  if pi
    if mine == 1
      Out.atomic_add(0, 1)
      Out.update(2, pi.load.pid & 0xFFFFFFFF)
    end
  else
    if mine == 1
      Out.atomic_add(1, 1)
    end
  end
end
BPF.tp_btf :on_pi, "sched_pi_setprio", args: {0 => TaskT, 1 => [:or_null, TaskT]}
