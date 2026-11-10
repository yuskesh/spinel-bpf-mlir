require "bpf"



Task = Struct.new(:pid, :tgid)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32)
TaskT = BPF::KernelType.new(Task.new(0, 0))
FTest = Struct.new(:a)
BPF.kernel_type(FTest, "bpf_fentry_test_t", a: [:kptr, FTest])
FTestT = BPF::KernelType.new(FTest.new(0))

Cfg = BPF::ArrayMap.new("Cfg", :u32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 6)

def on_wake(ctx)
  mine = 0
  c = Cfg.lookup(0)
  if c
    if BPF.pid_tgid >> 32 == c.load
      mine = 1
    end
  end
  p = ctx.kptr_or_null(0, TaskT)
  if p
    if mine == 1
      Out.atomic_add(0, 1)
      Out.update(1, p.load.pid & 0xFFFFFFFF)
    end
  else
    if mine == 1
      Out.atomic_add(2, 1)
    end
  end
end
BPF.fentry :on_wake, "wake_up_new_task", args: {0 => [:or_null, TaskT]}

def on_t8(ctx)
  mine = 0
  c = Cfg.lookup(0)
  if c
    if BPF.pid_tgid >> 32 == c.load
      mine = 1
    end
  end
  t = ctx.kptr_or_null(0, FTestT)
  if t
    if mine == 1
      Out.atomic_add(3, 1)
    end
    a = t.ptr(:a, FTestT)
    if a
      if mine == 1
        Out.atomic_add(4, 1)
      end
    else
      if mine == 1
        Out.atomic_add(5, 1)
      end
    end
  end
end
BPF.fentry :on_t8, "bpf_fentry_test8", args: {0 => [:or_null, FTestT]}
