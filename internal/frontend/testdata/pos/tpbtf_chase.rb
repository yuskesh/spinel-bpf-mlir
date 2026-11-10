require "bpf"



Mm = Struct.new(:total_vm)
BPF.kernel_type(Mm, "mm_struct", total_vm: :u64)
MmT = BPF::KernelType.new(Mm.new(0))
Completion = Struct.new(:done)
BPF.kernel_type(Completion, "completion", done: :u32)
CompletionT = BPF::KernelType.new(Completion.new(0))
Task = Struct.new(:pid, :tgid, :real_parent, :mm, :vfork_done)
BPF.kernel_type(Task, "task_struct", pid: :i32, tgid: :i32, real_parent: [:kptr, Task], mm: [:kptr, Mm], vfork_done: [:kptr, Completion])
TaskT = BPF::KernelType.new(Task.new(0, 0, 0, 0, 0))

Cfg = BPF::ArrayMap.new("Cfg", :u32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 5)

def on_fork(ctx)
  parent = ctx.kptr(0, TaskT)
  child = ctx.kptr(1, TaskT)
  c = Cfg.lookup(0)
  if c
    if parent.load.tgid == c.load
      Out.atomic_add(0, 1)
      rp = child.ptr(:real_parent, TaskT)
      if rp
        Out.update(1, rp.load.tgid & 0xFFFFFFFF)
        pm = rp.ptr(:mm, MmT)
        if pm
          Out.update(4, pm.load.total_vm)
        end
      end
      vd = child.ptr(:vfork_done, CompletionT)
      if vd
        Out.update(2, vd.load.done & 0xFFFFFFFF)
      else
        Out.atomic_add(2, 1)
      end
      mm = child.ptr(:mm, MmT)
      if mm
        Out.atomic_add(3, 1)
      end
    end
  end
end
BPF.tp_btf :on_fork, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}
