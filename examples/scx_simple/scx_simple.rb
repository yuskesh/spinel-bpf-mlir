require "bpf"

# scx_simple (7.3.1 tools/sched_ext/scx_simple.bpf.c) with its vtime arithmetic, through the u64 intrinsics.
SchedExtEntity = Struct.new(:dsq_vtime, :slice, :weight)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64, slice: :u64, weight: :u32)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0, 0, 0)))

Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
FifoSched = BPF::OptionalConfig.new("FifoSched", :u8)
VtimeNow = BPF::Global.new("VtimeNow", :u64)
Uei = BPF::ExitInfo.new("Uei")

def simple_select_cpu(ctx)
  prev = ctx.arg(1)
  cpu = prev
  p = ctx.kptr_or_null(0, TaskT)
  if p
    c, idle = BPF::Scx.select_cpu_dfl(p, prev, ctx.arg(2))
    cpu = c
    if idle
      Stats.atomic_add(0, 1)
      BPF::Scx.dsq_insert(p, BPF::Scx::DSQ_LOCAL, BPF::Scx::SLICE_DFL, 0)
    end
  end
  cpu
end

def simple_enqueue(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    Stats.atomic_add(1, 1)
    if FifoSched.value != 0
      BPF::Scx.dsq_insert(p, 0, BPF::Scx::SLICE_DFL, ctx.arg(1))
    else
      vt = p.load.scx.dsq_vtime
      floor = BPF.u64_sub(VtimeNow.value, BPF::Scx::SLICE_DFL)
      if BPF.time_before(vt, floor)
        vt = floor
      end
      BPF::Scx.dsq_insert_vtime(p, 0, BPF::Scx::SLICE_DFL, vt, ctx.arg(1))
    end
  end
end

def simple_dispatch(ctx)
  BPF::Scx.dsq_move_to_local(0)
end

def simple_running(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    if FifoSched.value == 0
      if BPF.time_before(VtimeNow.value, p.load.scx.dsq_vtime)
        VtimeNow.set(p.load.scx.dsq_vtime)
      end
    end
  end
end

def simple_stopping(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    if FifoSched.value == 0
      used = BPF.u64_sub(BPF::Scx::SLICE_DFL, p.load.scx.slice)
      scaled = BPF.u64_mul(used, 100)
      w = p.load.scx.weight
      d = 1
      if w > 0
        d = w
      end
      delta = BPF.u64_div(scaled, d)
      BPF::Scx.task_set_dsq_vtime(p, BPF.u64_add(p.load.scx.dsq_vtime, delta))
    end
  end
end

def simple_enable(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    BPF::Scx.task_set_dsq_vtime(p, VtimeNow.value)
  end
end

def simple_init(ctx)
  r = BPF::Scx.create_dsq(0, -1)
  if r != 0
    BPF::Scx.error("failed to create DSQ %d (%d)", 0, r)
  end
  r
end

def simple_exit(ctx)
  BPF::Scx.exit_info(ctx, Uei)
end

BPF.struct_ops :SimpleOps, "sched_ext_ops", name: "rbsimple", timeout_ms: 5000, flags: BPF::Scx::OPS_SWITCH_PARTIAL,
  select_cpu: :simple_select_cpu, enqueue: :simple_enqueue, dispatch: :simple_dispatch, running: :simple_running,
  stopping: :simple_stopping, enable: :simple_enable, init: :simple_init, exit: :simple_exit
