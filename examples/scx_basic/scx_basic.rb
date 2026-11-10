require "bpf"

# E200a: the base of scx_simple (7.3.1 tools/sched_ext/scx_simple.bpf.c) with no u64 arithmetic.
SchedExtEntity = Struct.new(:dsq_vtime)
BPF.kernel_type(SchedExtEntity, "sched_ext_entity", dsq_vtime: :u64)
Task = Struct.new(:scx)
BPF.kernel_type(Task, "task_struct", scx: [:struct, SchedExtEntity])
TaskT = BPF::KernelType.new(Task.new(SchedExtEntity.new(0)))

Stats = BPF::PerCpuArrayMap.new("Stats", :u64, 2)
FifoSched = BPF::OptionalConfig.new("FifoSched", :u8)
VtimeNow = BPF::Global.new("VtimeNow", :u64)
Uei = BPF::ExitInfo.new("Uei")

def basic_select_cpu(ctx)
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

def basic_enqueue(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    Stats.atomic_add(1, 1)
    if FifoSched.value != 0
      BPF::Scx.dsq_insert(p, 0, BPF::Scx::SLICE_DFL, ctx.arg(1))
    else
      BPF::Scx.dsq_insert_vtime(p, 0, BPF::Scx::SLICE_DFL, p.load.scx.dsq_vtime, ctx.arg(1))
    end
  end
end

def basic_dispatch(ctx)
  BPF::Scx.dsq_move_to_local(0)
end

def basic_running(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    if FifoSched.value == 0
      VtimeNow.set(p.load.scx.dsq_vtime)
    end
  end
end

def basic_enable(ctx)
  p = ctx.kptr_or_null(0, TaskT)
  if p
    BPF::Scx.task_set_dsq_vtime(p, VtimeNow.value)
  end
end

def basic_init(ctx)
  r = BPF::Scx.create_dsq(0, -1)
  if r != 0
    BPF::Scx.error("failed to create DSQ %d (%d)", 0, r)
  end
  r
end

def basic_exit(ctx)
  BPF::Scx.exit_info(ctx, Uei)
end

BPF.struct_ops :BasicOps, "sched_ext_ops", name: "rbbasic", timeout_ms: 5000, flags: BPF::Scx::OPS_SWITCH_PARTIAL,
  select_cpu: :basic_select_cpu, enqueue: :basic_enqueue, dispatch: :basic_dispatch, running: :basic_running,
  enable: :basic_enable, init: :basic_init, exit: :basic_exit
