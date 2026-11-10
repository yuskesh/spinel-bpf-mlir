require "bpf"





Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Cfg = BPF::ArrayMap.new("Cfg", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def on_guard(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      Out.atomic_add(0, ctx.arg(0))
    end
  end
  m = 0
  c = Cfg.lookup(0)
  if c
    m = c.load
  end
  return BPF.fmod_return(-1) if m == 1
  BPF::FMOD_CALL
end
BPF.fmod_ret :on_guard, "bpf_modify_return_test", nargs: 2, args: {0 => :i32}

def on_val(ctx)
  BPF.fmod_return((ctx.arg(0) & 0xFF) + 1)
end
BPF.fmod_ret :on_val, "bpf_modify_return_test", nargs: 2, args: {0 => :i32}

def on_obs(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      Out.atomic_add(2, 1)
      Out.update(3, ctx.ret)
    end
  end
end
BPF.fexit :on_obs, "bpf_modify_return_test", nargs: 2, ret: :i32
