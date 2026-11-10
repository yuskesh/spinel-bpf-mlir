require "bpf"

# fmod_ret: bpf_modify_return_test(int a, int *b) (the kernel's tracing test run calls it with (1, &b); b is 2, and the original function
# does *b += 1 and returns a + *b = 4). Only named return values: BPF::FMOD_CALL (the original function) and BPF.fmod_return(e) (e's range excludes 0).
# on_guard: for the Filter tgid add a to Out[0]; replace with −1 when Cfg[0] is 1, otherwise the original function. on_val: replace with (a & 0xFF) + 1 (range [1, 256]).
# on_obs (fexit): the return value after the trampoline into Out[3], the observation count into Out[2] (bml's test run does not return retval)
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
