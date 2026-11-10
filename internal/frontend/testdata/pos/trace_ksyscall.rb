require "bpf"

# ksyscall: prctl syscall arguments 1 to 5 (7.1.8 tracefs sys_enter_prctl: int option, unsigned long arg2 to arg5,
# checked before load). Only for the Filter tgid with option 0x4511_5000 (an unknown option; prctl just returns EINVAL):
# add 1 to Out[0], Out[1] = arg2, Out[2] = arg3, Out[3] = arg4 (r10 in the syscall convention, not cx as in the function convention), add arg5's low 16 bits to Out[4]
Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 5)

def on_prctl(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      if ctx.arg(1) == 0x4511_5000
        Out.atomic_add(0, 1)
        Out.update(1, ctx.arg(2))
        Out.update(2, ctx.arg(3))
        Out.update(3, ctx.arg(4))
        Out.atomic_add(4, ctx.arg(5) & 0xFFFF)
      end
    end
  end
end
BPF.ksyscall :on_prctl, "prctl", params: {1 => :i32, 2 => :u64, 3 => :u64, 4 => :u64, 5 => :u64}
