require "bpf"




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
