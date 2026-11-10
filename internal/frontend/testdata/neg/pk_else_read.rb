require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  w = ctx.check(0, 14)
  if w
    Out.update(0, w.u8(0))
  else
    Out.update(1, w.u8(1))
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 10:19
