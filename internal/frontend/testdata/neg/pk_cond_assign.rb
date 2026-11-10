require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  if (w = ctx.check(0, 14))
    Out.update(0, w.u8(0))
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 6:3
