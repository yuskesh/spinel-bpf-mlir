require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  n = 14
  w = ctx.check(0, n)
  if w
    Out.update(0, w.u8(0))
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB006 7:20
