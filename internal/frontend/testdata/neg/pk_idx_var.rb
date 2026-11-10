require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  w = ctx.check(0, 14)
  if w
    i = 3
    Out.update(0, w.u8(i))
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB006 9:24
