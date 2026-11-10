require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  w = ctx.check(0, 65536)
  if w
    Out.update(0, w.u8(0))
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB022 6:20
