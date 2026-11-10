require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  p = Out.lookup(1)
  if p
    w = ctx.check(p.load & 0xFFFF_FFFF, 4)
    if w
      Out.update(0, w.u8(0))
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB023 8:19
