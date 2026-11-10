require "bpf"

Off = BPF::ArrayMap.new("Off", :u32, 1)
Out = BPF::ArrayMap.new("Out", :u32, 1)


def masked(ctx)
  p = Off.lookup(0)
  if p
    w = ctx.check(p.load & 0xFFF, 2)
    if w
      Out.update(0, w.be16(0))
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :masked
