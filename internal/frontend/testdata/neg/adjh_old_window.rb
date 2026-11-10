require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 2)

def p(ctx)
  v = 0
  w = ctx.check(0, 14)
  if w
    v = w.u8(0)
  end
  st = ctx.adjust_head(4)
  Out.update(0, st)
  Out.update(1, v + w.u8(1))
  BPF::XDP_PASS
end
BPF.xdp :p

# want: SB005 14:21
