require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 2)

def trim4(ctx)
  st = ctx.adjust_tail(-4)
  Out.update(0, st)
  w = ctx.check(0, 18)
  if w
    Out.update(1, 1)
  end
  BPF::XDP_PASS
end

def trim0(ctx)
  _ = ctx.adjust_tail(0)
  BPF::XDP_PASS
end
BPF.xdp :trim4
BPF.xdp :trim0
