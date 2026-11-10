require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 1)

def p(ctx)
  st = ctx.adjust_tail(4)
  Out.update(0, st)
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB014 7:24
