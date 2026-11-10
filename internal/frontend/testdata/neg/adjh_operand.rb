require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 1)

def p(ctx)
  Out.update(0, ctx.adjust_head(4) + 1)
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB026 7:17
