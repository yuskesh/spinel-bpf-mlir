require "bpf"

# Discards the adjust_head status as a bare statement
def p(ctx)
  ctx.adjust_head(4)
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB026 5:3
