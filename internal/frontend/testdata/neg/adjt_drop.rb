require "bpf"


def p(ctx)
  ctx.adjust_tail(-4)
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB026 5:3
