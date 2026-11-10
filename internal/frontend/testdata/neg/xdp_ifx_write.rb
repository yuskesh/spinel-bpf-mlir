require "bpf"

# Write to xdp ingress_ifindex (read-only)
def p(ctx)
  ctx.ingress_ifindex = 1
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB002 5:3
