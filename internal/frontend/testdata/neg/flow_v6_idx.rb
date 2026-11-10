require "bpf"

# ipv6_src index 4 (outside 0..3)
def p(ctx)
  ctx.set_key(:ipv6_src, 4, 1)
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB014 5:26
