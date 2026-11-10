require "bpf"


def p(ctx)
  ctx.set_key(:ipv4_src, 1, 2)
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB002 5:3
