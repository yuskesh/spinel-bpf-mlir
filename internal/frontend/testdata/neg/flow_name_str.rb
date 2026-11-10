require "bpf"


def p(ctx)
  ctx.set_key("thoff", 14)
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB002 5:3
