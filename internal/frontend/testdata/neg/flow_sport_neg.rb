require "bpf"


def p(ctx)
  ctx.set_key(:sport, -1)
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB014 5:23
