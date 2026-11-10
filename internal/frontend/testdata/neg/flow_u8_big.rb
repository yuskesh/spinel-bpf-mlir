require "bpf"


def p(ctx)
  ctx.set_key(:ip_proto, 256)
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB014 5:26
