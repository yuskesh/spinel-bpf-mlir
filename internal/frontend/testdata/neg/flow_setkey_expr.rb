require "bpf"


def p(ctx)
  return BPF::FLOW_DROP if ctx.set_key(:thoff, 14) == 0
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB002 5:28
