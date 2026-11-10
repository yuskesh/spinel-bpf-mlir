require "bpf"


def p(ctx)
  BPF::FLOW_OK
end
BPF.xdp :p
# want: SB028 5:3
