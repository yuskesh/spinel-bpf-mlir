require "bpf"


def p(ctx)
  BPF::TC_PASS
end
BPF.xdp :p
# want: SB028 5:3
