require "bpf"


def p(ctx)
  BPF::SF_KEEP
end
BPF.xdp :p
# want: SB028 5:3
