require "bpf"


def p(ctx)
  BPF::NF_ACCEPT
end
BPF.xdp :p
# want: SB028 5:3
