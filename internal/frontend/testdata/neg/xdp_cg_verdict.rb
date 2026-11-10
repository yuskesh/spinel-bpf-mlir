require "bpf"


def p(ctx)
  BPF::CG_ALLOW
end
BPF.xdp :p
# want: SB028 5:3
