require "bpf"


def p(ctx)
  BPF::XDP_PASS
end
BPF.netfilter :p
# want: SB028 5:3
