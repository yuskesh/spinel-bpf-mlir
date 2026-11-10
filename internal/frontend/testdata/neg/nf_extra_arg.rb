require "bpf"


def p(ctx)
  BPF::NF_ACCEPT
end
BPF.netfilter :p, :x
# want: SB008 7:1
