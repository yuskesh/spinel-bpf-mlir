require "bpf"

# An xdp program returns a netfilter verdict
def p(ctx)
  BPF::NF_ACCEPT
end
BPF.xdp :p
# want: SB028 5:3
