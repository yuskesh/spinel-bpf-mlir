require "bpf"


def p(skb)
  BPF::SF_KEEP
end
BPF.socket_filter :p, :ingress
# want: SB008 7:1
