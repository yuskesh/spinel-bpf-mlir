require "bpf"

# An attach direction on socket_filter (it has no attach clause)
def p(skb)
  BPF::SF_KEEP
end
BPF.socket_filter :p, :ingress
# want: SB008 7:1
