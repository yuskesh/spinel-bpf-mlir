require "bpf"

# socket_filter returns an XDP verdict
def p(skb)
  BPF::XDP_PASS
end
BPF.socket_filter :p
# want: SB028 5:3
