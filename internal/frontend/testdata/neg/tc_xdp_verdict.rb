require "bpf"


def p(skb)
  BPF::XDP_PASS
end
BPF.tcx :p, :ingress
# want: SB028 5:3
