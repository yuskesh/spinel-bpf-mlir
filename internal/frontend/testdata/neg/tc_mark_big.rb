require "bpf"


def p(skb)
  skb.mark = 4294967296
  BPF::TC_PASS
end
BPF.tcx :p, :ingress
# want: SB014 5:14
