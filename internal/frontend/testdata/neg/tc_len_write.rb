require "bpf"


def p(skb)
  skb.len = 5
  BPF::TC_PASS
end
BPF.tcx :p, :egress
# want: SB002 5:3
