require "bpf"


def p(skb)
  w = skb.check(0, 14)
  if w
    w.set_u8(0, 1)
  end
  BPF::TC_PASS
end
BPF.tcx :p, :ingress
# want: SB002 7:5
