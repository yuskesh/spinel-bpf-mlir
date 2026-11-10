require "bpf"


def p(skb)
  x = 0
  w = skb.check(0, 14)
  if w
    x = w.be32(0) + 1
  end
  skb.mark = x
  BPF::TC_PASS
end
BPF.tcx :p, :egress
# want: SB014 10:14
