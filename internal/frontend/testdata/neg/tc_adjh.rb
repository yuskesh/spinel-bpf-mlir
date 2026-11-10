require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 1)

def p(skb)
  st = skb.adjust_head(4)
  Out.update(0, st)
  BPF::TC_PASS
end
BPF.tcx :p, :ingress
# want: SB002 7:8
