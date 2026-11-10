require "bpf"


Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(skb)
  Out.update(0, skb.ifindex)
  BPF::TC_PASS
end
BPF.tcx :p, :ingress
# want: SB002 7:17
