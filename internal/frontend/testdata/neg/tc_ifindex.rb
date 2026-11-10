require "bpf"

# A field not in the table (ifindex) on the tc context
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(skb)
  Out.update(0, skb.ifindex)
  BPF::TC_PASS
end
BPF.tcx :p, :ingress
# want: SB002 7:17
