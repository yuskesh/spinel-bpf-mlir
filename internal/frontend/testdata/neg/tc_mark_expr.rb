require "bpf"

# A mark write inside an expression (statement only)
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(skb)
  Out.update(0, (skb.mark = 1))
  BPF::TC_PASS
end
BPF.tcx :p, :ingress
# want: SB002 7:18
