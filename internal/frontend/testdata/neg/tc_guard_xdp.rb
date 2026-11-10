require "bpf"


In = BPF::ArrayMap.new("In", :i32, 1)

def p(skb)
  k = 0
  q = In.lookup(0)
  if q
    k = q.load
  end
  return BPF::XDP_DROP if k < 0
  BPF::TC_PASS
end
BPF.tcx :p, :egress
# want: SB028 12:10
