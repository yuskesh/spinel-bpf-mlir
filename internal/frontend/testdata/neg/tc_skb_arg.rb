require "bpf"


Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def p(skb)
  Counts.atomic_add(0, skb.arg(1))
  BPF::TC_PASS
end
BPF.tcx :p, :ingress
# want: SB002 7:24
