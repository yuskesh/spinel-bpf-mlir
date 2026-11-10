require "bpf"

# A sched_cls program that does not end in a verdict
Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def p(skb)
  Counts.atomic_add(0, 1)
end
BPF.tcx :p, :ingress
# want: SB008 7:3
