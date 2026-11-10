require "bpf"

# A sched_cls program returns an XDP verdict (XDP_PASS = 2 = TC_DROP — the values overlap)
def p(skb)
  BPF::XDP_PASS
end
BPF.tcx :p, :ingress
# want: SB028 5:3
