require "bpf"

# 2^32 for mark (outside u32)
def p(skb)
  skb.mark = 4294967296
  BPF::TC_PASS
end
BPF.tcx :p, :ingress
# want: SB014 5:14
