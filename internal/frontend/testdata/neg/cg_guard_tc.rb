require "bpf"


def p(skb)
  n = skb.len
  return BPF::TC_DROP if n > 64
  BPF::CG_ALLOW
end
BPF.cgroup_skb :p, :ingress
# want: SB028 6:10
