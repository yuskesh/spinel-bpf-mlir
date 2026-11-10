require "bpf"


def p(skb)
  BPF::SF_KEEP
end
BPF.cgroup_skb :p, :ingress
# want: SB028 5:3
