require "bpf"


def p(skb)
  BPF::XDP_PASS
end
BPF.cgroup_skb :p, :egress
# want: SB028 5:3
