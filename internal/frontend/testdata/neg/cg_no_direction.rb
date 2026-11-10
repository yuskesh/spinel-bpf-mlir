require "bpf"

# cgroup_skb without a direction
def p(skb)
  BPF::CG_ALLOW
end
BPF.cgroup_skb :p
# want: SB008 7:1
