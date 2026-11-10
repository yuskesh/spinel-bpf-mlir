require "bpf"

# cgroup_skb with an unknown direction
def p(skb)
  BPF::CG_ALLOW
end
BPF.cgroup_skb :p, :forward
# want: SB008 7:1
