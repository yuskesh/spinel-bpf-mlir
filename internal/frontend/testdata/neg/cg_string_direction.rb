require "bpf"

# cgroup_skb with its direction given as a String
def p(skb)
  BPF::CG_ALLOW
end
BPF.cgroup_skb :p, "ingress"
# want: SB008 7:1
