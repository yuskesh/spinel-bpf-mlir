require "bpf"

# netfilter returns a cgroup_skb verdict
def p(ctx)
  BPF::CG_ALLOW
end
BPF.netfilter :p
# want: SB028 5:3
