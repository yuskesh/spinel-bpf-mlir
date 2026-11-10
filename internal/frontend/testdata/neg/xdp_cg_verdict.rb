require "bpf"

# An xdp program returns a cgroup_skb verdict
def p(ctx)
  BPF::CG_ALLOW
end
BPF.xdp :p
# want: SB028 5:3
