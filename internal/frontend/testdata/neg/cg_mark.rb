require "bpf"

# The cgroup_skb context field mark (not in the capability table)
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(skb)
  Out.update(0, skb.mark)
  BPF::CG_ALLOW
end
BPF.cgroup_skb :p, :ingress
# want: SB002 7:17
