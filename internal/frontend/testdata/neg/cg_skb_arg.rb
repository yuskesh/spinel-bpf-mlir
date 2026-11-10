require "bpf"


Out = BPF::ArrayMap.new("Out", :u64, 1)

def p(skb)
  Out.update(0, skb.arg(1))
  BPF::CG_ALLOW
end
BPF.cgroup_skb :p, :ingress
# want: SB002 7:17
