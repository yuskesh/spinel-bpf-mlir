require "bpf"

# Write to a cgroup_skb window (windows are read-only)
def p(skb)
  w = skb.check(0, 20)
  if w
    w.set_u8(0, 1)
  end
  BPF::CG_ALLOW
end
BPF.cgroup_skb :p, :egress
# want: SB002 7:5
