require "bpf"

# A socket_filter guard returns a sched_cls verdict
def p(skb)
  n = skb.len
  return BPF::TC_DROP if n > 64
  BPF::SF_KEEP
end
BPF.socket_filter :p
# want: SB028 6:10
