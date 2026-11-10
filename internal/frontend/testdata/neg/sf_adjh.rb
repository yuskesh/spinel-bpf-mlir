require "bpf"

# adjust_head on the socket_filter context
Out = BPF::ArrayMap.new("Out", :i64, 1)

def p(skb)
  st = skb.adjust_head(4)
  Out.update(0, st)
  BPF::SF_KEEP
end
BPF.socket_filter :p
# want: SB028 7:8
