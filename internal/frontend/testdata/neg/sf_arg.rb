require "bpf"

# Tracing API on the socket_filter context
Out = BPF::ArrayMap.new("Out", :u64, 1)

def p(skb)
  Out.update(0, skb.arg(1))
  BPF::SF_KEEP
end
BPF.socket_filter :p
# Predicted SB002 — a read on a context without a packet takes the same path as the tracing kinds: SB028
# want: SB028 7:17
