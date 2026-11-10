require "bpf"


Out = BPF::ArrayMap.new("Out", :u64, 1)

def p(skb)
  Out.update(0, skb.arg(1))
  BPF::SF_KEEP
end
BPF.socket_filter :p

# want: SB028 7:17
