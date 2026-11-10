require "bpf"


Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(skb)
  Out.update(0, skb.mark)
  BPF::SF_KEEP
end
BPF.socket_filter :p
# want: SB028 7:17
