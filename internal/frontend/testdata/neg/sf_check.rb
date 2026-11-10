require "bpf"


Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(skb)
  w = skb.check(0, 14)
  if w
    Out.update(0, 1)
  end
  BPF::SF_KEEP
end
BPF.socket_filter :p
# want: SB028 7:7
