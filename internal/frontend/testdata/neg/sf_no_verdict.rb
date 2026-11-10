require "bpf"


Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(skb)
  Out.update(0, 1)
end
BPF.socket_filter :p
# want: SB008 7:3
