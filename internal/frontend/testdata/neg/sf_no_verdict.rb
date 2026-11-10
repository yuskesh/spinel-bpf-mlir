require "bpf"

# A socket_filter program that does not end in a verdict
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(skb)
  Out.update(0, 1)
end
BPF.socket_filter :p
# want: SB008 7:3
