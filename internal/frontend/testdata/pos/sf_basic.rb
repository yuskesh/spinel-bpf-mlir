require "bpf"


Out = BPF::ArrayMap.new("Out", :u32, 1)

def short_only(skb)
  n = skb.len
  Out.update(0, n)
  return BPF::SF_DROP if n > 64
  BPF::SF_KEEP
end
BPF.socket_filter :short_only
