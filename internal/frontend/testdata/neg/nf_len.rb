require "bpf"

# len on the netfilter context (it has no integer field — the sk_buff len comes through ctx.skb(T))
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(ctx)
  Out.update(0, ctx.len)
  BPF::NF_ACCEPT
end
BPF.netfilter :p
# want: SB028 7:17
