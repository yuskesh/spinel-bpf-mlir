require "bpf"

# len on the xdp context (ctx.len was added for socket_filter only)
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(ctx)
  Out.update(0, ctx.len)
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB002 7:17
