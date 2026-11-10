require "bpf"

# A field not in the table (rx_queue_index) on the xdp context
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(ctx)
  Out.update(0, ctx.rx_queue_index)
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB002 7:17
