require "bpf"

# xdp / tc context fields: xdp's ingress_ifindex into Out[0]; tc egress writes len into Out[1] and sets mark to 42; ingress puts mark into Out[2],
# adds 7, writes it back and puts the reread value into Out[3]
Out = BPF::ArrayMap.new("Out", :u32, 4)

def ifx(ctx)
  Out.update(0, ctx.ingress_ifindex)
  BPF::XDP_PASS
end

def mark_out(skb)
  Out.update(1, skb.len)
  skb.mark = 42
  BPF::TC_PASS
end

def mark_in(skb)
  Out.update(2, skb.mark)
  skb.mark = (skb.mark + 7) & 0xFFFF_FFFF
  Out.update(3, skb.mark)
  BPF::TC_PASS
end
BPF.xdp :ifx
BPF.tcx :mark_out, :egress
BPF.tcx :mark_in, :ingress
