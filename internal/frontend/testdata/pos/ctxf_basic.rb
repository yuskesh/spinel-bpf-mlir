require "bpf"



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
