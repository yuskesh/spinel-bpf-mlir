require "bpf"



Out = BPF::ArrayMap.new("Out", :u64, 4)

def etype(w)
  w.be16(12)
end

def ip_proto(ctx)
  r = 0
  w = ctx.check(0, 34)
  if w
    if w.be16(12) == 0x0800
      r = w.u8(23)
    end
  end
  r
end

def on_xdp(ctx)
  w = ctx.check(0, 14)
  if w
    Out.update(0, etype(w) & 0xFFFF)
  end
  Out.update(1, ip_proto(ctx) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :on_xdp

def on_tc(ctx)
  w = ctx.check(0, 14)
  if w
    Out.update(2, etype(w) & 0xFFFF)
  end
  BPF::TC_PASS
end
BPF.tcx :on_tc, :ingress
