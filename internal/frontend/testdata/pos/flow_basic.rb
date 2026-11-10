require "bpf"



def flow4(ctx)
  w = ctx.check(14, 20)
  if w
    ctx.set_key(:addr_proto, 0x0800)
    ctx.set_key(:ip_proto, w.u8(9))
    ctx.set_key(:ipv4_src, w.le32(12))
    ctx.set_key(:ipv4_dst, w.le32(16))
    ctx.set_key(:thoff, (ctx.key(:nhoff) + 20) & 0xFFFF)
  end
  return BPF::FLOW_DROP if ctx.key(:n_proto) != 8
  BPF::FLOW_OK
end

def flow6(ctx)
  w = ctx.check(14, 40)
  if w
    ctx.set_key(:ip_proto, w.u8(6))
    ctx.set_key(:ipv6_src, 2, w.le32(16))
    ctx.set_key(:ipv6_dst, 3, w.le32(36))
  end
  BPF::FLOW_OK
end
BPF.flow_dissector :flow4
BPF.flow_dissector :flow6
