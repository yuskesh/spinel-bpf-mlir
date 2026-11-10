require "bpf"


Protos = BPF::ArrayMap.new("Protos", :u64, 3)

def on_xdp(ctx)
  w = ctx.check(12, 2)
  if w
    et = w.be16(0)
    slot = 2
    if et == 0x0800
      slot = 0
    elsif et == 0x86DD
      slot = 1
    end
    Protos.atomic_add(slot, 1)
  end
  BPF::XDP_PASS
end

def on_tc(skb)
  w = skb.check(12, 2)
  if w
    et = w.be16(0)
    slot = 2
    if et == 0x0800
      slot = 0
    elsif et == 0x86DD
      slot = 1
    end
    Protos.atomic_add(slot, 1)
  end
  BPF::TC_PASS
end
BPF.xdp :on_xdp
BPF.tcx :on_tc, :ingress
