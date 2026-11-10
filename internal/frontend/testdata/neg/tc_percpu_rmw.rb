require "bpf"


Hits = BPF::PerCpuArrayMap.new("Hits", :i64, 4)

def on_xdp(ctx)
  h = Hits.lookup(0)
  if h
    Hits.update(0, (h.load & 0xFFFF) + 1)
  end
  BPF::XDP_PASS
end

def on_tc(skb)
  BPF::TC_PASS
end
BPF.xdp :on_xdp
BPF.tcx :on_tc, :ingress
# want: SB019 9:5
