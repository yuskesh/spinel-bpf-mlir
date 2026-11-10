require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def f(c)
  r = 0
  w = c.check(0, 14)
  if w
    r = w.u8(0)
  end
  r
end

def on_x(ctx)
  Out.update(0, f(ctx) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :on_x

def on_c(ctx)
  Out.update(1, f(ctx) & 0xFF)
  BPF::TC_PASS
end
BPF.tcx :on_c, :ingress
# want: SB034 4:1
