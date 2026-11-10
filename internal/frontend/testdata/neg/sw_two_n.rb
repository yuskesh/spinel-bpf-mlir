require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def et(w)
  w.u8(0)
end

def prog(ctx)
  w = ctx.check(0, 14)
  if w
    Out.update(0, et(w) & 0xFF)
  end
  v = ctx.check(0, 20)
  if v
    Out.update(1, et(v) & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 15:22
