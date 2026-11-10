require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def both(w, q)
  w.u8(0)
end

def prog(ctx)
  p = Out.lookup(0)
  if p
    w = ctx.check(0, 14)
    if w
      Out.update(1, both(w, p) & 0xFF)
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 4:1
