require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def inner(w)
  w.u8(0)
end

def outer(w)
  inner(w)
end

def prog(ctx)
  w = ctx.check(0, 14)
  if w
    Out.update(0, outer(w) & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 9:9
