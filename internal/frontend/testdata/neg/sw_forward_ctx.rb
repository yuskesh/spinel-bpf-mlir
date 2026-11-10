require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def inner(c)
  r = 0
  w = c.check(0, 14)
  if w
    r = w.u8(0)
  end
  r
end

def outer(c)
  inner(c)
end

def prog(ctx)
  Out.update(0, outer(ctx) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 14:9
