require "bpf"
M = BPF::ArrayMap.new("M", :u64, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)
def scale(a)
  a * 3 + 1
end
def prog(ctx)
  x = 0
  p = M.lookup(0)
  if p
    x = p.load & 0xFFFF
  end
  Out.update(1, scale(x) & 0xFFFFF)
  y = 0
  q = M.lookup(2)
  if q
    y = q.load & 0x7FFFFFFFFFFFFFFF
  end
  Out.update(3, scale(y) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 5:3
