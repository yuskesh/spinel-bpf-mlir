require "bpf"


Pair = Struct.new(:a, :b)
BPF.record(Pair, a: :u16, b: :u16)
Pairs = BPF::RecordMap.new("Pairs", Pair.new(0, 0), 1)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  k = 0
  b = 0
  w = ctx.check(0, 2)
  if w
    k = w.u8(0) & 15
    b = w.u8(1)
  end
  s = 0
  k.times do |i|
    s += i
  end
  m = (b & 15) - 4
  t = 0
  m.times { t += 1 }
  u = 0
  64.times { u += b & 0xFF }
  Out.update(0, s)
  Out.update(1, t)
  Pairs.update(0, Pair.new(u, 0))
  BPF::XDP_PASS
end
BPF.xdp :prog
