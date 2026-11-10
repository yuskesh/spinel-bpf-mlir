require "bpf"


Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Pair = Struct.new(:a, :v)
BPF.record(Pair, a: :u16, v: [:u16, 3])
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 4)
Ps = BPF::RecordMap.new("Ps", Pair.new(0, Array.new(3, 0)), 2)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  p = Hs.lookup(0)
  if p
    Out.update(0, p.load.hist[3])
    p.load.hist[5] = 7
    p.atomic_add(:hist, 2, 1)
  end
  q = Ps.lookup(1)
  if q
    Out.update(1, q.load.v[2])
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
