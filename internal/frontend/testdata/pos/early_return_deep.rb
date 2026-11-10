require "bpf"


Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 1)
In = BPF::ArrayMap.new("In", :i32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  k = 0
  q = In.lookup(0)
  if q
    k = q.load
  end
  return BPF::XDP_DROP if k == 13
  Out.update(0, 1)
  return BPF::XDP_DROP if k > 100
  Out.update(1, 2)
  return BPF::XDP_DROP unless k >= -100
  Out.update(2, 3)
  s = 0
  8.times do |i|
    p = Hs.lookup(0)
    if p
      s += p.load.hist[i]
    end
  end
  Out.update(3, s + k + 100)
  BPF::XDP_PASS
end
BPF.xdp :prog
