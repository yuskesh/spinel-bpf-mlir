require "bpf"


Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 65], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(65, 0), 0), 4)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  i = 0
  q = Out.lookup(1)
  if q
    i = q.load & 7
  end
  p = Hs.lookup(0)
  if p
    Out.update(0, p.load.hist[3])
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB024 5:31
