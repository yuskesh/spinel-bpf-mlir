require "bpf"

# Formerly a negative example, now positive: variable index i ∈ [0, 7] (accepted); a default constant 0 and a lookup value join into the same index (a constant and an unknown index on different paths, a shape non-root loaders can reject: ebpf-compile warns, an SB021 Conditional)
Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 4)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  i = 0
  q = Out.lookup(1)
  if q
    i = q.load & 7
  end
  p = Hs.lookup(0)
  if p
    Out.update(0, p.load.hist[i])
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
