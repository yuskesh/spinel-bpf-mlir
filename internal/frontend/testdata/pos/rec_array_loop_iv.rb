require "bpf"


Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 2)
Out = BPF::ArrayMap.new("Out", :u64, 1)

def prog(ctx)
  s = 0
  8.times do |i|
    p = Hs.lookup(0)
    if p
      s += p.load.hist[i]
    end
  end
  Out.update(0, s)
  BPF::XDP_PASS
end
BPF.xdp :prog
