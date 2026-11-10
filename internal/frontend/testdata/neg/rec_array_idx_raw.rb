require "bpf"


Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 2)
In = BPF::ArrayMap.new("In", :i32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 1)

def prog(ctx)
  q = In.lookup(0)
  if q
    i = q.load
    p = Hs.lookup(0)
    if p
      Out.update(0, p.load.hist[i])
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB031 16:33
