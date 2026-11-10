require "bpf"


Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 2)
In = BPF::ArrayMap.new("In", :i32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 1)

def prog(ctx)
  q = In.lookup(0)
  if q
    i = q.load & 7
    p = Hs.lookup(0)
    if p
      p.load.hist[i] = p.load.hist[i] + 1
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 16:7
