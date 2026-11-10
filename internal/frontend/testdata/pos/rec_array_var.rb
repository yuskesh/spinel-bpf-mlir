require "bpf"


Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Five = Struct.new(:a, :v)
BPF.record(Five, a: :u32, v: [:u32, 5])
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 2)
Ps = BPF::RecordMap.new("Ps", Five.new(0, Array.new(5, 0)), 2)
In = BPF::ArrayMap.new("In", :u32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  q = In.lookup(0)
  if q
    i = q.load & 7
    j = (q.load >> 3) & 7
    u = (q.load & 0xFF) % 5
    p = Hs.lookup(0)
    if p
      Out.update(0, p.load.hist[i])
      p.load.hist[j] = 5
    end
    r = Ps.lookup(0)
    if r
      Out.update(1, r.load.v[u])
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
