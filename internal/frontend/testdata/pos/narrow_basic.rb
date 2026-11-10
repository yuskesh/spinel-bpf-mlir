require "bpf"


Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 1)
In = BPF::ArrayMap.new("In", :i32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 8)

def prog(ctx)
  q = In.lookup(0)
  if q
    k = q.load
    n = q.load & 0xF
    if k >= 0 && k < 8
      p = Hs.lookup(0)
      if p
        Out.update(0, p.load.hist[k])
      end
    end
    if k > 0 && k <= 16
      s = 0
      k.times { |i| s += i }
      Out.update(1, s)
    end
    if k > -1000 && k < 1000
      Out.update(2, (k * k * k) & 0xFFFFFFFF)
    end
    if k >= 0
      unless k >= 8
        p2 = Hs.lookup(0)
        if p2
          Out.update(3, p2.load.hist[k])
        end
      end
    end
    if k >= 0 && k < n
      t = 0
      k.times { |i| t += 1 }
      Out.update(4, t)
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
