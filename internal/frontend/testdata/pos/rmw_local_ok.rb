require "bpf"


S = Struct.new(:a, :b)
BPF.record(S, a: :u32, b: :u32)
Out = BPF::ArrayMap.new("Out", :u32, 4)
In = BPF::ArrayMap.new("In", :u32, 2)
R = BPF::RecordMap.new("R", S.new(0, 0), 2)

def prog(ctx)
  q = In.lookup(0)
  if q
    x = q.load & 0xFF
    Out.update(0, x + 1)
    Out.atomic_add(1, x)
  end
  p = Out.lookup(2)
  if p
    y = p.load & 0xFF
    Out.update(3, y + 1)
  end
  z = 5
  Out.update(2, z)
  v = 0
  w = In.lookup(1)
  if w
    v = w.load & 0xFF
  end
  r = R.lookup(0)
  if r
    r.atomic_add(:a, v)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
