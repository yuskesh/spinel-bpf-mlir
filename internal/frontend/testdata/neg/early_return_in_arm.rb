require "bpf"


In = BPF::ArrayMap.new("In", :i32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  k = 0
  q = In.lookup(0)
  if q
    k = q.load
  end
  p = Out.lookup(1)
  if p
    return BPF::XDP_DROP if k < 0
  end
  Out.update(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB008 15:5
