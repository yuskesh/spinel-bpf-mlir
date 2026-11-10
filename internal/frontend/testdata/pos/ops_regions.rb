require "bpf"

In = BPF::ArrayMap.new("In", :u32, 2)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  total = 0
  seen = false
  p = In.lookup(0)
  if p
    total = p.load * 2
    seen = true
  else
    total = 1
  end
  if seen
    Out.atomic_add(0, total)
  end
  Out.update(1, total + 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
