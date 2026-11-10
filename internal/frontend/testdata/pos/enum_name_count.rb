require "bpf"


Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog

def count(x)
  x + 1
end
puts count(1)
