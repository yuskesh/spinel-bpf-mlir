require "bpf"


Counts = BPF::ArrayMap.new("Counts", :u64, 2)
Unused = BPF::Counter.new("Unused", :u64)

def prog(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
