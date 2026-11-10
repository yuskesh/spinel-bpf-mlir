require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
Spare = BPF::ArrayMap.new("Spare", :u32, 4)

def prog(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
