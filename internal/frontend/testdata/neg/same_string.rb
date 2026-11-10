require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
B = BPF::ArrayMap.new("Counts", :u64, 2)
def prog(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB013 4:23
