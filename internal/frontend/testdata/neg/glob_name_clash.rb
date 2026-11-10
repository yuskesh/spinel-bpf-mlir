require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
Other = BPF::ArrayMap.new("Other", :u64, 2)
Hits = BPF::Counter.new("Counts", :u64)

def prog(ctx)
  Counts.atomic_add(0, 1)
  Other.atomic_add(0, 1)
  Hits.add(1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB029 5:25
