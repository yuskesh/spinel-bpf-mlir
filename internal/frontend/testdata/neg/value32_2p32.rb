require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
B = BPF::ArrayMap.new("B", :u32, 2)
def prog(ctx)
  B.atomic_add(0, 4294967296)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 6:19
