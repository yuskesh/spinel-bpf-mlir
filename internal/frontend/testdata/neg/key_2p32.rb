require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  Counts.atomic_add(4294967296, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 6:21
