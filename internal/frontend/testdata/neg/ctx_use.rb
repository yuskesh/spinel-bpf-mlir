require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  Counts.atomic_add(0, ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB001 6:24
