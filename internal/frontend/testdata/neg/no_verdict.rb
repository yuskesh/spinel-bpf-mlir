require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  Counts.atomic_add(0, 1)
end
BPF.xdp :prog
# want: SB008 6:3
