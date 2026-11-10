require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)


def helper
  Counts.atomic_add(0, 1)
end

def prog(ctx)
  helper
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 7:3
