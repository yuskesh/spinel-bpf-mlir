require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  return BPF::XDP_DROP
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB008 6:3
