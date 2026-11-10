require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  p = Counts.lookup(0)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 6:3
