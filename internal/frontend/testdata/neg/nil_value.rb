require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  Counts.update(0, nil)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB001 6:20
