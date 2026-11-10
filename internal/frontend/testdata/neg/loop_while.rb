require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  while false
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB001 6:3
