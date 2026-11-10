require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  p = Counts.lookup(0)
  if p
  end
  p = Counts.lookup(1)
  if p
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 9:3
