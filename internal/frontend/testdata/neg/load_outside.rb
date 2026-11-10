require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  p = Counts.lookup(0)
  if p
  end
  Counts.update(1, p.load)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 9:20
