require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
B = BPF::ArrayMap.new("B", :u32, 2)
def prog(ctx)
  p = Counts.lookup(0)
  if p
    B.update(0, p.load)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 8:17
