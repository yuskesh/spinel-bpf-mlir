require "bpf"

Out = BPF::ArrayMap.new("Out", :u32, 2)

# A local that has the origin in only one if arm (the join is the union)
def prog(ctx)
  x = 0
  p = Out.lookup(0)
  if p
    x = p.load & 0xFF
  end
  Out.update(0, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 12:3
