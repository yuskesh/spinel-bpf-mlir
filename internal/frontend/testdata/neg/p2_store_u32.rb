require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
U = BPF::ArrayMap.new("U", :u32, 4)

def prog(ctx)
  a = -7
  b = 3
  q = U.lookup(1)
  if q
    U.update(0, (q.load & 0xFFFF_FFFF) + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 11:17
