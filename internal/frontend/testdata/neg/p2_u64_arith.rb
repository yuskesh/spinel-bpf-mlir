require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
U = BPF::ArrayMap.new("U", :u32, 4)

def prog(ctx)
  a = -7
  b = 3
  q = Counts.lookup(0)
  if q
    U.update(0, q.load + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 11:17
