require "bpf"


A = BPF::ArrayMap.new("A", :i64, 2)
def prog(ctx)
  p = A.lookup(0)
  if p
    A.update(0, (p.load & 0xFFFF) + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 8:5
