require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def f(a, b, c, d, e, g)
  a + b
end
def prog(ctx)
  Out.update(0, f(1, 2, 3, 4, 5, 6) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 4:1
