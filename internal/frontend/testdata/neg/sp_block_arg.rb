require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def f(a, &blk)
  a + 1
end
def prog(ctx)
  Out.update(0, f(1) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 4:1
