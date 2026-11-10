require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def f(a)
  if a > 1
    2
  else
    3
  end
end
def prog(ctx)
  Out.update(0, f(1) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 5:3
