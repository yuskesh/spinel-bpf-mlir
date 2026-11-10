require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def f(a)
  a > 1
end
def prog(ctx)
  if f(1)
    Out.update(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 4:1
