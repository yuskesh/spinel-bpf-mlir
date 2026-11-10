require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def f(a)
  g(a)
end
def g(a)
  f(a)
end
def prog(ctx)
  Out.update(0, f(1) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB035 4:1
