require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  x = BPF.ktime_ns
  T.update(x, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB001 6:12
