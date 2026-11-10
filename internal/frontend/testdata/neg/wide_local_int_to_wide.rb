require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  x = 3
  x = BPF.ktime_ns
  T.update(0, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB001 6:3
