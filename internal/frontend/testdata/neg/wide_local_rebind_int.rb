require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  x = BPF.ktime_ns
  x = 3
  T.update(0, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 6:3
