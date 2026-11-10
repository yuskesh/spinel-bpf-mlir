require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  x = BPF.ktime_ns
  if x > 5
    T.update(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 6:6
