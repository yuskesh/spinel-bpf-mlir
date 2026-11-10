require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  x = BPF.ktime_ns
  if x
    T.update(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 6:6
