require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  k = BPF.ktime_ns & 1
  if k == 1
    x = BPF.ktime_ns
  else
    x = 0
  end
  T.update(0, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 11:15
