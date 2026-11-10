require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  x = BPF.ktime_ns
  x += 1
  T.update(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 6:3
