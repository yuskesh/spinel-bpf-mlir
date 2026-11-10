require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  if BPF.time_before(BPF.ktime_ns, 3) == 1
    T.update(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB001 5:6
