require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  w = BPF.ktime_ns & 0xFFFFFFFF
  d = w > 0 ? w : 1
  T.update(0, BPF.u64_div(BPF.ktime_ns, d))
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 7:41
