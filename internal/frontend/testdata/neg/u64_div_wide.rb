require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def prog(ctx)
  T.update(0, BPF.u64_div(BPF.ktime_ns, BPF.ktime_ns))
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 5:41
