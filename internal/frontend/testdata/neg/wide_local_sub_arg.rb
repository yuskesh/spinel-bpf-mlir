require "bpf"

T = BPF::ArrayMap.new("T", :u64, 2)
def helper(v)
  v & 1
end

def prog(ctx)
  x = BPF.ktime_ns
  T.update(0, helper(x))
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 10:22
