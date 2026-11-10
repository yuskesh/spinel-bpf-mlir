require "bpf"

# a u64 local rebound to a u64 value in one arm (rule A), then copied to a u64 map
T = BPF::ArrayMap.new("T", :u64, 2)

def prog(ctx)
  x = BPF.ktime_ns
  if (x & 1) == 1
    x = BPF.u64_add(x, 1)
  end
  T.update(0, x)
  BPF::XDP_PASS
end

BPF.xdp :prog
