require "bpf"

# a u64 local (rule A) copied to a u64 map, masked into an i64 map, and shifted into a key
T = BPF::ArrayMap.new("T", :u64, 2)
O = BPF::ArrayMap.new("O", :i64, 2)
U = BPF::ArrayMap.new("U", :u32, 16)

def prog(ctx)
  x = BPF.ktime_ns
  T.update(0, x)
  O.update(0, x & 0xFF)
  U.update(x >> 60, 1)
  BPF::XDP_PASS
end

BPF.xdp :prog
