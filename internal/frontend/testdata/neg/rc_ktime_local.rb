require "bpf"

L = Struct.new(:n, :_pad0, :ns)
BPF.record(L, n: :u32, _pad0: :u32, ns: :u64)
Ls = BPF::RecordMap.new("Ls", L.new(0, 0, 0), 1)
T = BPF::ArrayMap.new("T", :u64, 2)

def prog(ctx)
  x = BPF.ktime_ns
  T.update(0, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 9:7
