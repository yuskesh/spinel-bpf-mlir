require "bpf"



L = Struct.new(:n, :ns)
BPF.record(L, n: :u64, ns: :u64)
Ls = BPF::RecordMap.new("Ls", L.new(0, 0), 1)
T = BPF::ArrayMap.new("T", :u64, 2)

def prog(ctx)
  Ls.update(0, L.new(1, BPF.ktime_ns))
  T.update(0, BPF.ktime_ns)
  T.update(1, BPF.ktime_ns & 0xFFFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
