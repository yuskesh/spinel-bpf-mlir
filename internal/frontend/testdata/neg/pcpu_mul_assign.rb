require "bpf"


S = Struct.new(:n, :m)
BPF.record(S, n: :u64, m: :u64)
M = BPF::PerCpuRecordMap.new("M", S.new(0, 0), 2)
def prog(ctx)
  p = M.lookup(0)
  if p
    p.load.n *= 2
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB001 10:5
