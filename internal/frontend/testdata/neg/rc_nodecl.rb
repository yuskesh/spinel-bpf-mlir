require "bpf"

S = Struct.new(:a, :b, :n)
M = BPF::RecordMap.new("M", S.new(0, 0, 0), 2)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  p = M.lookup(0)
  if p
    Out.update(0, p.load.a)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB024 4:29
