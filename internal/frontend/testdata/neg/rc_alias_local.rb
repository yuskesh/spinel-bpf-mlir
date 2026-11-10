require "bpf"

S = Struct.new(:a, :b, :n)
BPF.record(S, a: :u8, b: :u8, n: :u16)
M = BPF::RecordMap.new("M", S.new(0, 0, 0), 2)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  p = M.lookup(0)
  if p
    r = p.load
    r.a = 5
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 11:9
