require "bpf"

S = Struct.new(:a, :_pad0, :n)
BPF.record(S, a: :u8, _pad0: :u8, n: :u16)
M = BPF::RecordMap.new("M", S.new(0, 0, 0), 2)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  p = M.lookup(0)
  if p
    Out.update(0, p.load._pad0)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB024 11:19
