require "bpf"

S = Struct.new(:a, :b, :n)
BPF.record(S, a: :u8, b: :u8, n: :u16)
M = BPF::RecordMap.new("M", S.new(0, 0, 0), 2)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  M.update(0, S.new(1, 2))
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB024 9:15
