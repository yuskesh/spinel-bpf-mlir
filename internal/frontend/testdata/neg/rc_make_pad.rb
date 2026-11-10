require "bpf"

S = Struct.new(:a, :_pad0, :n)
BPF.record(S, a: :u8, _pad0: :u8, n: :u16)
M = BPF::RecordMap.new("M", S.new(0, 0, 0), 2)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  M.update(0, S.new(1, 5, 3))
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB024 9:24
