require "bpf"

S = Struct.new(:a, :b)
BPF.record(S, a: :u32, b: :u32)
V = BPF::RecordHashMap.new("V", :u32, S.new(0, 0), 8)
def prog(ctx)
  _ = V.add_or_init(1, 2)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB002 7:7
