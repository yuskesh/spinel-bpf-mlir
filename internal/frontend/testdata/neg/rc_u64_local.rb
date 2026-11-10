require "bpf"

S = Struct.new(:a, :_pad0, :_pad1, :c)
BPF.record(S, a: :u64, _pad0: :u32, _pad1: :u32, c: :u64)
M = BPF::RecordMap.new("M", S.new(0, 0, 0, 0), 2)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  p = M.lookup(0)
  if p
    x = p.load.a
    Out.update(0, x & 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 11:9
