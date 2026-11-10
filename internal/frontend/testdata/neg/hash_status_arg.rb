require "bpf"

K = Struct.new(:a, :b)
BPF.record(K, a: :u32, b: :u32)
H = BPF::HashMap.new("H", :u32, :u64, 8)
R = BPF::HashMap.new("R", K.new(0, 0), :u64, 8)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  Out.update(0, H.delete(1))
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB026 10:17
