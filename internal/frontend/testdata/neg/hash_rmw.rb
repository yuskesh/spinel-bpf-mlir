require "bpf"

K = Struct.new(:a, :b)
BPF.record(K, a: :u32, b: :u32)
H = BPF::HashMap.new("H", :u32, :u64, 8)
R = BPF::HashMap.new("R", K.new(0, 0), :u64, 8)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  p = H.lookup(1)
  if p
    _ = H.update(1, p.load & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 12:9
