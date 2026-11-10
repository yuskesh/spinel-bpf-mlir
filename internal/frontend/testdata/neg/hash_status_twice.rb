require "bpf"

K = Struct.new(:a, :b)
BPF.record(K, a: :u32, b: :u32)
H = BPF::HashMap.new("H", :u32, :u64, 8)
R = BPF::HashMap.new("R", K.new(0, 0), :u64, 8)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  st = H.insert(1, 2)
  st = H.insert(2, 3)
  Out.update(0, st)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB026 10:3
