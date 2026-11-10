require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 8)
H = BPF::HashMap.new("H", :u32, :u64, 16)


def prog(ctx)
  4.times do |i|
    H.insert(i, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB026 9:5
