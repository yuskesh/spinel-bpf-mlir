require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 4)

# The product of the nested counts is above 64 (16 × 8)
def prog(ctx)
  s = 0
  16.times do |i|
    8.times { |j| s += i + j }
  end
  Out.update(0, s)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 9:5
