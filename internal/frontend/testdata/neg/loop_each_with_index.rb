require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 4)

# each_with_index (Spinel splices in its builtins — the position is the one after the splice line correction)
def prog(ctx)
  s = 0
  (0...4).each_with_index { |a, i| s += i }
  Out.update(0, s)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 8:3
