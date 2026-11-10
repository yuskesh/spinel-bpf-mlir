require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 4)


def prog(ctx)
  s = 0
  2.times do |i|
    2.times do |j|
      2.times { |k| s += i + j + k }
    end
  end
  Out.update(0, s)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 10:7
