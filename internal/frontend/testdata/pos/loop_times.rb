require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  s = 0
  4.times do |i|
    s += i
  end
  t = 0
  (0...8).each { |k| t += k * 2 }
  u = 1
  (0..7).each do |j|
    u += j
  end
  Out.update(0, s)
  Out.update(1, t)
  Out.update(2, u)
  BPF::XDP_PASS
end
BPF.xdp :prog
