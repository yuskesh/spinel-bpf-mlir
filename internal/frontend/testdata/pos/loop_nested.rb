require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 1)

def prog(ctx)
  s = 0
  8.times do |i|
    8.times do |j|
      next if j > i
      s += i * j
    end
  end
  Out.update(0, s)
  BPF::XDP_PASS
end
BPF.xdp :prog
