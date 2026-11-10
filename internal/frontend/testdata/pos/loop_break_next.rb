require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  s = 0
  c = 0
  8.times do |i|
    next if i == 1
    s += i
    break if s > 10
    unless i < 6
      c += 1
      next
    end
    c += 10
  end
  n = 0
  (0...16).each do |i|
    if i == 3
      n += 100
      break
    end
    n += 1
  end
  Out.update(0, s)
  Out.update(1, c)
  Out.update(2, n)
  BPF::XDP_PASS
end
BPF.xdp :prog
