require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 4)

# Uses the value of times (as a receiver or a break value — Spinel types it poly)
def prog(ctx)
  s = 0
  r = 4.times do |i|
    break if i == 2
    s += i
  end
  Out.update(0, s)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 8:7
